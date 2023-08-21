/*
    MIT License

    Copyright (c) 2023 scizzydo http://github.com/scizzydo/memdump

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#include <Windows.h>

#include "misc.h"
#include "tstream.h"
#include "logging.hpp"
#include "SmartHandle.hpp"
#include "SelfInject.h"
#include "RemoteProcess.h"
#include "shared_data.hpp"

extern DWORD WINAPI unpack(LPVOID lpReserved);

// Helper function to listen to the handles from our child process and print it out
void readfile_thread_proc(HANDLE stdhandle, std::ostream& stream) {
    char buffer[0x1000]{};
    DWORD bytes_read = 0;
    BOOL success = FALSE;
    do {
        success = ReadFile(stdhandle, buffer, 0xFFF, &bytes_read, NULL);
        if (!success || bytes_read == 0) break;
        buffer[bytes_read] = '\0';
        stream << buffer;
    } while (success);
}

int _tmain(int argc, TCHAR** argv) {
    if (argc < 2) {
        logging::error("Missing executable to dump as an argument!");
        return EXIT_FAILURE;
    }
    auto path = std::filesystem::canonical(argv[1]);
    if (!std::filesystem::exists(path)) {
        logging::error(_T("{} does not exist!"), path.native());
        return EXIT_FAILURE;
    }
    if (std::filesystem::is_directory(path)) {
        logging::error(_T("{} is a directory, not an executable!"), path.native());
        return EXIT_FAILURE;
    }

    // Saving our path in exe_path, in case we want it in the injected side?
    auto our_path = std::filesystem::canonical(argv[0]);
    memcpy(exe_path, our_path.native().c_str(), (our_path.native().length() + 1) * sizeof(TCHAR));

    /*
    * Initializing the child stderr & stdout read & write handles. This information will
    * be passed to the newly created process to ensure it's stdout comes to our process.
    */
    SmartHandle child_stderr_rd, child_stdout_rd;
    SmartHandle child_stderr_wr, child_stdout_wr;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    if (!CreatePipe(&child_stdout_rd, &child_stdout_wr, &sa, 0)) {
        logging::error("Failed to create pipe for child stdout! {:#x}", GetLastError());
        return EXIT_FAILURE;
    }
    if (!SetHandleInformation(child_stdout_rd, HANDLE_FLAG_INHERIT, 0)) {
        logging::error("Failed to set handle information for child stdout! {:#x}", GetLastError());
        return EXIT_FAILURE;
    }

    if (!CreatePipe(&child_stderr_rd, &child_stderr_wr, &sa, 0)) {
        logging::error("Failed to create pipe for child stderr! {:#x}", GetLastError());
        return EXIT_FAILURE;
    }
    if (!SetHandleInformation(child_stderr_wr, HANDLE_FLAG_INHERIT, 0)) {
        logging::error("Failed to set handle information for child stderr! {:#x}", GetLastError());
        return EXIT_FAILURE;
    }

    // Basic structure initalization for CreateProcess with the exception of the handles we created above.
    PROCESS_INFORMATION process_info{};
    STARTUPINFO startup_info{};
    ZeroMemory(&startup_info, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);

    startup_info.hStdError = child_stderr_wr;
    startup_info.hStdOutput = child_stdout_wr;
    startup_info.hStdInput = reinterpret_cast<HANDLE>(-1);
    startup_info.dwFlags |= STARTF_USESTDHANDLES;
    if (!CreateProcess(nullptr, const_cast<TCHAR*>(path.native().c_str()), nullptr,
        nullptr, TRUE, CREATE_SUSPENDED,
        nullptr, nullptr, &startup_info, &process_info)) {
        logging::error("Failed to create child process! {:#x}", GetLastError());
        return EXIT_FAILURE;
    }

    logging::success(_T("Started {} [{:#x}]"), path.filename().native(), process_info.dwProcessId);
    SmartHandle hproc(process_info.hProcess), hthread(process_info.hThread);

    DWORD exit_code = EXIT_SUCCESS;
    RemoteProcess process(hproc);
    try {
        /*
        * Reading remote process TLS directory address. We want to overwrite this to a nullptr, as when we CreateRemoteThread
        * we don't want whatever that process may do with their TLS callbacks to trigger. In other words, when we inject ourself
        * we want to ensure we are the first ones to do anything.
        */
        auto const tls_directory = process.image_tls_directory();
        PVOID tls_callbacks = nullptr;
        if (!ReadProcessMemory(hproc, reinterpret_cast<LPCVOID>(tls_directory.AddressOfCallBacks),
            &tls_callbacks, sizeof(PVOID), nullptr))
            throw std::runtime_error(std::format("Failed to read address of TLS callbacks ({:#x})", GetLastError()));
        DWORD old_protection = NULL;
        if (!VirtualProtectEx(hproc, reinterpret_cast<LPVOID>(tls_directory.AddressOfCallBacks),
            sizeof(PVOID), PAGE_EXECUTE_READWRITE, &old_protection))
            throw std::runtime_error(std::format("Failed to change protection of TLS callbacks ({:#x})", GetLastError()));
        PVOID null = nullptr;
        if (!WriteProcessMemory(hproc, reinterpret_cast<LPVOID>(tls_directory.AddressOfCallBacks),
            &null, sizeof(PVOID), nullptr))
            throw std::runtime_error(std::format("Failed to write to address of TLS callbacks ({:#x})", GetLastError()));
        if (!VirtualProtectEx(hproc, reinterpret_cast<LPVOID>(tls_directory.AddressOfCallBacks),
            sizeof(PVOID), old_protection, &old_protection))
            throw std::runtime_error(std::format("Failed to reset protection of TLS callbacks ({:#x})", GetLastError()));

        // Create two threads that will be listening to our stdout and stderr from the child process
        std::thread(readfile_thread_proc, static_cast<HANDLE>(child_stdout_rd), std::ref(std::cout)).detach();
        std::thread(readfile_thread_proc, static_cast<HANDLE>(child_stderr_rd), std::ref(std::cerr)).detach();

        /*
        * Last but not least, inject ourselves into this process, calling the 'unpack' function with the tls callbacks as
        * the argument. This is so the unpacker can restore the TLS callbacks for dumping, and also trigger them itself.
        */
        exit_code = self_inject(hproc, unpack, tls_callbacks);
        if (exit_code != EXIT_SUCCESS)
            logging::error("Self inject result: {:#x}", exit_code);
    }
    catch (std::runtime_error const& err) {
        logging::error(err.what());
        exit_code = EXIT_FAILURE;
    }
    // And before exiting, just perform a flush so anything we wanted to have said, is said.
    std::cout.flush();
    std::wcout.flush();
    TerminateProcess(hproc, exit_code);
    return exit_code;
}