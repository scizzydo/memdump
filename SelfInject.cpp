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

#include "SelfInject.h"

#include <format>

#include "tstream.h"
#include "module_functions.h"
#include "RemoteBuffer.hpp"
#include "logging.hpp"

// Some data passed in from the injector to the remote loader
struct RemoteContext {
    PVOID base;
    PVOID func;
    PVOID args;
};

/*
* Remote loader is the function called on the internal side. Once internal,
* performing operations like a manual mapping to ensure all our relocations
* are handled, imports are done, and TLS called.
*/ 
DWORD WINAPI remote_loader(LPVOID lpThreadParameter) {
    auto const context = reinterpret_cast<RemoteContext*>(lpThreadParameter);
    auto const our_base = context->base;
    auto const nt_headers = module_nt_headers(our_base);

    /*
    * Capture the difference from the original process base, to the injected
    * process base.
    */ 
    auto const difference = reinterpret_cast<intptr_t>(our_base) -
        static_cast<intptr_t>(nt_headers->OptionalHeader.ImageBase);

    // If the base_delta is 0, then we don't need to do any relocations
    if (difference != 0) {
        auto base_relocation_dir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            reinterpret_cast<uint8_t*>(our_base) +
            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        // While the base_relocations contains info, perform relocations.
        while (base_relocation_dir->VirtualAddress && base_relocation_dir->SizeOfBlock) {
            auto const count = base_relocation_dir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(WORD);
            auto const list = reinterpret_cast<PWORD>(base_relocation_dir + 1);
            auto const base_reloction_address = reinterpret_cast<uintptr_t>(our_base) +
                base_relocation_dir->VirtualAddress;
            // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
            for (auto i = 0; i < count; ++i) {
                auto const relocation_address = reinterpret_cast<uint16_t*>(base_reloction_address + 
                    (list[i] & 0xFFFui16));
                switch (list[i] >> 12) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    /*
                    * The base relocation is skipped. This type can be used to pad a block. 
                    */
                    break;
                case IMAGE_REL_BASED_HIGH:
                    /*
                    * The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
                    * The 16-bit field represents the high value of a 32-bit word. 
                    */
                    *relocation_address += HIWORD(difference);
                    break;
                case IMAGE_REL_BASED_LOW:
                    /*
                    * The base relocation adds the low 16 bits of the difference to the 16-bit field at offset.
                    * The 16-bit field represents the low half of a 32-bit word.
                    */
                    *relocation_address += LOWORD(difference);
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    /*
                    * The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
                    */
                    *reinterpret_cast<uint32_t*>(relocation_address) += static_cast<int32_t>(difference);
                    break;
                case IMAGE_REL_BASED_HIGHADJ:
                    /*
                    * The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
                    * The 16-bit field represents the high value of a 32-bit word.
                    * The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation.
                    * This means that this base relocation occupies two slots. 
                    * 
                    * Used https://chromium.googlesource.com/external/pefile/+/6fbf45c72aed00c5833d088749febd3706ef8212/pefile.py#4628 as reference
                    */
                    *relocation_address = ((*relocation_address << 16) + list[++i] + static_cast<int32_t>(difference) & 0xFFFF0000) >> 16;
                    break;
                case IMAGE_REL_BASED_DIR64:
                    // The base relocation applies the difference to the 64-bit field at offset.
                    *reinterpret_cast<uint64_t*>(relocation_address) += difference;
                    break;
                default: break;
                }
            }
            base_relocation_dir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<uintptr_t>(base_relocation_dir) +
                base_relocation_dir->SizeOfBlock);
        }
    }

    /*
    * Collect the import directory information to ensure all dependencies are
    * loaded into this process for us to use.
    */
    auto import_descriptor_dir = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<uint8_t*>(our_base) +
        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (import_descriptor_dir->Characteristics) {
        auto original_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<uintptr_t>(our_base) +
            import_descriptor_dir->OriginalFirstThunk);
        auto first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<uintptr_t>(our_base) +
            import_descriptor_dir->FirstThunk);
        auto const library_name = reinterpret_cast<char*>(
            reinterpret_cast<uintptr_t>(our_base) +
            import_descriptor_dir->Name);

        auto const hmod = LoadLibraryA(library_name);
        if (!hmod)
            return EXIT_FAILURE;

        while (original_first_thunk->u1.AddressOfData) {
            if (original_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Thunk is imported by ordinal, so load it via ordinal
                auto const proc_address = GetProcAddress(hmod,
                    reinterpret_cast<LPCSTR>(original_first_thunk->u1.Ordinal & 0xFFFF));
                if (!proc_address)
                    return EXIT_FAILURE;
                first_thunk->u1.Function = reinterpret_cast<ULONGLONG>(proc_address);
            }
            else {
                // Thunk is imported by name
                auto const import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                    reinterpret_cast<uintptr_t>(our_base) +
                    original_first_thunk->u1.AddressOfData);
                auto const proc_address = GetProcAddress(hmod,
                    reinterpret_cast<LPCSTR>(import_by_name->Name));
                if (!proc_address)
                    return EXIT_FAILURE;
                first_thunk->u1.Function = reinterpret_cast<ULONGLONG>(proc_address);
            }
            ++original_first_thunk;
            ++first_thunk;
        }
        ++import_descriptor_dir;
    }

    // Get the TLS directory to perform all the TLS callbacks if they're needed.
    auto& tls_data_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_data_directory.Size) {
        auto const image_tls_directory = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(
            reinterpret_cast<uintptr_t>(our_base) +
            tls_data_directory.VirtualAddress);
        for (auto tls_callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(
            image_tls_directory->AddressOfCallBacks); *tls_callback; ++tls_callback)
            (*tls_callback)(our_base, DLL_PROCESS_ATTACH, nullptr);
    }
    // Finally, execute the function we passed through into the self_inject function
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(
        reinterpret_cast<uintptr_t>(our_base) +
        reinterpret_cast<uintptr_t>(context->func))(context->args);
}

DWORD self_inject(HANDLE process, LPTHREAD_START_ROUTINE func, PVOID args) {
    auto const image_base = reinterpret_cast<PVOID>(GetModuleHandle(NULL));
    auto const nt_headers = module_nt_headers(image_base);
    auto const size_of_image = nt_headers->OptionalHeader.SizeOfImage;

    // Attempting to load into the remote process at the same base address of our process
    RemoteBuffer buffer(process, image_base, size_of_image + sizeof(RemoteContext), PAGE_EXECUTE_READWRITE, true);
    if (!buffer) {
        logging::info("Failed to allocate buffer at requested address: {:#x}", reinterpret_cast<uintptr_t>(image_base));
        // If the buffer couldn't be allocated at our buffer, let the system choose the new base.
        if (!buffer.allocate(nullptr, size_of_image + sizeof(RemoteContext), PAGE_EXECUTE_READWRITE)) {
            logging::error("Failed to allocate buffer in remote process! {:#x}", GetLastError());
            return EXIT_FAILURE;
        }
    }
    logging::success("Allocated remote buffer at {:#x}", static_cast<uintptr_t>(buffer));

    /*
    * Collecting the data to pass to the RemoteContext structure loaded into the remote process.
    * This isn't really neaded, but wanted to pass something into the function argument. Since
    * we're loading our own process as it's already initialized and running in our process, the
    * data can already be set and read once in the remote process (see the exe_path for example).
    */
    RemoteContext ctx{
        .base = buffer,
        .func = reinterpret_cast<PVOID>(
            reinterpret_cast<uintptr_t>(func) - reinterpret_cast<uintptr_t>(image_base)),
        .args = args
    };

    // Write the remote context into target process
    if (!WriteProcessMemory(process, reinterpret_cast<LPVOID>(
        static_cast<uintptr_t>(buffer) + size_of_image), &ctx, sizeof(RemoteContext), nullptr)) {
        buffer.make_persistant(false);
        logging::error("Failed to write loader into remote process! {:#x}", GetLastError());
        return EXIT_FAILURE;
    }

    // Write our whole PE into the remote process
    if (!WriteProcessMemory(process, buffer, image_base, size_of_image, nullptr)) {
        buffer.make_persistant(false);
        logging::error("Failed to write image into remote process! {:#x}", GetLastError());
        return EXIT_FAILURE;
    }

    // Calculate the difference from our process to the remote loader and account for that in the target
    auto const remote_func = reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<uintptr_t>(buffer) +
        reinterpret_cast<uintptr_t>(remote_loader) - reinterpret_cast<uintptr_t>(image_base));

    // Finally, executing the remote loader in the target process and waiting for it to finish
    SmartHandle hthread = CreateRemoteThread(process, nullptr, NULL, remote_func, reinterpret_cast<LPVOID>(
        static_cast<uintptr_t>(buffer) + size_of_image), NULL, nullptr);
    if (!hthread) {
        buffer.make_persistant(false);
        logging::error("Failed to create remote thread! {:#x}", GetLastError());
        return EXIT_FAILURE;
    }
    WaitForSingleObject(hthread, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeThread(hthread, &exit_code);
    return exit_code;
}