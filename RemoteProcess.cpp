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

#include "RemoteProcess.h"

#include <format>
#include <stdexcept>
#include <winternl.h>

// Reads the remote process PEB to get the base address
PVOID RemoteProcess::base() {
    PROCESS_BASIC_INFORMATION process_basic_information{};
    ULONG bytes{};

    auto status = NtQueryInformationProcess(m_hproc, ProcessBasicInformation, &process_basic_information,
        static_cast<ULONG>(sizeof(process_basic_information)), &bytes);
    if (!NT_SUCCESS(status))
        throw std::runtime_error(std::format("Failed to query ProcessBasicInformation ({:#x})", status));

    if (!process_basic_information.PebBaseAddress)
        throw std::runtime_error("PebBaseAddress returned NULL");

    PEB peb;
    if (!ReadProcessMemory(m_hproc, process_basic_information.PebBaseAddress, &peb, sizeof(peb), nullptr))
        throw std::runtime_error(std::format("Failed to read peb ({:#x})", GetLastError()));

    return peb.Reserved3[1];
}

// Self explanatory function
IMAGE_DOS_HEADER RemoteProcess::image_dos_header() {
    auto base_address = base();
    IMAGE_DOS_HEADER header{};
    if (!ReadProcessMemory(m_hproc, base_address, &header, sizeof(IMAGE_DOS_HEADER), nullptr))
        throw std::runtime_error(std::format("Failed to read IMAGE_DOS_HEADER ({:#x})", GetLastError()));
    return header;
}

// Self explanatory function
IMAGE_NT_HEADERS RemoteProcess::image_nt_headers() {
    auto base_address = base();
    auto dos_header = image_dos_header();
    IMAGE_NT_HEADERS headers{};
    if (!ReadProcessMemory(m_hproc, reinterpret_cast<LPCVOID>(
        reinterpret_cast<uintptr_t>(base_address) + dos_header.e_lfanew), &headers, sizeof(headers), nullptr))
        throw std::runtime_error(std::format("Failed to read IMAGE_NT_HEADERS ({:#x})", GetLastError()));
    return headers;
}

// Self explanatory function
IMAGE_TLS_DIRECTORY RemoteProcess::image_tls_directory() {
    IMAGE_TLS_DIRECTORY directory{};
    auto const base_address = base();
    auto const nt_headers = image_nt_headers();
    auto const image_directory_tls = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (image_directory_tls.Size) {
        if (!ReadProcessMemory(m_hproc, reinterpret_cast<LPCVOID>(
            reinterpret_cast<uintptr_t>(base_address) + image_directory_tls.VirtualAddress),
            &directory, sizeof(IMAGE_TLS_DIRECTORY), nullptr))
            throw std::runtime_error(std::format("Failed to read IMAGE_TLS_DIRECTORY ({:#x})", GetLastError()));
    }
    return directory;
}
