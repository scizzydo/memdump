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

#include "module_functions.h"

#include <fstream>
#include <TlHelp32.h>

#include "misc.h"
#include "SmartHandle.hpp"

std::vector<uint8_t> disk_headers(HMODULE hmod) {
    auto const path = module_path(hmod);
    std::vector<uint8_t> headers(0x1000, 0);
    std::ifstream ifs(path, std::ios::binary);
    ifs >> std::noskipws;
    ifs.read(reinterpret_cast<char*>(&headers[0]), 0x1000);
    ifs.close();
    return headers;
}

PIMAGE_DOS_HEADER module_dos_header(PVOID base) {
    return reinterpret_cast<PIMAGE_DOS_HEADER>(base);
}

PIMAGE_NT_HEADERS module_nt_headers(PVOID base) {
    auto dos_header = module_dos_header(base);
    return reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(base) + dos_header->e_lfanew);
}

PIMAGE_SECTION_HEADER module_section(PVOID base, const char* name) {
    auto nt_headers = module_nt_headers(base);
    auto image_section = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_headers + 1);
    for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        if (!_stricmp(reinterpret_cast<const char*>(image_section->Name), name))
            return image_section;
        ++image_section;
    }
    return nullptr;
}

PIMAGE_DATA_DIRECTORY module_data_dir(PVOID base, uint32_t index) {
    auto const nt_headers = module_nt_headers(base);
    return reinterpret_cast<PIMAGE_DATA_DIRECTORY>(
        &nt_headers->OptionalHeader.DataDirectory[index]);
}

std::vector<Module> process_modules() {
    std::vector<Module> modules;
    SmartHandle snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (!snap)
        return modules;
    MODULEENTRY32 me32{};
    me32.dwSize = sizeof(me32);
    if (Module32First(snap, &me32)) {
        do {
            modules.push_back(Module{ .base = me32.modBaseAddr, .size = me32.modBaseSize });
        } while (Module32Next(snap, &me32));
    }
    return modules;
}
