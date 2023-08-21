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

#include <fstream>

#include "misc.h"
#include "imports.h"
#include "tstream.h"
#include "ntdllhooks.h"
#include "module_functions.h"
#include "shared_data.hpp"
#include "logging.hpp"

void fix_tls_callbacks(PVOID base, PVOID callbacks) {
    auto const nt_headers = module_nt_headers(base);
    // We need the TLS directory from the nt headers to restore our callback we nulled out
    auto const tls_directory = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(
        reinterpret_cast<uintptr_t>(base) + 
        module_data_dir(base, IMAGE_DIRECTORY_ENTRY_TLS)->VirtualAddress);

    // variable to hold the address of the callbacks where the first one is nulled out
    auto const tls_callbacks = reinterpret_cast<LPVOID>(tls_directory->AddressOfCallBacks);

    // Restoring the TLS callbacks to their original value. We know they won't trigger now.
    DWORD old_protection = NULL;
    VirtualProtect(tls_callbacks, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &old_protection);
    reinterpret_cast<PVOID*>(tls_callbacks)[0] = callbacks;
    VirtualProtect(tls_callbacks, sizeof(PVOID), old_protection, &old_protection);

    // Since the TLS callbacks didn't fire, and we already did what we want, let's force them.
    uint32_t count = 0;
    for (auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls_callbacks);
        *callback; ++callback) {
        logging::info("Executing TLS Callback {}: {:#x}", ++count, reinterpret_cast<uintptr_t>(*callback));
        (*callback)(base, DLL_PROCESS_ATTACH, nullptr);
    }
}

std::vector<uint8_t> fix_pe_headers(PVOID base) {
    auto const nt_headers = module_nt_headers(base);
    auto size_of_headers = reinterpret_cast<uintptr_t>(nt_headers + 1) - 
        reinterpret_cast<uintptr_t>(base) + 
        (nt_headers->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    auto const disk_header_data = disk_headers(reinterpret_cast<HMODULE>(base));
    std::vector<uint8_t> original_headers(size_of_headers, 0);
    memcpy(&original_headers[0], base, size_of_headers);

    memcpy(base, &disk_header_data[0], size_of_headers);
    return original_headers;
}

/*
* See namreeb's dumpwow for original comment: https://github.com/namreeb/dumpwow/blob/master/dll/dumper.cpp#L195
* Forcing all of the sections in the PE to be section aligned in memory, and file aligned on disk.
* Taking this opportunity to also update the NT headers with various data changes such as the size of our code, 
* intialized data, and unintialized data. In addition, the size of our headers may have changed due to a new
* section being added, so we want to ensure everything packs back up nicely for the dumping back to disk.
*/
void realign_sections(PVOID base) {
    auto const nt_headers = module_nt_headers(base);
    auto const section_align = nt_headers->OptionalHeader.SectionAlignment;
    auto const file_align = nt_headers->OptionalHeader.FileAlignment;

    uint32_t size_of_code = NULL, size_of_data = NULL, size_of_uninit_data = NULL;
    auto pointer_to_raw_data = nt_headers->OptionalHeader.SizeOfHeaders;
    auto image_sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_headers + 1);
    for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        auto const image_section = &image_sections[i];
        auto const virtual_size = ALIGN_UP(image_section->Misc.VirtualSize, section_align);

        auto const section_base = reinterpret_cast<uint8_t*>(base) + image_section->VirtualAddress;

        image_section->Misc.VirtualSize = virtual_size;
        if (_stricmp(".import", reinterpret_cast<const char*>(image_section->Name)) != 0) {
            for (auto remaining = virtual_size; remaining != 0; --remaining) {
                auto const current = section_base + remaining - 1;

                if (*current != 0x00) {
                    image_section->SizeOfRawData = ALIGN_UP(remaining, file_align);
                    break;
                }
            }
        }

        image_section->PointerToRawData = pointer_to_raw_data;
        pointer_to_raw_data += image_section->SizeOfRawData;

        auto const characteristics = image_section->Characteristics;

        if (characteristics & IMAGE_SCN_CNT_CODE)
            size_of_code += image_section->Misc.VirtualSize;
        else if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
            size_of_data += image_section->Misc.VirtualSize;
        else if (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            size_of_uninit_data += image_section->Misc.VirtualSize;
    }

    nt_headers->OptionalHeader.SizeOfCode = size_of_code;
    nt_headers->OptionalHeader.SizeOfInitializedData = size_of_data;
    nt_headers->OptionalHeader.SizeOfUninitializedData = size_of_uninit_data;

    auto const last_section = &image_sections[nt_headers->FileHeader.NumberOfSections - 1];
    nt_headers->OptionalHeader.SizeOfImage = ALIGN_UP(
        last_section->VirtualAddress + last_section->Misc.VirtualSize, section_align);

    auto size_of_headers = static_cast<DWORD>(ALIGN_UP(reinterpret_cast<uintptr_t>(nt_headers + 1) -
        reinterpret_cast<uintptr_t>(base) +
        (nt_headers->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)), file_align));
    nt_headers->OptionalHeader.SizeOfHeaders = size_of_headers;
}

/*
* Relocations in this process currently are based off the in memory address. We want to push
* everything back to be in line and match the default base from the disk (i.e. 0x140000000)
*/
void fix_relocations(PVOID base) {
    auto const nt_headers = module_nt_headers(base);
    auto relocations = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
        reinterpret_cast<uintptr_t>(base) + 
        module_data_dir(base, IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress);

    auto const old_base = reinterpret_cast<intptr_t>(base);
    auto const new_base = static_cast<intptr_t>(nt_headers->OptionalHeader.ImageBase);
    auto const base_diff = new_base - old_base;

    while (relocations->SizeOfBlock && relocations->VirtualAddress) {
        auto const block_relocation_count = (relocations->SizeOfBlock -
            sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto const block_entries = reinterpret_cast<PWORD>(
            reinterpret_cast<uintptr_t>(relocations) +
            sizeof(IMAGE_BASE_RELOCATION));

        for (auto i = 0; i < block_relocation_count; ++i) {
            if ((block_entries[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                auto const p = reinterpret_cast<uintptr_t*>(old_base +
                    relocations->VirtualAddress + (block_entries[i] & 0xFFF));
                *p += base_diff;
            }
        }

        relocations = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            reinterpret_cast<uintptr_t>(relocations) + relocations->SizeOfBlock);
    }
}

void rebuild_pe(PVOID base, const std::vector<uint8_t>& import_dir) {
    auto const nt_headers = module_nt_headers(base);
    auto name = get_new_filename(module_path(reinterpret_cast<HMODULE>(base)));
    logging::info(_T("Creating dump {}"), name.native());

    std::ofstream ofs(name, std::ios::binary);
    if (!ofs.good()) {
        logging::error(_T("Failed to open up {}"), name.native());
        return;
    }

    realign_sections(base);

    auto total_size = nt_headers->OptionalHeader.SizeOfHeaders;

    auto tellp = ofs.tellp();
    ofs.write(reinterpret_cast<const char*>(base),
        static_cast<std::streamsize>(total_size));
    logging::info("Wrote section headers to disk: {:#x} total bytes", total_size);

    auto image_section = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_headers + 1);
    for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        auto const section_start = reinterpret_cast<const char*>(base) + image_section->VirtualAddress;
        auto const section_size = image_section->SizeOfRawData;
        
        if (!_stricmp(".import", reinterpret_cast<const char*>(image_section->Name))) {
            ofs.write(reinterpret_cast<const char*>(&import_dir[0]), import_dir.size());
            if (ofs.bad()) {
                logging::error("ofstream bad bit got set! Resetting. May need investigating!");
                ofs.clear();
            }
        }
        else {
            ofs.write(section_start, section_size);
            if (ofs.bad()) {
                logging::error("ofstream bad bit got set! Resetting. May need investigating!");
                ofs.clear();
            }
        }
        total_size += section_size;
        logging::info("Wrote section {} to disk: {:#x} total bytes",
            reinterpret_cast<const char*>(image_section->Name), total_size);
        ++image_section;
    }
    if (ofs.tellp() - tellp > 0)
        logging::success(_T("Successfully created {}!"), name.native());
    ofs.close();
}

DWORD WINAPI unpack(LPVOID lpReserved) {
    auto const base = reinterpret_cast<PVOID>(GetModuleHandle(NULL));
    logging::info("Process base: {}", base);
    logging::info("TLS callbacks: {}", lpReserved);

    auto result = EXIT_SUCCESS;
    setup_hooks();

    fix_tls_callbacks(base, lpReserved);

    fix_pe_headers(base);

    realign_sections(base);

    auto const new_import_dir = fix_imports(base);
    if (new_import_dir.size()) {
        fix_relocations(base);

        realign_sections(base);

        rebuild_pe(base, new_import_dir);
    }
    else {
        result = EXIT_FAILURE;
        logging::error("Failed to fix imports! Not writing to disk.");
    }

    std::cout.flush();
    std::wcout.flush();
    return result;
}