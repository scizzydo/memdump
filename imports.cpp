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

#include "imports.h"

#include <iostream>
#include <format>
#include <sstream>

#include "logging.hpp"
#include "concolic.hpp"
#include "module_functions.h"
#include "ExportDir.h"

// Import table rebuilder built and based off of namreebs dumpwow: https://github.com/namreeb/dumpwow/blob/master/dll/imports.cpp
class ImportTable {
    const uint32_t new_section_va;
    const uint32_t iat_va;
    const PVOID pe_base;

    std::vector<Module> modules;

    std::vector<uint8_t> buffer;

    struct ImportDirEntry {
        IMAGE_IMPORT_DESCRIPTOR header;
        std::string name;
        std::vector<IMAGE_THUNK_DATA> thunks;
        ImportDirEntry(const IMAGE_IMPORT_DESCRIPTOR& header, const std::string& name) :
            header(header), name(name)
        {}
    };

    std::vector<ImportDirEntry> import_dirs;

    auto write(const std::string& str) {
        auto const ret = buffer.size();
        buffer.resize(ret + str.length() + 1);
        memcpy(&buffer[ret], str.c_str(), str.length() + 1);
        return new_section_va + ret;
    }

    template<typename T>
    auto write() {
        auto const ret = buffer.size();
        buffer.resize(ret + sizeof(T));
        memset(&buffer[ret], 0, sizeof(T));
        return new_section_va + ret;
    }

    template<typename T>
    auto write(const T& value) {
        auto const ret = buffer.size();
        buffer.resize(ret + sizeof(T));
        memcpy(&buffer[ret], &value, sizeof(T));
        return new_section_va + ret;
    }

    template<typename T>
    auto write(const std::vector<T>& vec) {
        if (vec.empty())
            return new_section_va + buffer.size();

        auto const bytes = sizeof(T) * vec.size();

        auto const ret = buffer.size();
        buffer.resize(ret + bytes);
        memcpy(&buffer[ret], &vec[0], bytes);
        return new_section_va + ret;
    }

    ImportDirEntry& get_import_dir(PVOID function) {
        auto iter = std::find_if(modules.begin(), modules.end(), [function](auto const& entry) {
            return (entry.base < function &&
                reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(
                    entry.base) + entry.size) > function);
            });
        if (iter == modules.end())
            throw std::runtime_error(std::format("Failed to find {} in modules", function));

        ExportDir export_directory(iter->base);

        auto const module_name = export_directory.module_name();

        if (!import_dirs.empty() && import_dirs.back().name == module_name)
            return import_dirs.back();

        for (auto& import_dir : import_dirs) {
            if (import_dir.name == module_name)
                throw std::runtime_error("Import directory order failure");
        }

        IMAGE_IMPORT_DESCRIPTOR import_descriptor{};
        memset(&import_descriptor, 0, sizeof(import_descriptor));

        import_descriptor.Name = static_cast<DWORD>(write(module_name));

        import_dirs.emplace_back(import_descriptor, module_name);
        return import_dirs.back();
    }
public:
    ImportTable(PVOID base, uint32_t new_section_va, uint32_t iat_va, std::vector<Module>& modules) :
        new_section_va(new_section_va), iat_va(iat_va), modules(modules), pe_base(base)
    {}

    void add_function(PVOID thunk, PVOID function, bool force_new_dir, std::vector<Module>::iterator& iter) {
        auto nt_headers = module_nt_headers(iter->base);
        auto export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            reinterpret_cast<uintptr_t>(iter->base) +
            module_data_dir(iter->base, IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress);

        const std::string export_module_name = reinterpret_cast<const char*>(
            reinterpret_cast<uintptr_t>(iter->base) +
            export_directory->Name);

        auto thunk_rva = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(thunk) -
            reinterpret_cast<uintptr_t>(pe_base));

        IMAGE_THUNK_DATA thunk_data{};
        memset(&thunk_data, 0, sizeof(thunk_data));

        /*
        * force_new_dir is the classes way of saying the last module is done, and onto the next.
        * There is a possiblity the current module we're checking though isn't a new one, or the
        * last one.
        */
        if (!force_new_dir && !import_dirs.empty() &&
            import_dirs.back().name != export_module_name) {
            /*
            * Module passed in was is not the last module in the import directory.
            * This happens due to exported functions from a DLL exporting to another.
            */
            auto const current_module = import_dirs.back().name;
            auto const current_module_handle = GetModuleHandleA(current_module.c_str());

            if (!current_module_handle)
                throw std::runtime_error(std::format("Failed to get module handle! ({:X})",
                    GetLastError()));

            // Iterate each export to check if it was exported, and if so check if it's our one.
            const ExportDir current_module_export_dir(current_module_handle);
            for (auto const& exp : current_module_export_dir) {
                if (!exp.is_forwarded())
                    continue;

                PVOID target = nullptr;
                if (exp.is_forwarded_by_ordinal())
                    target = GetProcAddress(reinterpret_cast<HMODULE>(
                        iter->base), reinterpret_cast<LPCSTR>(exp.get_forwarder_ordinal()));
                else
                    target = GetProcAddress(reinterpret_cast<HMODULE>(
                        iter->base), exp.get_forwarder_function().c_str());

                if (!target || target != function)
                    continue;

                if (!exp.has_name()) {
                    /*
                    * If a function doesn't have a name, and is only exported by ordinal
                    * then we want to set the highest bit to 1 signifying it's to be imported
                    * by ordinal. Bits 0-15 will then be the ordinal used to import.
                    */
                    thunk_data.u1.Ordinal = exp.get_ordinal();
                    thunk_data.u1.Ordinal |= (1ULL << 63);
                }
                else {
                    /*
                    * Export did contain a name and hint, so we're going to set the ordinal
                    * in bits 0-15 followed by the name. Per PE specification, highest bit must
                    * be 0, so just ensuring it is for sanity...
                    */
                    thunk_data.u1.AddressOfData = static_cast<ULONGLONG>(
                        write(exp.get_hint()));
                    thunk_data.u1.AddressOfData &= ~(1ULL << 63);
                    write(exp.get_name());

                    if ((thunk_data.u1.AddressOfData +
                        exp.get_name().length() + 1) % 2 != 0)
                        write<uint8_t>(0);
                }

                logging::info("{:#016x} -> {}!{} (ord: {} hint: {:X}) {}", reinterpret_cast<uintptr_t>(thunk),
                    current_module, exp.get_name(), exp.get_ordinal(), exp.get_hint(),
                    (exp.is_forwarded_by_ordinal() ? "[ordinal forwarded]" : "[forwarded]"));

                import_dirs.back().thunks.push_back(thunk_data);
                memcpy(thunk, &thunk_data, sizeof(thunk_data));
                return;
            }
        }

        // Fell back from the export possibility, so this should be the last worked module or a new one.
        auto& import_dir = get_import_dir(function);

        const ExportDir export_dir(iter->base);
        for (auto const& e : export_dir) {
            if (e.get_function() == function) {
                if (import_dir.header.FirstThunk == 0)
                    import_dir.header.FirstThunk = thunk_rva;

                if (e.has_name()) {
                    /*
                    * If a function doesn't have a name, and is only exported by ordinal
                    * then we want to set the highest bit to 1 signifying it's to be imported
                    * by ordinal. Bits 0-15 will then be the ordinal used to import.
                    */
                    thunk_data.u1.Ordinal = e.get_ordinal();
                    thunk_data.u1.Ordinal |= (1ULL << 63);
                }
                else {
                    /*
                    * Export did contain a name and hint, so we're going to set the ordinal
                    * in bits 0-15 followed by the name. Per PE specification, highest bit must
                    * be 0, so just ensuring it is for sanity...
                    */
                    thunk_data.u1.AddressOfData = static_cast<ULONGLONG>(
                        write(e.get_hint()));
                    thunk_data.u1.AddressOfData &= ~(1ULL << 63);
                    write(e.get_name());

                    if ((thunk_data.u1.AddressOfData +
                        e.get_name().length() + 1) % 2 != 0)
                        write<uint8_t>(0);
                }

                logging::info("{:#016x} -> {}!{} (ord: {} hint: {:X})", reinterpret_cast<uintptr_t>(thunk),
                    export_module_name, e.get_name(), e.get_ordinal(), e.get_hint());

                import_dir.thunks.push_back(thunk_data);
                memcpy(thunk, &thunk_data, sizeof(thunk_data));
                return;
            }
        }
    }

    void finalize(PVOID base, PIMAGE_SECTION_HEADER new_section, std::vector<uint8_t>& buffer_out) {
        IMAGE_THUNK_DATA empty_thunk_data{};
        memset(&empty_thunk_data, 0, sizeof(empty_thunk_data));

        size_t count_funcs = 0, count_mods = import_dirs.size();
        // First run through is writing all the thunks to the import directory
        for (auto& import_dir : import_dirs) {
            // Point the current size of the buffer (in memory RVA) to the OriginalFirstThunk
            import_dir.header.OriginalFirstThunk = new_section_va +
                static_cast<uint32_t>(buffer.size());
            count_funcs += import_dir.thunks.size();
            // Write in the thunks to the import directory buffer
            write(import_dir.thunks);
            // Write a null terminated thunk to symbolize the end of the ILT portion of this module
            write(empty_thunk_data);
        }

        logging::info("Wrote import directory data for {} functions from {} modules",
            count_funcs, count_mods);

        // Capturing the RVA from the size of the buffer to where the import directory is.
        auto const import_dir_rva = static_cast<DWORD>(buffer.size());
        // Write all IMAGE_IMPORT_DESCRIPTORs to the buffer
        for (auto& import_dir : import_dirs)
            write(import_dir.header);

        auto const nt_headers = module_nt_headers(base);

        // Ensuring our import directory is file aligned
        buffer.resize(ALIGN_UP(static_cast<DWORD>(buffer.size()),
            nt_headers->OptionalHeader.FileAlignment));

        // Section SizeOfRawData set to reflect the buffer size
        new_section->SizeOfRawData = static_cast<DWORD>(buffer.size());
        // Virtual size can be larger than size of raw data. Ensuring it's section aligned.
        new_section->Misc.VirtualSize = ALIGN_UP(
            static_cast<DWORD>(buffer.size()),
            nt_headers->OptionalHeader.SectionAlignment);

        auto import_data_dir = module_data_dir(base, IMAGE_DIRECTORY_ENTRY_IMPORT);
        // Update the import directory virtual address to point to our new directory
        import_data_dir->VirtualAddress = new_section_va + import_dir_rva;
        // Set the import directory size to the import directory size
        import_data_dir->Size = static_cast<DWORD>(import_dirs.size() *
            sizeof(IMAGE_IMPORT_DESCRIPTOR));

        auto iat_data_dir = module_data_dir(base, IMAGE_DIRECTORY_ENTRY_IAT);
        // Ensure the IAT size and VA are updated
        iat_data_dir->VirtualAddress = iat_va;
        iat_data_dir->Size = import_dir_rva;

        buffer_out = std::move(buffer);
    }
};

PIMAGE_SECTION_HEADER add_section(PVOID base) {
    auto const nt_headers = module_nt_headers(base);
    auto const sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_headers + 1);
    auto const last_section = &sections[nt_headers->FileHeader.NumberOfSections - 1];

    // Getting the virtual address of the last section to calculate where new header VA will be
    auto const section_header_va = reinterpret_cast<uint8_t*>(
        reinterpret_cast<uintptr_t>(last_section) +
        sizeof(IMAGE_SECTION_HEADER));
    // End of the last section is where our new section will reside
    auto const section_header_end_va = section_header_va +
        sizeof(IMAGE_SECTION_HEADER);

    /*
    * If the section header end is larger than the SizeOfHeaders we must update different
    * parts of the PE header (which we're doing anyway, so this is just for info).
    */
    if (section_header_end_va > reinterpret_cast<uint8_t*>(base) +
        nt_headers->OptionalHeader.SizeOfHeaders)
        logging::info("Need to extend section header to accomodate for new section");

    IMAGE_SECTION_HEADER new_section;
    memset(&new_section, 0, sizeof(IMAGE_SECTION_HEADER));
    /*
    * New section can be named anything, however it's purpose is for imports, then
    * might as well name it imports. Maybe do checking instead to see if .idata exists
    * as that is the Windows PE name per the docs.
    */
    memcpy(new_section.Name, ".import", sizeof(".import"));
    // Virtual Address to the actual data when loaded into memory based off last section.
    new_section.VirtualAddress = last_section->VirtualAddress +
        last_section->Misc.VirtualSize;
    new_section.PointerToRawData = last_section->PointerToRawData +
        last_section->SizeOfRawData;
    // Setting characteristics to this section so that it's marked as initialized data.
    new_section.Characteristics = IMAGE_SCN_MEM_READ |
        IMAGE_SCN_CNT_INITIALIZED_DATA;

    memcpy(section_header_va, &new_section, sizeof(new_section));
    // Finally update NT headers so it reflects we added this new section
    nt_headers->FileHeader.NumberOfSections += 1;

    return reinterpret_cast<PIMAGE_SECTION_HEADER>(section_header_va);
}

std::vector<uint8_t> fix_imports(PVOID base) {
    auto const new_section = add_section(base);
    if (!new_section) {
        logging::error("Failed to create a new section!");
        return {};
    }
    else {
        logging::info("New section {} added. Virtual Address: {:#x}",
            reinterpret_cast<const char*>(new_section->Name),
            new_section->VirtualAddress);
    }

    /*
    * Enumerating all the modules in the process now so we don't have to so
    * we don't have to each address below when looking for the exports.
    */
    auto modules = process_modules();

    auto const nt_headers = module_nt_headers(base);
    auto const image_size = nt_headers->OptionalHeader.SizeOfImage;

    // Helper function to quickly decide whether or not the address can be an export.
    auto valid_pointer = [base, image_size](uintptr_t address) {
        // If the address resides in our image, we know it's not an export
        if (address > reinterpret_cast<uintptr_t>(base) &&
            address < reinterpret_cast<uintptr_t>(base) + image_size)
            return false;

        // Ensuring that the address points to an accessable, executable region.
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
            return false;
        return mbi.RegionSize != 0 && !(mbi.Protect & PAGE_NOACCESS) && (mbi.Protect & PAGE_EXECUTE_READWRITE);
    };

    // Getting the PEs .rdata section to start our search
    auto const rdata = module_section(base, ".rdata");

    // Helper variable to the virtual address of the rdata section
    auto const rdata_start = reinterpret_cast<PVOID>(
        reinterpret_cast<uintptr_t>(base) +
        rdata->VirtualAddress);

    MEMORY_BASIC_INFORMATION rdata_mbi{};
    VirtualQuery(rdata_start, &rdata_mbi, sizeof(rdata_mbi));

    // Helper variable to the end of the rdata section
    auto const rdata_end = reinterpret_cast<PVOID>(
        reinterpret_cast<uintptr_t>(rdata_start) +
        rdata_mbi.RegionSize);
    
    // Helper variable to that is the relative VA from the PE base
    auto const rdata_va = static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(rdata_start) -
        reinterpret_cast<uintptr_t>(base));

    ImportTable import_table(base, new_section->VirtualAddress, rdata_va, modules);

    /*
    * Start of the IAT search. force_new_import_dir signifies that a new module
    * has been hit, so we start a new portion to reflect this.
    */ 
    PVOID iat_start = nullptr;
    bool force_new_import_dir = true;
    for (auto current_addr = reinterpret_cast<PVOID*>(rdata_start);
        current_addr < rdata_end; ++current_addr) {
        auto const thunk_ea = *current_addr;

        // Helper to identify if we're good to check this address, or break out.
        auto valid = !thunk_ea || valid_pointer(reinterpret_cast<uintptr_t>(thunk_ea));

        /*
        * If the thunk_ea is NULL then it is probably the NULL terminated thunk data,
        * meaning we want to start a new import directory.
        */
        if (!thunk_ea)
            force_new_import_dir = true;

        if (valid && thunk_ea) {
            // Credits to namreeb on the concolic search
            ConcolicThreadContext ctx{};
            if (!concolic_begin(thunk_ea, ctx))
                continue;

            // The RAX contains the address of our import function we want
            auto const function = ctx.rax;

            // Check to ensure this address resides within one of the modules enumerated earlier
            auto it = std::find_if(modules.begin(), modules.end(), [function](auto const& entry) {
                return reinterpret_cast<uintptr_t>(entry.base) < function &&
                    reinterpret_cast<uintptr_t>(entry.base) + entry.size > function;
                });
            if (it != modules.end()) {
                if (!iat_start)
                    iat_start = reinterpret_cast<PVOID>(current_addr);

                try {
                    import_table.add_function(current_addr, reinterpret_cast<PVOID>(function),
                        force_new_import_dir, it);
                }
                catch (std::runtime_error& err) {
                    logging::error(err.what());
                    return {};
                }

                /*
                * Setting our variable to false so the following functions get
                * set to the same module, until the null thunk is hit.
                */ 
                force_new_import_dir = false;
            }
        }

        // Breaking out as we don't want to keep checking the whole rdata
        if (iat_start && !valid)
            break;
    }

    std::vector<uint8_t> buffer;
    // Put all the collected information together to feed our import directory into the buffer
    import_table.finalize(base, new_section, buffer);
    return buffer;
}