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

#include "ExportDir.h"

#include <iostream>

#include "module_functions.h"
#include <string>
#include <format>

#ifdef max
#undef max
#endif

ExportDir::ExportDir(PVOID base) :
    base_(base) 
{
    data_directory_ = module_data_dir(base, IMAGE_DIRECTORY_ENTRY_EXPORT);

    export_directory_ = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<uintptr_t>(base) +
        data_directory_->VirtualAddress);

    export_functions_ = reinterpret_cast<PDWORD>(
        reinterpret_cast<uintptr_t>(base) +
        export_directory_->AddressOfFunctions);
    export_names_ = reinterpret_cast<PDWORD>(
        reinterpret_cast<uintptr_t>(base) +
        export_directory_->AddressOfNames);
    export_name_ordinals_ = reinterpret_cast<PWORD>(
        reinterpret_cast<uintptr_t>(base) +
        export_directory_->AddressOfNameOrdinals);
}

std::string ExportDir::module_name() const {
    return reinterpret_cast<const char*>(
        reinterpret_cast<uintptr_t>(base_) +
        export_directory_->Name);
}

DWORD ExportDir::ordinal_base() const {
    return export_directory_->Base;
}

DWORD ExportDir::number_of_functions() const {
    return export_directory_->NumberOfFunctions;
}

DWORD ExportDir::number_of_names() const {
    return export_directory_->NumberOfNames;
}

PDWORD ExportDir::export_function() const {
    return export_functions_;
}

PDWORD ExportDir::export_names() const {
    return export_names_;
}

PWORD ExportDir::export_name_ordinals() const {
    return export_name_ordinals_;
}

DWORD ExportDir::Function::get_function_rva() const {
    return function_rva_;
}

ExportDir::Function::Function(const ExportDir* export_dir, WORD hint) :
    export_dir_(export_dir), forwarded_(false), hint_(hint)
{
    auto num_names = export_dir_->export_directory_->NumberOfNames;
    auto num_funcs = export_dir_->export_directory_->NumberOfFunctions;
    if (hint < num_names)
        name_rva_ = export_dir_->export_names_[hint];
    else
        name_rva_ = 0;
    if (hint >= num_names) {
        hint_ = std::numeric_limits<WORD>::max();
        ordinal_ = static_cast<WORD>(num_funcs - hint) - 1;
        function_rva_ = export_dir_->export_functions_[ordinal_];
    }
    else {
        ordinal_ = export_dir_->export_name_ordinals_[hint];
        function_rva_ = export_dir_->export_functions_[ordinal_];
    }

    auto const export_dir_start = export_dir_->data_directory_->VirtualAddress;
    auto const export_dir_end = export_dir_->data_directory_->VirtualAddress +
        export_dir_->data_directory_->Size;
    if (function_rva_ >= export_dir_start &&
        function_rva_ + 4 < export_dir_end) {
        forwarded_ = true;
        forwarder_ = reinterpret_cast<const char*>(
            reinterpret_cast<uintptr_t>(export_dir_->base_) +
            function_rva_);

        auto const split_pos = forwarder_.rfind('.');
        if (split_pos != std::string::npos) {
            forwarder_split_ = std::make_pair(forwarder_.substr(0, split_pos),
                forwarder_.substr(split_pos + 1));
        }
    }
}

WORD ExportDir::Function::get_hint() const {
    return hint_;
}

WORD ExportDir::Function::get_ordinal() const {
    return static_cast<WORD>(
        export_dir_->export_directory_->Base + ordinal_);
}

PVOID ExportDir::Function::get_function() const {
    return reinterpret_cast<PVOID>(
        reinterpret_cast<uintptr_t>(export_dir_->base_) +
        function_rva_);
}

bool ExportDir::Function::has_name() const {
    return name_rva_ != 0;
}

bool ExportDir::Function::has_hint() const {
    return hint_ != std::numeric_limits<WORD>::max();
}

std::string ExportDir::Function::get_name() const {
    if (!has_name())
        return "[NONAME]";
    return reinterpret_cast<const char*>(
        reinterpret_cast<uintptr_t>(export_dir_->base_) +
        name_rva_);
}

bool ExportDir::Function::is_forwarded() const {
    return forwarded_;
}

WORD ExportDir::Function::get_forwarder_ordinal() const {
    if (!is_forwarded_by_ordinal())
        throw std::runtime_error(std::format("{} is not forwarded by ordinal", get_name()));

    auto const forwarder_function{ get_forwarder_function() };
    return static_cast<WORD>(std::stoul(std::string(forwarder_function.begin() + 1, 
        forwarder_function.end())));
}

std::string ExportDir::Function::get_forwarder_module() const {
    return forwarder_split_.first;
}

std::string ExportDir::Function::get_forwarder_function() const {
    return forwarder_split_.second;
}

bool ExportDir::Function::is_forwarded_by_ordinal() const {
    return get_forwarder_function()[0] == '#';
}
