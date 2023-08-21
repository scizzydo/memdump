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

#pragma once
#include <Windows.h>
#include <iterator>
#include <optional>
#include <memory>
#include <string>

/*
* Helper class for the import table rebuilding. Contains sub class for iterating, and also function data.
* This was the first time I've ever written an iterator class, and can say a lot of this is based off of
* hadesmem:
* https://github.com/namreeb/hadesmem/blob/master/include/memory/hadesmem/pelib/export.hpp
* https://github.com/namreeb/hadesmem/blob/master/include/memory/hadesmem/pelib/export_dir.hpp
* https://github.com/namreeb/hadesmem/blob/master/include/memory/hadesmem/pelib/export_list.hpp
* 
* Didn't see a need to have it all split up, as I'm accessing each bit and piece at the same time as initalizing
* the base ExportDir class.
* Items addressed in this vs hadesmem:
* handling export functions just like when enumerating them from Windows dumpbin tool
* added hint identification (the index to the name table being the hint)
* slimmed up parts from the 3 files provided above
* removed std::iterator to avoid warning from it's deprecation in c++17
* 
* Function names should be self explanatory to what they're for
*/
class ExportDir {
    PVOID base_;
    PDWORD export_functions_;
    PDWORD export_names_;
    PWORD export_name_ordinals_;
    PIMAGE_DATA_DIRECTORY data_directory_;
    PIMAGE_EXPORT_DIRECTORY export_directory_;
public:
    class Function {
        const ExportDir* export_dir_;
        WORD hint_;
        WORD ordinal_;
        DWORD name_rva_;
        DWORD function_rva_;
        bool forwarded_;
        std::string forwarder_;
        std::pair<std::string, std::string> forwarder_split_;
    public:
        Function(const ExportDir* export_dir, WORD hint);
        WORD get_hint() const;
        WORD get_ordinal() const;
        PVOID get_function() const;
        std::string get_name() const;
        bool is_forwarded() const;
        WORD get_forwarder_ordinal() const;
        std::string get_forwarder_module() const;
        std::string get_forwarder_function() const;
        bool is_forwarded_by_ordinal() const;
        bool has_name() const;
        bool has_hint() const;
        DWORD get_function_rva() const;
    };
    template <typename T>
    class Iterator {
    public:
        using value_type = T;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type*;
        using reference = value_type&;
        using iterator_category = std::bidirectional_iterator_tag;

        constexpr Iterator() noexcept :
            impl_{}
        {
        }

        explicit Iterator(ExportDir const* export_dir, WORD index) :
            index_(index), export_dir_(export_dir)
        {
            impl_ = std::make_shared<Impl>(
                value_type{ export_dir, static_cast<WORD>(index_) });
        }

        explicit Iterator(ExportDir const* export_dir) :
            Iterator(export_dir, 0)
        {
        }

        reference operator*() const noexcept {
            return *impl_->export_;
        }

        pointer operator->() const noexcept {
            return &*impl_->export_;
        }

        Iterator& operator++() {
            index_++;
            if (index_ > export_dir_->number_of_functions() - 1 || index_ < 0)
                impl_.reset();
            else
                impl_->export_.emplace(value_type{ export_dir_, static_cast<WORD>(index_) });
            return *this;
        }

        Iterator operator++(int) {
            Iterator const iter{ *this };
            ++*this;
            return iter;
        }

        Iterator& operator--() {
            index_--;
            if (index_ > export_dir_->number_of_functions() - 1 || index_ < 0)
                impl_.reset();
            else
                impl_->export_.emplace(value_type{ export_dir_, static_cast<WORD>(index_) });
            return *this;
        }

        Iterator operator--(int) {
            Iterator const iter{ *this };
            --this;
            return iter;
        }

        bool operator==(Iterator const& other) const noexcept {
            return impl_ == other.impl_;
        }

        bool operator!=(Iterator const& other) const noexcept {
            return !(*this == other);
        }

    private:
        uint32_t index_;
        ExportDir const* export_dir_;
        struct Impl {
            explicit Impl(value_type const& exp) noexcept :
                export_(exp)
            {}
            std::optional<value_type> export_;
        };
        std::shared_ptr<Impl> impl_;
    };
    ExportDir() = default;
    explicit ExportDir(PVOID base);
    std::string module_name() const;
    DWORD ordinal_base() const;
    DWORD number_of_functions() const;
    DWORD number_of_names() const;
    PDWORD export_function() const;
    PDWORD export_names() const;
    PWORD export_name_ordinals() const;
    using iterator = Iterator<Function>;
    using const_iterator = Iterator<Function const>;
    iterator begin() {
        return iterator{ this };
    }
    const_iterator begin() const {
        return const_iterator{ this };
    }
    const_iterator cbegin() const {
        return const_iterator{ this };
    }
    iterator end() noexcept {
        return iterator{};
    }
    const_iterator end() const noexcept {
        return const_iterator{};
    }
    const_iterator cend() const noexcept {
        return const_iterator{};
    }
};