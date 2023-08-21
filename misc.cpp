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

#include "misc.h"

#include <vector>
#include <tchar.h>

std::filesystem::path module_path(HMODULE hmod) {
    std::vector<TCHAR> buffer;
    DWORD copied = 0;
    do {
        buffer.resize(buffer.size() + MAX_PATH);
        copied = GetModuleFileName(hmod, &buffer[0], static_cast<DWORD>(buffer.size()));
    } while (copied >= static_cast<DWORD>(buffer.size()));
    buffer.resize(copied);
    return std::filesystem::path(buffer.begin(), buffer.end());
}

/*
* Function pulls from the file attributes to read either the ProductVersion or FileVersion.
* Some processes store their 'version' in either or. We first check ProductVersion to ensure
* it's not a version that contains any words, otherwise fall back to the FileVersion.
*/
std::string get_file_version(const std::filesystem::path& filepath) {
    DWORD verHandle = 0;
    uint32_t size = 0;
    LPVOID lpBuffer = NULL;
    auto verSize = GetFileVersionInfoSizeA(filepath.string().c_str(), &verHandle);
    std::string result;
    if (verSize) {
        auto verData = std::make_unique<uint8_t[]>(verSize);
        if (GetFileVersionInfo(filepath.native().c_str(), verHandle, verSize, verData.get())) {
            if (VerQueryValueA(verData.get(), "\\VarFileInfo\\Translation", &lpBuffer, &size)) {
                uint16_t* lpw = reinterpret_cast<uint16_t*>(lpBuffer);
                auto search_string = std::format("\\StringFileInfo\\{:04x}{:04x}\\ProductVersion", lpw[0], lpw[1]);
                if (VerQueryValueA(verData.get(), search_string.c_str(), &lpBuffer, &size)) {
                    std::string temp(reinterpret_cast<const char*>(lpBuffer));
                    auto it = std::find_if(temp.begin(), temp.end(), [](char const& c) {
                        return !(c == '.' || std::isdigit(c));
                        });
                    if (!temp.empty() && it == temp.end()) {
                        return temp;
                    }
                }
            }
            if (VerQueryValue(verData.get(), _T("\\"), &lpBuffer, &size)) {
                if (size) {
                    VS_FIXEDFILEINFO* verInfo = reinterpret_cast<VS_FIXEDFILEINFO*>(lpBuffer);
                    if (verInfo->dwSignature == 0xfeef04bd) {
                        return std::format("{:d}.{:d}.{:d}.{:d}",
                            (verInfo->dwFileVersionMS >> 16) & 0xffff,
                            (verInfo->dwFileVersionMS >> 0) & 0xffff,
                            (verInfo->dwFileVersionLS >> 16) & 0xffff,
                            (verInfo->dwFileVersionLS >> 0) & 0xffff);
                    }
                }
            }
        }
    }
    return result;
}

std::filesystem::path get_new_filename(const std::filesystem::path& path) {
    auto const dir = path.parent_path();
    auto const extension = path.extension();
    auto const stem = path.stem();
    auto const version = get_file_version(path);
    return dir / (stem.string() + "_" + version + extension.string());
}

std::string wstring_to_string(std::wstring const& str) {
    std::string result;
    auto sz = WideCharToMultiByte(CP_ACP, 0, &str[0], static_cast<int32_t>(str.size()), 0, 0, 0, 0);
    result = std::string(sz, 0);
    WideCharToMultiByte(CP_ACP, 0, &str[0], static_cast<int32_t>(str.size()), &result[0], sz, 0, 0);
    return result;
}