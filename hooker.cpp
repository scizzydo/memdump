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

#include "hooker.h"

#include <stdexcept>
#include <format>
#include <iostream>

extern "C" {
    #include "nmd/nmd_assembly.h"
}

PVOID create_tramp(PVOID address, PVOID target, size_t length) {
    uint8_t jump[] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    auto destination = VirtualAlloc(nullptr, sizeof(jump) + length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (destination) {
        *reinterpret_cast<PVOID*>(&jump[6]) = reinterpret_cast<PVOID>(
            reinterpret_cast<uintptr_t>(address) + length);
        memcpy(destination, address, length);
        memcpy(reinterpret_cast<PVOID>(
            reinterpret_cast<uintptr_t>(destination) +
            length), jump, sizeof(jump));
    }
    return destination;
}

Hook create_hook(PVOID addr, PVOID target, LPVOID* tramp) {
    Hook hook{.original = addr, .target = target };
    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(addr, &mbi, sizeof(mbi));
    auto const diff = reinterpret_cast<uintptr_t>(mbi.BaseAddress) -
        reinterpret_cast<uintptr_t>(addr);
    auto size = mbi.RegionSize - diff;
    auto instruction_length = nmd_x86_ldisasm(addr, size, static_cast<NMD_X86_MODE>(sizeof(void*)));
    while (instruction_length < 14)
        instruction_length += nmd_x86_ldisasm(reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(addr) + instruction_length), 
            size - instruction_length, static_cast<NMD_X86_MODE>(sizeof(void*)));
    hook.original_bytes.resize(instruction_length);
    memcpy(&hook.original_bytes[0], addr, instruction_length);
    if (tramp) {
        auto destination = create_tramp(addr, target, instruction_length);
        if (!destination)
            throw std::runtime_error(std::format("Failed to allocate memory! ({:X})", GetLastError()));
        hook.tramp = destination;
        *tramp = destination;
    }
    return hook;
}

bool Hook::enable() {
    uint8_t jump[] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    *reinterpret_cast<PVOID*>(&jump[6]) = target;
    DWORD old_protection = NULL;
    if (!VirtualProtect(original, original_bytes.size() + sizeof(jump), PAGE_EXECUTE_READWRITE, &old_protection))
        return false;
    memcpy(original, jump, sizeof(jump));
    for (auto i = sizeof(jump); i < original_bytes.size(); ++i)
        reinterpret_cast<uint8_t*>(original)[i] = 0x90;
    VirtualProtect(original, original_bytes.size() + sizeof(jump), old_protection, &old_protection);
    return true;
}

bool Hook::disable() {
    DWORD old_protection = NULL;
    if (!VirtualProtect(original, original_bytes.size(), PAGE_EXECUTE_READWRITE, &old_protection))
        return false;
    memcpy(original, &original_bytes[0], original_bytes.size());
    VirtualProtect(original, original_bytes.size(), old_protection, &old_protection);
    return true;
}