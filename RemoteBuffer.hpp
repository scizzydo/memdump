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
#include <cstdint>

// Helper class to allow RAII to clean up our remote allocated buffers
class RemoteBuffer {
	HANDLE hProcess;
	PVOID buffer;
	bool persistant;
public:
	RemoteBuffer() :
		hProcess(INVALID_HANDLE_VALUE), buffer(nullptr), persistant(false)
	{}
	RemoteBuffer(HANDLE hProc) :
		RemoteBuffer(hProc, false)
	{}
	RemoteBuffer(HANDLE hProc, bool persist) :
		hProcess(hProc), buffer(nullptr), persistant(persist)
	{}
	RemoteBuffer(HANDLE hProc, SIZE_T dwSize, DWORD flProtect) :
		RemoteBuffer(hProc, nullptr, dwSize, flProtect, false)
	{}
	RemoteBuffer(HANDLE hProc, SIZE_T dwSize, DWORD flProtect, bool persist) :
		RemoteBuffer(hProc, nullptr, dwSize, flProtect, persist)
	{}
	RemoteBuffer(HANDLE hProc, LPVOID lpAddress, SIZE_T dwSize, DWORD flProtect) :
		RemoteBuffer(hProc, nullptr, dwSize, flProtect, false)
	{}
	RemoteBuffer(HANDLE hProc, LPVOID lpAddress, SIZE_T dwSize, DWORD flProtect, bool persist) :
		hProcess(hProc), persistant(persist)
	{
		allocate(lpAddress, dwSize, flProtect);
	}
	~RemoteBuffer() {
		if (buffer && !persistant) {
			free();
		}
	}
	void make_persistant(bool persist) {
		persistant = persist;
	}
	PVOID allocate(LPVOID lpAddress, SIZE_T dwSize, DWORD flProtect) {
		buffer = VirtualAllocEx(hProcess, lpAddress, dwSize, MEM_COMMIT | MEM_RESERVE, flProtect);
		return buffer;
	}
	BOOL free() {
		auto result = VirtualFreeEx(hProcess, buffer, 0, MEM_RELEASE);
		buffer = nullptr;
		return result;
	}
	operator uintptr_t() {
		return reinterpret_cast<uintptr_t>(buffer);
	}
	operator PVOID() {
		return buffer;
	}
	operator bool() {
		return buffer != nullptr;
	}
};