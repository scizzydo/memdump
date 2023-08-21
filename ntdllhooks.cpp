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

#include "ntdllhooks.h"

#include <format>
#include <iostream>
#include <tchar.h>

#include "logging.hpp"
#include "hooker.h"

// Macros for shorting all the writing needed to create the hook stuffs
#define CONSTRUCT(ret, convention, name, ...) \
	inline ret(convention* pfn##name)(__VA_ARGS__) = nullptr; \
	inline ret(convention* o##name)(__VA_ARGS__) = nullptr;

#define CREATE_HOOK(ret, convention, name, ...) \
	CONSTRUCT(ret, convention, name, __VA_ARGS__) \
	static ret convention name##Hook(__VA_ARGS__)

#define CONSTRUCT_NT(name, ...) \
	CONSTRUCT(NTSTATUS, WINAPI, name, __VA_ARGS__)
#define CREATE_NT_HOOK(name, ...) \
	CONSTRUCT_NT(name, __VA_ARGS__) \
	static NTSTATUS NTAPI name##Hook(__VA_ARGS__)

#define SEC_NO_CHANGE 0x00400000

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

HANDLE hSection;
/*
* Following function hooks are in place to allow writing to the section in the event
* of it being mapped to prevent changes. Idea to implement from the link below.
* For more details see: https://www.unknowncheats.me/forum/3121774-post8.html
*/
CREATE_NT_HOOK(NtCreateSection,
	PHANDLE			   SectionHandle,
	ACCESS_MASK		   DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER	   MaximumSize,
	ULONG			   SectionPageProtection,
	ULONG			   AllocationAttributes,
	HANDLE			   FileHandle) {
	if (!hSection) {
		SectionPageProtection = (AllocationAttributes & SEC_IMAGE) != 0 || FileHandle == nullptr || SectionPageProtection == PAGE_EXECUTE_READWRITE
			? PAGE_EXECUTE_READWRITE
			: PAGE_EXECUTE_WRITECOPY;
		logging::info("NtCreateSection - Set SectionPageProtection to {}",
			(SectionPageProtection == PAGE_EXECUTE_WRITECOPY ? "PAGE_EXECUTE_WRITECOPY" : "PAGE_EXECUTE_READWRITE"));
	}
	if (DesiredAccess != SECTION_ALL_ACCESS) {
		DesiredAccess = SECTION_ALL_ACCESS;
	}
	if (AllocationAttributes & SEC_NO_CHANGE) {
		logging::info("NtCreateSection - Page Protection: {:#x} - Allocation Attributes: {:#x}",
			SectionPageProtection, AllocationAttributes);
		logging::info("NtCreateSection - Removed SEC_NO_CHANGE from call");
		AllocationAttributes &= ~SEC_NO_CHANGE;
	}
	auto result = oNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
	if (NT_SUCCESS(result))
		if (!hSection) hSection = *SectionHandle;
	return result;
}

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation,
	SectionRelocationInformation,
	MaxSectionInfoClass
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;

typedef struct _SECTION_BASIC_INFORMATION {
	PVOID                   SectionBase;
	ULONG                   SectionAttributes;
	LARGE_INTEGER           SectionSize;
} SECTION_BASIC_INFORMATION, * PSECTION_BASIC_INFORMATION;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID                   EntryPoint;
	ULONG                   StackZeroBits;
	ULONG                   StackReserved;
	ULONG                   StackCommit;
	ULONG                   ImageSubsystem;
	WORD                    SubSystemVersionLow;
	WORD                    SubSystemVersionHigh;
	ULONG                   Unknown1;
	ULONG                   ImageCharacteristics;
	ULONG                   ImageMachineType;
	ULONG                   Unknown2[3];
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

NTSTATUS(NTAPI* NtQuerySection)(
	HANDLE SectionHandle,
	SECTION_INFORMATION_CLASS InformationClass,
	PVOID InformationBuffer,
	ULONG InformationBufferSize,
	PULONG ResultLength) = nullptr;

CREATE_NT_HOOK(NtMapViewOfSection,
	HANDLE		   SectionHandle,
	HANDLE		   ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR	   ZeroBits,
	SIZE_T		   CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T		   ViewSize,
	DWORD		   InheritDisposition,
	ULONG		   AllocationType,
	ULONG		   Win32Protect) {
	if (*BaseAddress)
		logging::info("NtMapViewOfSection: Called on base {} with 0x{:X} ({:x} bytes)",
			*BaseAddress, Win32Protect, *ViewSize);
	if (AllocationType & SEC_NO_CHANGE) {
		logging::info("NtMapViewOfSection: Removed SEC_NO_CHANGE from call");
		AllocationType &= ~SEC_NO_CHANGE;
	}
	if (reinterpret_cast<PVOID>(GetModuleHandle(NULL)) == *BaseAddress) {
		SECTION_BASIC_INFORMATION sbi{};
		if (NT_SUCCESS(NtQuerySection(SectionHandle, SectionBasicInformation, &sbi, sizeof(sbi), 0))) {
			bool readwrite = (sbi.SectionAttributes & SEC_COMMIT) != 0;
			bool secimage = (sbi.SectionAttributes & SEC_IMAGE) != 0;
			logging::info("NtMapViewOfSection: Set to {} as section is SEC_COMMIT (SEC_IMAGE: {})",
				(readwrite ? "PAGE_EXECUTE_WRITECOPY" : "PAGE_EXECUTE_READWRITE"), 
				(secimage ? "true" : "false"));
			Win32Protect = (readwrite ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE_READWRITE);
		}
		auto result = oNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
		return result;
	}
	return oNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}

void setup_hooks() {
#define HOOK_MODULE_FN(hmod, name) \
	{ \
		auto pfn = GetProcAddress(hmod, #name); \
		if (pfn) { \
			pfn##name = reinterpret_cast<decltype(pfn##name)>(pfn); \
			auto hook = create_hook(pfn, &name##Hook, reinterpret_cast<LPVOID*>(&o##name)); \
			if (!hook.enable()) { \
				logging::error("Failed to hook {} - {:X}", #name, GetLastError()); \
			} \
			else { \
				logging::success("{} hooked", #name); }; \
		} else { \
			logging::error("Failed to find {}", #name);\
		} \
	}
	auto ntdll = GetModuleHandle(_T("ntdll.dll"));
	if (!ntdll) {
		logging::error("Unable to obtain ntdll.dll handle");
		return;
	}
	NtQuerySection = reinterpret_cast<decltype(NtQuerySection)>(
		GetProcAddress(ntdll, "NtQuerySection"));
	HOOK_MODULE_FN(ntdll, NtCreateSection);
	HOOK_MODULE_FN(ntdll, NtMapViewOfSection);
#undef HOOK_MODULE_FN
}