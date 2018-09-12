//PassCat - Passwords Recovery Tool
//This file is part of PassCat Project

//Written by : @maldevel
//Website : https ://www.twelvesec.com/
//GIT : https://github.com/twelvesec/passcat

//TwelveSec(@Twelvesec)

//This program is free software : you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program.If not, see < http://www.gnu.org/licenses/>.

//For more see the file 'LICENSE' for copying permission.


#include "libsystem.h"
#include "config.h"

#include <ShlObj.h>

#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef LONG KPRIORITY;

typedef struct _SYSTEM_PROCESS_INFORMATION_DETAILD
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION_DETAILD, *PSYSTEM_PROCESS_INFORMATION_DETAILD;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
	IN       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT   PVOID SystemInformation,
	IN       ULONG SystemInformationLength,
	OUT OPTIONAL  PULONG ReturnLength
	);


HRESULT libsystem::get_appdata_path(PWSTR* path) {
	HRESULT appdata = NULL;
	return SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, path);
}

HRESULT libsystem::get_localappdata_path(PWSTR* path) {
	HRESULT appdata = NULL;
	return SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, path);
}

std::wstring libsystem::get_filezilla_path(void) {
	PWSTR roaming[MAX_PATH] = { 0 };
	get_appdata_path(roaming);
	std::wstring filezilla_path(*roaming);
	return filezilla_path + FILEZILLA_FOLDER;
}

std::wstring libsystem::get_pidgin_path(void) {
	PWSTR roaming[MAX_PATH] = { 0 };
	get_appdata_path(roaming);
	std::wstring path(*roaming);
	return path + PIDGIN_FOLDER;
}

std::wstring libsystem::get_chrome_path(std::wstring folder) {
	PWSTR localappdata[MAX_PATH] = { 0 };
	get_localappdata_path(localappdata);
	std::wstring path(*localappdata);
	return path + folder;
}

std::wstring libsystem::get_opera_path(std::wstring folder) {
	PWSTR roaming[MAX_PATH] = { 0 };
	get_appdata_path(roaming);
	std::wstring path(*roaming);
	return path + folder;
}

BOOL libsystem::generate_temp_filename(LPCWSTR prefix, LPWSTR filename) {
	WCHAR temp[MAX_PATH] = { 0 };

	if (GetTempPathW(MAX_PATH, temp) == 0) {
		return FALSE;
	}

	if (GetTempFileNameW(temp, prefix, 0, filename) == 0) {
		return FALSE;
	}

	return TRUE;
}

BOOL libsystem::dump_to_file(LPCWSTR filename, LPWSTR data) {
	HANDLE hFile;
	DWORD bytesToWrite = (DWORD)wcslen(data) * sizeof(wchar_t);
	DWORD dwBytesWritten = 0;

	hFile = CreateFileW(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	if (!WriteFile(hFile, data, bytesToWrite, &dwBytesWritten, NULL)) {
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}

DWORD libsystem::GetProcessIdByProcessName(LPCWSTR pszProcessName) {

	ULONG bufferSize = 1024 * sizeof(SYSTEM_PROCESS_INFORMATION_DETAILD);
	PSYSTEM_PROCESS_INFORMATION_DETAILD pspid = NULL;
	HANDLE hHeap = GetProcessHeap();
	PBYTE pBuffer = NULL;
	ULONG ReturnLength;
	PFN_NT_QUERY_SYSTEM_INFORMATION pfnNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");
	NTSTATUS status;
	int uLen = lstrlenW(pszProcessName) * sizeof(WCHAR);

	__try {
		pBuffer = (PBYTE)HeapAlloc(hHeap, 0, bufferSize);
#pragma warning(disable: 4127)
		while (TRUE) {
#pragma warning(default: 4127)
			status = pfnNtQuerySystemInformation(SystemProcessInformation, (PVOID)pBuffer, bufferSize, &ReturnLength);
			if (status == STATUS_SUCCESS) {
				break;
			}
			else if (status != STATUS_INFO_LENGTH_MISMATCH) { // 0xC0000004L
				return 1;   // error
			}

			bufferSize *= 2;
			pBuffer = (PBYTE)HeapReAlloc(hHeap, 0, (PVOID)pBuffer, bufferSize);
		}

		for (pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD)pBuffer;;
			pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD)(pspid->NextEntryOffset + (PBYTE)pspid)) {

			if (pspid->ImageName.Length == uLen && lstrcmpiW(pspid->ImageName.Buffer, pszProcessName) == 0) {
				return (DWORD)pspid->UniqueProcessId;
			}

			if (pspid->NextEntryOffset == 0) {
				break;
			}
		}
	}
	__finally {
		HeapFree(hHeap, 0, pBuffer);
		pBuffer = NULL;
	}
	return 0;
}
