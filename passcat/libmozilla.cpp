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


#include <iostream>
#include <fstream>

#include "libmozilla.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#pragma comment (lib, "Shlwapi.lib")
#include <Shlwapi.h>

using namespace rapidjson;

typedef enum _SECStatus {
	SECWouldBlock = -2,
	SECFailure = -1,
	SECSuccess = 0
} SECStatus;

typedef enum {
	siBuffer,
	siClearDataBuffer,
	siCipherDataBuffer,
	siDERCertBuffer,
	siEncodedCertBuffer,
	siDERNameBuffer,
	siEncodedNameBuffer,
	siAsciiNameString,
	siAsciiString,
	siDEROID
} SECItemType;

struct SECItemStr {
	SECItemType type;
	unsigned char *data;
	unsigned int len;
};

typedef struct SECItemStr SECItem;
typedef unsigned int PRUint32;
typedef int PRBool;

typedef SECStatus(*NSS_InitFunc)(const char*);
typedef SECStatus(*NSS_ShutdownFunc)(void);
typedef void *(*PK11_GetInternalKeySlotFunc)(void);
typedef void(*PK11_FreeSlotFunc) (void*);
typedef SECStatus(*PK11_CheckUserPasswordFunc) (void*, char*);
typedef SECStatus(*PK11_AuthenticateFunc) (void*, int, void*);
typedef char*(*PL_Base64DecodeFunc)(const char *, PRUint32, char *);
typedef SECStatus(*PK11_SDRDecryptFunc) (SECItem*, SECItem*, void*);
typedef void(*SECITEM_ZfreeItemFunc)(SECItem *, PRBool);

NSS_InitFunc NSSInit;
NSS_ShutdownFunc NSSShutdown;
PK11_GetInternalKeySlotFunc PK11GetInternalKeySlot;
PK11_FreeSlotFunc PK11FreeSlot;
PK11_CheckUserPasswordFunc PK11CheckUserPassword;
PK11_AuthenticateFunc PK11Authenticate;
PL_Base64DecodeFunc PLBase64Decode;
PK11_SDRDecryptFunc PK11SDRDecrypt;
SECITEM_ZfreeItemFunc SECITEMZfreeItem;

bool libmozilla::initialized = false;
HMODULE libmozilla::hnss3Lib = false;
HMODULE libmozilla::hmozglueLib = false;

#define PR_TRUE  1
#define PR_FALSE 0

static void _handle_credentials(std::string hostname, std::string encUsername, std::string encPassword) {
	int len = 0;
	char *decoded;
	int adjust = 0;
	int decodeLen;
	SECItem request;
	SECItem reply;
	SECStatus status;
	char *plaintext;

	std::cout << "Hostname: " << hostname << std::endl;

	len = (unsigned int)strlen(encUsername.c_str());
	if (encUsername.c_str()[len - 1] == '=')
	{
		adjust++;
		if (encUsername.c_str()[len - 2] == '=')
			adjust++;
	}
	if ((decoded = (char *)PLBase64Decode(encUsername.c_str(), len, NULL)) == NULL) {
		return;
	}

	decodeLen = (len * 3) / 4 - adjust;
	request.data = (unsigned char *)decoded;
	request.len = decodeLen;
	reply.data = 0;
	reply.len = 0;

	if ((status = PK11SDRDecrypt(&request, &reply, NULL)) != SECSuccess) {
		return;
	}

	if ((plaintext = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, reply.len + 1)) == NULL) {
		SECITEMZfreeItem(&request, PR_FALSE);
		SECITEMZfreeItem(&reply, PR_FALSE);
		return;
	}

	strncpy_s(plaintext, reply.len + 1, (const char*)reply.data, reply.len);
	plaintext[reply.len] = '\0';

	std::cout << "Username: " << plaintext << std::endl;

	HeapFree(GetProcessHeap(), 0, plaintext);
	plaintext = NULL;
	SECITEMZfreeItem(&request, PR_FALSE);
	SECITEMZfreeItem(&reply, PR_FALSE);
	
	//***************

	adjust = 0;
	len = (unsigned int)strlen(encPassword.c_str());
	if (encPassword.c_str()[len - 1] == '=')
	{
		adjust++;
		if (encPassword.c_str()[len - 2] == '=')
			adjust++;
	}
	if ((decoded = (char *)PLBase64Decode(encPassword.c_str(), len, NULL)) == NULL) {
		return;
	}

	decodeLen = (len * 3) / 4 - adjust;

	request.data = (unsigned char *)decoded;
	request.len = decodeLen;
	reply.data = 0;
	reply.len = 0;

	if ((status = PK11SDRDecrypt(&request, &reply, NULL)) != SECSuccess) {
		return;
	}

	if ((plaintext = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, reply.len + 1)) == NULL) {
		SECITEMZfreeItem(&request, PR_FALSE);
		SECITEMZfreeItem(&reply, PR_FALSE);
		return;
	}

	strncpy_s(plaintext, reply.len + 1, (const char*)reply.data, reply.len);
	plaintext[reply.len] = '\0';

	std::cout << "Password: " << plaintext << std::endl;

	HeapFree(GetProcessHeap(), 0, plaintext);
	plaintext = NULL;
	SECITEMZfreeItem(&request, PR_FALSE);
	SECITEMZfreeItem(&reply, PR_FALSE);
}

static void _print_passwords(std::wstring profileFolder, std::wstring signons) {
	std::wstring path = L"sql:" + profileFolder;
	std::wstring signonsJson = profileFolder + L"\\" + signons;
	std::string fullPath(path.begin(), path.end());
	SECStatus result;
	void *slot;

	if (!PathFileExistsW(signonsJson.c_str())) {
		return;
	}

	if ((result = NSSInit(fullPath.c_str())) != SECSuccess) {
		return;
	}

	if ((slot = PK11GetInternalKeySlot()) == NULL) {
		NSSShutdown();
		return;
	}

	if ((result = PK11CheckUserPassword(slot, "")) != SECSuccess) {
		PK11FreeSlot(slot);
		NSSShutdown();
		return;
	}

	if ((result = PK11Authenticate(slot, TRUE, NULL)) != SECSuccess) {
		PK11FreeSlot(slot);
		NSSShutdown();
		return;
	}

	std::ifstream ifs(signonsJson);
	std::string content((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));

	Document d;
	d.Parse(content.c_str());

	if (d.HasMember("logins")) {
		if (d["logins"].IsArray()) {
			const Value& a = d["logins"].GetArray();
			for (SizeType i = 0; i < a.Size(); i++) {
				if (a[i].IsObject()) {

					std::string hostname;
					std::string encusername;
					std::string encpassword;

					for (Value::ConstMemberIterator itr = a[i].MemberBegin(); itr != a[i].MemberEnd(); ++itr) {
						if (itr->name != NULL) {
							std::string val(itr->name.GetString());

							if (val == "hostname") {
								if (itr->value != NULL) {
									hostname = itr->value.GetString();
								}
							}

							if (val == "encryptedUsername") {
								if (itr->value != NULL) {
									encusername = itr->value.GetString();
								}
							}

							if (val == "encryptedPassword") {
								if (itr->value != NULL) {
									encpassword = itr->value.GetString();
								}
							}
						}
					}

					_handle_credentials(hostname, encusername, encpassword);
					std::cout << std::endl;
				}
			}
		}
	}

	PK11FreeSlot(slot);
	NSSShutdown();
}

static void _handle_profiles(std::wstring folder, std::wstring searchpath, std::wstring signons) {
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW ffd;

	if ((hFind = FindFirstFileW(searchpath.c_str(), &ffd)) == INVALID_HANDLE_VALUE) {
		return;
	}

	do {
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			std::wstring profilePath(ffd.cFileName);
			if (profilePath == L"." || profilePath == L"..") {
				continue;
			}
			_print_passwords(folder + L"\\" + ffd.cFileName, signons);
		}
	} while (FindNextFileW(hFind, &ffd) != 0);

	FindClose(hFind);
}

void libmozilla::init(std::wstring nss3Dll, std::wstring mozglueDll) {
	if (initialized) return;

	if (!(hmozglueLib = LoadLibraryW(mozglueDll.c_str()))) {
		return;
	}

	if (!(hnss3Lib = LoadLibraryW(nss3Dll.c_str()))) {
		FreeLibrary(hmozglueLib);
		return;
	}

	NSSInit = (NSS_InitFunc)GetProcAddress(hnss3Lib, "NSS_Init");
	NSSShutdown = (NSS_ShutdownFunc)GetProcAddress(hnss3Lib, "NSS_Shutdown");
	PK11GetInternalKeySlot = (PK11_GetInternalKeySlotFunc)GetProcAddress(hnss3Lib, "PK11_GetInternalKeySlot");
	PK11FreeSlot = (PK11_FreeSlotFunc)GetProcAddress(hnss3Lib, "PK11_FreeSlot");
	PK11CheckUserPassword = (PK11_CheckUserPasswordFunc)GetProcAddress(hnss3Lib, "PK11_CheckUserPassword");
	PK11Authenticate = (PK11_AuthenticateFunc)GetProcAddress(hnss3Lib, "PK11_Authenticate");
	PLBase64Decode = (PL_Base64DecodeFunc)GetProcAddress(hnss3Lib, "PL_Base64Decode");
	PK11SDRDecrypt = (PK11_SDRDecryptFunc)GetProcAddress(hnss3Lib, "PK11SDR_Decrypt");
	SECITEMZfreeItem = (SECITEM_ZfreeItemFunc)GetProcAddress(hnss3Lib, "SECITEM_ZfreeItem");

	if (!NSSInit || !NSSShutdown || !PK11GetInternalKeySlot || !PK11FreeSlot || !PK11CheckUserPassword || !PK11Authenticate
		|| !PLBase64Decode || !PK11SDRDecrypt || !SECITEMZfreeItem) {
		FreeLibrary(hnss3Lib);
		FreeLibrary(hmozglueLib);
		return;
	}

	initialized = true;
}

void libmozilla::finalize(void) {
	if (!initialized) return;

	if (hnss3Lib) {
		FreeLibrary(hnss3Lib);
	}

	if (hmozglueLib) {
		FreeLibrary(hmozglueLib);
	}

	initialized = false;
}

void libmozilla::print_firefox_passwords(std::wstring path, std::wstring signons) {
	if (!initialized) return;

	if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
		return;
	}

	_handle_profiles(path, path + L"\\*", signons);
}
