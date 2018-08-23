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


#include "libxml.h"

#include <Windows.h>
#include <tchar.h>
#include <iostream>

#import <msxml6.dll>rename_namespace(_T("MSXML"))

#pragma comment (lib, "Crypt32.lib")
#include <Wincrypt.h>

bool libxml::initialized = false;

void libxml::init(void) {
	CoInitialize(NULL);
	initialized = true;
}

void libxml::finalize(void) {
	if (!initialized) return;

	CoUninitialize();
	initialized = false;
}

void libxml::dump_xml_content(std::wstring filename) {
	if (!initialized) return;

	MSXML::IXMLDOMDocument2Ptr xmlDoc;

	try {
		HRESULT hr = xmlDoc.CreateInstance(__uuidof(MSXML::DOMDocument60));

		if (FAILED(hr)) {
			CoUninitialize();
			return;
		}

		if (xmlDoc->load(_variant_t(filename.c_str())) != VARIANT_TRUE) {
			std::wcout << "Unable to load " << filename << std::endl;
		}
		else {
			BSTR xmlData = xmlDoc->xml.copy();
			std::wcout << xmlData << std::endl;
		}
	}
	catch (_com_error &e) {
		std::cout << e.ErrorMessage() << std::endl;
		xmlDoc = NULL;
	}
}

void libxml::select_by_xpath(std::wstring filename, std::wstring XPATH) {
	if (!initialized) return;

	MSXML::IXMLDOMDocument2Ptr xmlDoc;

	try {
		HRESULT hr = xmlDoc.CreateInstance(__uuidof(MSXML::DOMDocument60));

		if (FAILED(hr)) {
			CoUninitialize();
			return;
		}

		if (xmlDoc->load(_variant_t(filename.c_str())) != VARIANT_TRUE) {
			std::wcout << "Unable to load " << filename << std::endl;
		}
		else {
			MSXML::IXMLDOMNodeListPtr list = xmlDoc->selectNodes(_bstr_t(XPATH.c_str()));

			for (long i = 0; i != list->length; ++i) {
				std::wcout << "Host: " << list->item[i]->selectSingleNode("Host")->text << std::endl;
				std::wcout << "Port: " << list->item[i]->selectSingleNode("Port")->text << std::endl;
				std::wcout << "Username: " << list->item[i]->selectSingleNode("User")->text << std::endl;

				// TODO: base64 decode passwords
				BYTE* decoded = 0;
				DWORD decodedLen = 0;

				if (!CryptStringToBinaryW(list->item[i]->selectSingleNode("Pass")->text, 0, CRYPT_STRING_BASE64, NULL, &decodedLen, NULL, NULL)) {
					std::wcout << std::endl;
					continue;
				}

				decoded = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (decodedLen + 1) * sizeof(BYTE));
				if (decoded == NULL) {
					std::wcout << std::endl;
					continue;
				}

				if (!CryptStringToBinaryW(list->item[i]->selectSingleNode("Pass")->text, 0, CRYPT_STRING_BASE64, decoded, &decodedLen, NULL, NULL)) {
					std::wcout << std::endl;
					HeapFree(GetProcessHeap(), 0, decoded);
					continue;
				}

				std::cout << "Password: " << decoded << std::endl;
				std::wcout << std::endl;
				HeapFree(GetProcessHeap(), 0, decoded);
			}
		}
	}
	catch (_com_error &e) {
		std::cout << e.ErrorMessage() << std::endl;
		xmlDoc = NULL;
	}
}
