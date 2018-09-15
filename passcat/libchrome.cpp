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

#include "libchrome.h"
#include "libsystem.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "sqlite3.h"

#include <iostream>
#include <algorithm>
#include <fstream>

#pragma comment (lib, "Shlwapi.lib")
#include <Shlwapi.h>

using namespace rapidjson;

static int _callback(void *NotUsed, int argc, char **argv, char **azColName) {
	return 0;
}

static void _print_passwords(std::wstring filename, std::wstring folder, std::string sqlQuery) {
	WCHAR tempfile[MAX_PATH] = { 0 };
	int rc;
	char *zErrMsg = 0;
	sqlite3 *db;
	char **results = NULL;
	int rows, columns;
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	sqlite3_blob *blob;
	void *block = 0;

	std::wstring path = libsystem::get_chrome_path(folder);
	if (!libsystem::generate_temp_filename(L"psc", tempfile)) {
		return;
	}

	if (!CopyFileW(filename.c_str(), tempfile, FALSE)) {
		return;
	}

	std::wstring tt(tempfile);
	if ((rc = sqlite3_open(std::string(tt.begin(), tt.end()).c_str(), &db))) {
		sqlite3_close(db);
		return;
	}

	if ((rc = sqlite3_get_table(db, sqlQuery.c_str(), &results, &rows, &columns, &zErrMsg)) != SQLITE_OK) {
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return;
	}
	else {
		for (int rowCtr = 1; rowCtr <= rows; ++rowCtr) {
			int cellPosition = (rowCtr * columns);
			std::cout << "URL: " << results[cellPosition] << std::endl;
			cellPosition = (rowCtr * columns) + 1;
			std::cout << "Username: " << results[cellPosition] << std::endl;
			cellPosition = (rowCtr * columns) + 2;
			sqlite3_free_table(results);

			if ((rc = sqlite3_blob_open(db, "main", "logins", "password_value", rowCtr, 0, &blob)) != SQLITE_OK) {
				sqlite3_close(db);
				return;
			}

			int len = 0;
			if ((len = sqlite3_blob_bytes(blob)) <= 0) {
				sqlite3_close(db);
				return;
			}

			if ((block = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len)) == NULL) {
				sqlite3_blob_close(blob);
				sqlite3_close(db);
				return;
			}

			if ((rc = sqlite3_blob_read(blob, block, len, 0)) != SQLITE_OK) {
				HeapFree(GetProcessHeap(), 0, block);
				sqlite3_blob_close(blob);
				sqlite3_close(db);
				return;
			}

			sqlite3_blob_close(blob);

			DataIn.cbData = len;
			DataIn.pbData = (BYTE *)block;

			if (CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut)) {
				DataOut.pbData[DataOut.cbData] = '\0';
				std::cout << "Password: " << DataOut.pbData << std::endl;
			}
		}

		if (rows > 0) {
			std::cout << std::endl;
		}
	}

	HeapFree(GetProcessHeap(), 0, block);
	sqlite3_close(db);
	DeleteFileW(tempfile);
}

static void _handle_profile(std::wstring pattern, std::wstring folder, std::wstring searchpath, std::string sqlQuery) {
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW ffd;

	if ((hFind = FindFirstFileW(searchpath.c_str(), &ffd)) == INVALID_HANDLE_VALUE) {
		return;
	}

	do {
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}
		else {
			std::wstring filename(ffd.cFileName);
			std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
			if (filename.find(pattern) != std::wstring::npos) {
				_print_passwords(folder + L"\\" + ffd.cFileName, folder, sqlQuery);
			}
		}
	} while (FindNextFileW(hFind, &ffd) != 0);

	FindClose(hFind);
}

void libchrome::print_chrome_passwords(std::wstring path, std::wstring pattern, std::wstring config, std::string sqlQuery) {
	std::wstring localstate = path + L"\\" + config;

	if (!PathFileExistsW(localstate.c_str())) {
		return;
	}

	std::ifstream ifs(localstate);
	std::string content((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));

	Document d;
	d.Parse(content.c_str());

	if (d.HasMember("profile") && d["profile"].HasMember("info_cache")) {
		if (d["profile"]["info_cache"].IsObject()) {
			for (Value::ConstMemberIterator itr = d["profile"]["info_cache"].MemberBegin();
				itr != d["profile"]["info_cache"].MemberEnd(); ++itr) {

				std::string temp(itr->name.GetString());
				std::wstring profilePath = path + L"\\" + std::wstring(temp.begin(), temp.end());
				std::wstring searchProfilePath = path + L"\\" + std::wstring(temp.begin(), temp.end()) + L"\\*";

				_handle_profile(pattern, profilePath, searchProfilePath, sqlQuery);
			}
		}
	}
	else {
		_handle_profile(pattern, path, path + L"\\*", sqlQuery);
	}
}
