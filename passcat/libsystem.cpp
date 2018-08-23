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

#include <ShlObj.h>

HRESULT libsystem::get_roaming_path(PWSTR* path) {
	HRESULT appdata = NULL;
	return SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, path);
}

std::wstring libsystem::get_filezilla_path(void) {
	PWSTR roaming[MAX_PATH] = { 0 };
	libsystem::get_roaming_path(roaming);
	std::wstring filezilla_path(*roaming);
	return filezilla_path + L"\\FileZilla";
}
