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

#pragma once

#include <string>
#include <tchar.h>
#import <msxml6.dll>rename_namespace(_T("MSXML"))

namespace libxml {
	extern bool initialized;
	void init(void);
	void dump_xml_content(std::wstring filename);
	MSXML::IXMLDOMNodeListPtr select_by_path(std::wstring filename, std::wstring XPATH);
	MSXML::IXMLDOMNodeListPtr select_by_path(LPWSTR data, std::wstring XPATH);
	void finalize(void);
}
