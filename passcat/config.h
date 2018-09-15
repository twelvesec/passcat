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

#define FILEZILLA_FILE_ONE L"recentservers.xml"
#define FILEZILLA_FILE_TWO L"sitemanager.xml"
#define FILEZILLA_XPATH_ONE L"//FileZilla3/RecentServers/Server"
#define FILEZILLA_XPATH_TWO L"//FileZilla3/Servers/Server"
#define FILEZILLA_FOLDER L"\\FileZilla"

#define WIFI_XPATH_ONE L"//pf:WLANProfile/pf:MSM/pf:security/pf:authEncryption"
#define WIFI_XPATH_TWO L"//pf:WLANProfile/pf:MSM/pf:security/pf:sharedKey"

#define WINSCP_REG_ONE L"Software\\Martin Prikryl\\WinSCP 2\\Configuration"
#define WINSCP_REG_TWO L"Software\\Martin Prikryl\\WinSCP 2\\Sessions"

#define PIDGIN_FILE L"accounts.xml"
#define PIDGIN_XPATH L"//account/account"
#define PIDGIN_FOLDER L"\\.purple"

#define CHROME_FILES_SEARCH L"login data"
#define CHROME_CONFIG_FILE L"Local State"
#define CHROME_FOLDER L"\\Google\\Chrome\\User Data"
#define CHROME_SQL_QUERY "SELECT action_url, username_value, password_value FROM logins"

#define OPERA_FILES_SEARCH L"login data"
#define OPERA_CONFIG_FILE L"Local State"
#define OPERA_FOLDER L"\\Opera Software\\Opera Stable"
#define OPERA_SQL_QUERY "SELECT action_url, username_value, password_value FROM logins"

#define FIREFOX_FILE L"logins.json"
#define FIREFOX_FOLDER L"\\Mozilla\\Firefox\\Profiles"
#define FIREFOX_DLL_NSS3 L"C:\\Program Files\\Mozilla Firefox\\nss3.dll"
#define FIREFOX_DLL_MOZGLUE L"C:\\Program Files\\Mozilla Firefox\\mozglue.dll"

#define THUNDERBIRD_FILE L"logins.json"
#define THUNDERBIRD_FOLDER L"\\Thunderbird\\Profiles"
#define THUNDERBIRD_DLL_NSS3 L"C:\\Program Files (x86)\\Mozilla Thunderbird\\nss3.dll"
#define THUNDERBIRD_DLL_MOZGLUE L"C:\\Program Files (x86)\\Mozilla Thunderbird\\mozglue.dll"
