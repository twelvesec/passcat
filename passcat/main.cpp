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

#include <windows.h>
#include <iostream>

#include "libpasscat.h"
#include "config.h"

#define VERSION "1.0"

int main(int argc, char *argv[])
{
	std::cout << std::endl << "-------------------------------------------" << std::endl;
	std::cout << "  PassCat v." << VERSION << " - Passwords Recovery Tool" << std::endl;
	std::cout << "-------------------------------------------" << std::endl << std::endl;

	libpasscat::init(FIREFOX_DLL_NSS3, FIREFOX_DLL_MOZGLUE);

	std::cout << "-------------------------" << std::endl;
	std::cout << "  FileZilla Credentials" << std::endl;
	std::cout << "-------------------------" << std::endl << std::endl;
	libpasscat::cat_filezilla_passwords();
	std::cout << "-------------------------------------------" << std::endl << std::endl;


	std::cout << "-------------------------" << std::endl;
	std::cout << "  WiFi Credentials" << std::endl;
	std::cout << "-------------------------" << std::endl << std::endl;
	libpasscat::cat_wifi_passwords();
	std::cout << "-------------------------------------------" << std::endl << std::endl;


	std::cout << "-------------------------" << std::endl;
	std::cout << "  WinSCP Credentials" << std::endl;
	std::cout << "-------------------------" << std::endl << std::endl;
	libpasscat::cat_winscp_passwords();
	std::cout << "-------------------------------------------" << std::endl << std::endl;


	std::cout << "-------------------------" << std::endl;
	std::cout << "  Pidgin Credentials" << std::endl;
	std::cout << "-------------------------" << std::endl << std::endl;
	libpasscat::cat_pidgin_passwords();
	std::cout << "-------------------------------------------" << std::endl << std::endl;


	std::cout << "------------------------------------" << std::endl;
	std::cout << "  Credential Manager Credentials" << std::endl;
	std::cout << "------------------------------------" << std::endl << std::endl;
	libpasscat::cat_credmanager_passwords();
	std::cout << "-------------------------------------------" << std::endl << std::endl;


	std::cout << "------------------------------------" << std::endl;
	std::cout << "  Vault & IE Credentials" << std::endl;
	std::cout << "------------------------------------" << std::endl << std::endl;
	libpasscat::cat_vault_ie_passwords();
	std::cout << "-------------------------------------------" << std::endl << std::endl;


	std::cout << "------------------------------------" << std::endl;
	std::cout << "  Google Chrome Credentials" << std::endl;
	std::cout << "------------------------------------" << std::endl << std::endl;
	libpasscat::cat_chrome_passwords();
	std::cout << "-------------------------------------------" << std::endl << std::endl;


	std::cout << "------------------------------------" << std::endl;
	std::cout << "  Opera Credentials" << std::endl;
	std::cout << "------------------------------------" << std::endl << std::endl;
	libpasscat::cat_opera_passwords();
	std::cout << "-------------------------------------------" << std::endl << std::endl;


	std::cout << "------------------------------------" << std::endl;
	std::cout << "  Firefox Credentials" << std::endl;
	std::cout << "------------------------------------" << std::endl << std::endl;
	libpasscat::cat_mozilla_passwords();
	std::cout << "-------------------------------------------" << std::endl << std::endl;

	libpasscat::finalize();

	return 0;
}
