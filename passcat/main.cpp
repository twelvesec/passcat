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
using namespace std;
#include "libpasscat.h"
#include "config.h"

#define VERSION "1.2.1"

int main(int argc, char *argv[])
{
	std::cout << std::endl;
	std::cout << std::endl <<
		R"(___________              .__                _________              )" << std::endl <<
		R"(\__    ___/_  _  __ ____ |  |___  __ ____  /   _____/ ____   ____  )" << std::endl <<
		R"(  |    |  \ \/ \/ // __ \|  |\  \/ // __ \ \_____  \_/ __ \_/ ___\ )" << std::endl <<
		R"(  |    |   \     /\  ___/|  |_\   /\  ___/ /        \  ___/\  \___ )" << std::endl <<
		R"(  |____|    \/\_/  \___  >____/\_/  \___  >_______  /\___  >\___  >)" << std::endl <<
		R"(                       \/               \/        \/     \/     \/ )" << std::endl <<
		std::endl;
	std::cout << "----------------------------------------------------------------" << std::endl;
	std::cout << "  PassCat v." << VERSION << " - Passwords Recovery Tool" << std::endl;
	std::cout << "  PassCat is an open source tool licensed under GPLv3." << std::endl;
	std::cout << "  Written by : @maldevel" << std::endl;
	std::cout << "  https ://www.twelvesec.com/" << std::endl;
	std::cout << "  Please visit https://github.com/twelvesec/passcat for more.." << std::endl;
	std::cout << "----------------------------------------------------------------" << std::endl << std::endl;

	libpasscat::init();

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


	std::cout << "------------------------------------" << std::endl;
	std::cout << "  Thunderbird Credentials" << std::endl;
	std::cout << "------------------------------------" << std::endl << std::endl;
	libpasscat::cat_thunderbird_passwords();
	std::cout << "-------------------------------------------" << std::endl << std::endl;

	libpasscat::finalize();

	return 0;
}
