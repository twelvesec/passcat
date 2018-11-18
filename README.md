## PassCat

**Passwords Recovery Tool**

PassCat is an open source Windows native C/C++ application capable of retrieving the passwords stored locally on a computer.

*For a full list of our tools, please visit our website https://www.twelvesec.com/*

Written by:

* [maldevel](https://github.com/maldevel) ([twitter](https://twitter.com/maldevel))

---

### Dependencies

* Windows 10 x64
* Microsoft Visual C++ 2017 Redistributable (x64)

---

### Supported software

* FileZilla
* Windows Wireless Network
* WinSCP
* Pidgin
* Windows Credential Manager
* Vault Files
* Internet Explorer Browser
* Google Chrome Browser
* Opera Browser
* Firefox Browser
* Thunderbird Email Client (you have to build PassCat for Windows 10 x86. Keep in mind that using the x86 version you will not be able to retrieve Firefox passwords)

---

### Build Instructions

* Download Visual Studio 2017 Community Edition.
* Open solution file ("PassCat.sln").
* Choose "Release" option from the dropdown menu in the configuration manager and "x64" Platform.
* Select "Build" -> "Build Solution" from the menu or press the "F6" keyboard shortcut.
* Executable location: "C:\\[path]\[to]\passcat\x64\Release\PassCat.exe"

---

### Usage

* Some passwords such as WiFi credentials can only be retrieved by running PassCat as an administrator, so you have to open two command lines, one as an administrator and another one as a normal user.
* Copy the executable file to a more convenient location and change your current directory to this location.
* Open the "cmd.exe" window and change the current directory. e.g.:

```
cd "C:\[path]\[to]\passcat\x64\Release\"
```

* Execute PassCat

```
.\PassCat.exe
```

---

### Credits

* [sqlite-amalgamation](https://www.sqlite.org/download.html)
* [rapidjson](https://github.com/Tencent/rapidjson)
* [LaZagne](https://github.com/AlessandroZ/LaZagne)

---
