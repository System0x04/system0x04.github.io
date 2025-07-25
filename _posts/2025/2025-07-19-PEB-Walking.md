---
title: "PEB Walking: Figure out DLLs export symbols."
date: 2025-07-16 15:45:30 +0200
categories: [Windows internals]
tags: [PEB Walking, Maldev, Windows, User-Mode]     # TAG names should always be lowercase
image: assets/PEBWalking/wallhaven-je53mp.png
---
## **PEB**

The Process Environment Block (PEB) is a data structure related to each process in user-mode. It holds a huge amount of information, including in-memory loaded modules (DLL/EXE), <a href="https://getinternalsinfo.io/sysinternals/Thread/" target="_blank">`Threads`</a>, 
information about the image loader (Known internally as <a href="https://getinternalsinfo.io/sysinternals/Image%20loader/" target="_blank">`Ldr`</a>), 
and parameters passed by the user, etc. Each process owns it's own PEB and lives in the `User-Mode` virtual address (VA) space of a process. The OS would use this information and data structures for internal purposes.


![img-description](/assets/PEBWalking/PEB_base_address.png)
_Notepad instance of the PEB base address Process Hacker 2_

Within the PEB, there is an Ldr member that points to a `PEB_LDR_DATA` structure, and its duty is to load modules into memory
{% highlight CPP %}
typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
{% endhighlight %}
_https://ntdoc.m417z.com/peb_ldr_data_

![img_description](assets/PEBWalking/!peb.png)
_!peb Command in Windbg_

If we want to know which functions are exported by a PE file (DLL/EXE), the first thing we need to do is figure out the module base address (e.g., ntdll.dll, KERNEL32.DLL, etc.). In WinDbg, we can use the `lm` command to seek all loaded modules in the process virtual address space. 


![img_description](assets/PEBWalking/lm.PNG)
_lm Command in Windbg_

## **Export Table**

Now, we know a PE loads modules into memory. It's time to seek all export functions that might be in a DLL, if there are any.
The export functions are in the Export Table of any DLL. Frequently, PE file loads modules into their virtual address (VA) space to import functions that are in this DLL. 

![img_description](assets/PEBWalking/Export_Directory.png)
_Screenshot of export fucntions in PE viewer_

In the above screenshot, I'm using an ntdll file as an example. At the time of writing this post, there are 2,438 entries.
The export table is a data structure `_IMAGE_EXPORT_DIRECTORY`, and it's found in the first array member of `Data Directory`, that is, 0 member. The Data Directory it's an array data structure `_IMAGE_DATA_DIRECTORY`  and has 16 members.

If we parse the PE layout, we can see that the export table is in the`Optional Header` structure. The Optional Header is in one of the PE headers, in this case, `NT Header`. NT Header and `PE header` are the same.


![img_description](assets/PEBWalking/IMAGE_DATA_DIRECTORY.png)
_Data Directory array: 0 is Export Directory_

To resolve the export table's location, the first step is to obtain its `RVA` from the data directory and add it to the module's base address. Although this is trivial in WinDbg or with third-party tools, the process differs when implementing it programmatically

![img_description](assets/PEBWalking/IMAGE_EXPORT_DIRECTORY.png)
__IMAGE_EXPORT_DIRECTORY members_


To programmatically obtain the RVA of a PE (DLL/EXE) file's export table, the first thing we must do is search for the `e_lfanew` member in the `DOS header`. This header is a `_IMAGE_DOS_HEADER` structure type. The e_lfanew member has the file offset of the `NT header`.

{% highlight cpp %}
//0x40 bytes (sizeof)
struct _IMAGE_DOS_HEADER
{
    USHORT e_magic;                                                         //0x0
    USHORT e_cblp;                                                          //0x2
    USHORT e_cp;                                                            //0x4
    USHORT e_crlc;                                                          //0x6
    USHORT e_cparhdr;                                                       //0x8
    USHORT e_minalloc;                                                      //0xa
    USHORT e_maxalloc;                                                      //0xc
    USHORT e_ss;                                                            //0xe
    USHORT e_sp;                                                            //0x10
    USHORT e_csum;                                                          //0x12
    USHORT e_ip;                                                            //0x14
    USHORT e_cs;                                                            //0x16
    USHORT e_lfarlc;                                                        //0x18
    USHORT e_ovno;                                                          //0x1a
    USHORT e_res[4];                                                        //0x1c
    USHORT e_oemid;                                                         //0x24
    USHORT e_oeminfo;                                                       //0x26
    USHORT e_res2[10];                                                      //0x28
    LONG e_lfanew;                                                          //0x3c
}; 
{% endhighlight %}

_https://www.vergiliusproject.com/kernels/x86/windows-8/rtm/_IMAGE_DOS_HEADER_

![Desktop View](assets/PEBWalking/DOS_Header.png){: width="700" height="400" }
_Dos Header members_

In the DOS header, we add the offset to the module's base address (e.g., ntdll.dll, KERNEL32.DLL, etc.) to reach the NT header, which is a data structure of type `IMAGE_NT_HEADERS`. For now, the member we're interested in is `OptionalHeader`. OptionalHeader is another data structure of type `IMAGE_OPTIONAL_HEADER`.

![img_description](assets/PEBWalking/OptionalHeader.png)

In `IMAGE_OPTIONAL_HEADER64` there are 30 members and the one we are interested in is the data directory, which is an array of structures. It has 16 members, and the first member points to the module's export table.

{%highlight CPP%}
typedef struct _IMAGE_OPTIONAL_HEADER64 {
 WORD        Magic;
 BYTE        MajorLinkerVersion;
 BYTE        MinorLinkerVersion;
 DWORD       SizeOfCode;
 DWORD       SizeOfInitializedData;
 DWORD       SizeOfUninitializedData;
 DWORD       AddressOfEntryPoint;
 DWORD       BaseOfCode;
 ULONGLONG   ImageBase;
 DWORD       SectionAlignment;
 DWORD       FileAlignment;
 WORD        MajorOperatingSystemVersion;
 WORD        MinorOperatingSystemVersion;
 WORD        MajorImageVersion;
 WORD        MinorImageVersion;
 WORD        MajorSubsystemVersion;
 WORD        MinorSubsystemVersion;
 DWORD       Win32VersionValue;
 DWORD       SizeOfImage;
 DWORD       SizeOfHeaders;
 DWORD       CheckSum;
 WORD        Subsystem;
 WORD        DllCharacteristics;
 ULONGLONG   SizeOfStackReserve;
 ULONGLONG   SizeOfStackCommit;
 ULONGLONG   SizeOfHeapReserve;
 ULONGLONG   SizeOfHeapCommit;
 DWORD       LoaderFlags;
 DWORD       NumberOfRvaAndSizes;
 IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
{% endhighlight %}

_https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32#remarks_

As mentioned earlier, the data directory is an array of `IMAGE_DATA_DIRECTORY` structures, which contain 16 entries. The first entry (index 0) corresponds to the export table. Each member of this array holds the RVA of a critical structure, such as the export table or the import table.

![img_description](assets/PEBWalking/EntryDataDirectory.png)
_https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagedirectoryentrytodata_

Microsoft provides a set of macros for accessing directory data. In this case, I'll use `IMAGE_DIRECTORY_ENTRY_EXPORT` to retrieve the RVA from the export table. I then add it to the module's base address.


{% highlight cpp %}
auto pImgExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pModule + pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
std::cout << "[+] EXPORT DIRECTORY:\t 0x" << pImgExportDir << "\n\n";

auto Symbols = reinterpret_cast<PDWORD>(pModule + pImgExportDir->AddressOfNames);
auto pAddNames = reinterpret_cast<PDWORD>(pModule + pImgExportDir->AddressOfFunctions);
auto NumberNames = pImgExportDir->NumberOfNames;
auto Ord = reinterpret_cast<PWORD>(pModule + pImgExportDir->AddressOfNameOrdinals);

for (DWORD i = 0; i <= NumberNames - 1; i++)
    std::wcout << "Name: " << (PCHAR)(pModule + Symbols[i]) << ":\t0x" << (pModule + pAddNames[i]) << "\tOrdinal: " << (WORD)Ord[i] << std::endl;
{% endhighlight %}

{% highlight cpp %}
 typedef struct _IMAGE_EXPORT_DIRECTORY {
     DWORD   Characteristics;
     DWORD   TimeDateStamp;
     WORD    MajorVersion;
     WORD    MinorVersion;
     DWORD   Name;
     DWORD   Base;
     DWORD   NumberOfFunctions;
     DWORD   NumberOfNames;
     DWORD   AddressOfFunctions;     // RVA from base of image
     DWORD   AddressOfNames;         // RVA from base of image
     DWORD   AddressOfNameOrdinals;  // RVA from base of image
 };
 {% endhighlight %}
 _https://ghidra.re/ghidra_docs/api/ghidra/app/util/bin/format/pe/ExportDataDirectory.html_

 In this context, the most important members for us are **AddressOfNames, AddressOfFunctions, NumberOfNames, AddressOfNameOrdinals**. All of these have their respective RVA `(Relative Virtual Address)`.

 - **NumberOfNames:** This is the total number of symbols exported by name in the PE file. It's important to note that not all symbols/functions have names.
 - **AddressOfFunctions:** It's the RVA that points to an array of module symbols.
 - **AddressOfNames:** Points to an array of symbols name into module.

![img_description](assets/PEBWalking/AddressOfNames.png)

 - **AddressOfNameOrdinals:** An array that holds the `ordinal` values corresponding to the symbol names listed in the AddressOfNames array.

![img_description](assets/PEBWalking/Ordinals.png)

So, the approach to get the symbols of some modules from the export table at runtime is the following:

- **Module base address:** Find out the module base address, for instance, ntdll.dll, KERNEL32.DLL, etc. You can make it, though PEB Walking or directly load the module with the `LoadLibrary` function in memory.
- **MS DOS header:** Get the member e_elfanew in the MS DOS header (IMAGE_DOS_HEADER). Recall that this member is the gate to NT header.
- **NT header:** The field `OptionalHeader` is a type struct IMAGE_OPTIONAL_HEADER, and it holds the data directory array. Remember that the first memeber in this array is the export directory. It has the RVA to the struct IMAGE_EXPORT_DIRECTORY.

![img_description](assets/PEBWalking/PEBWalking.PNG)

### **Full code** ###

{% highlight cpp %}
//  En este proyecto haremos un PEB walking  para enumerar los modulos cargados en el espacio de direciones virtuales del proceso.
//  Usare el metodo de lectura de memoria a traves un offset relativo para conseguir la direccion de PEB directamente
//  El PEB contiene informacion jugosa de un proceso en user-mode.
//  Enumeraremos las funciones de exportacion de una DLL consiguiendo el RVA del directorio de exportacion.

#include <phnt_windows.h>
#include <phnt.h>
#include <iostream>
#define PHNT_MODE PHNT_MODE_USER

//  Para conseguir la direccion de memoria del PEB podemos usar inline assembly para procesos de 32-bit
//  https://learn.microsoft.com/en-us/cpp/assembler/inline/inline-assembler?view=msvc-170

// Creare una pequeña funcion para convertir strings de tipo ancho de minusculas a mayusculas
// y asi poder hacer una comprabacion adecuada de strings sin problemas.

constexpr std::wstring ToUpperString(const std::wstring& str)
{
    std::wstring wstrUpperStr;
    for (int i = 0; i < str.length(); i++)
        wstrUpperStr.push_back( towupper(str[i]) );
    
    return wstrUpperStr.data();  
}


int wmain(int argc, const PWCHAR Module[])
{
    
    if (argc < 2)
    {
        std::cerr << "[-] Sorry, no module was provided!" << std::endl;
        return 1;
    }

    // Acceder a la direccion del PEB a traves de registro de segmento GS.
    auto pPeb = reinterpret_cast<PPEB>(__readgsqword(0x60)); // https://learn.microsoft.com/en-us/cpp/intrinsics/readgsbyte-readgsdword-readgsqword-readgsword?view=msvc-170
    auto Head = &pPeb->Ldr->InMemoryOrderModuleList;
    auto Current = Head->Flink;

    PLDR_DATA_TABLE_ENTRY   pEntry;
    PIMAGE_DOS_HEADER       pDosHeader;
    PIMAGE_NT_HEADERS64     pNtHeaders64;

    std::cout << "[*] Initializing PEB Walking!\n\n" ;

    while (Current != Head)
    {
        // Calcular el inicio del LDR_DATA_TABLE_ENTRY
        // la macro CONTAINING_RECORD calcula la direcion base de cualquier tipo de estructura determinada , asi como un campo dentro de ella.
        pEntry = CONTAINING_RECORD(Current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks); // https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-containing_record

        /*
            Iterar a traves del array de modulos cargados hasta encontrar ntdll.dll.
            Para tratar con strings:
                https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnlen-strnlen-s?view=msvc-170
                https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcmp-wcscmp-mbscmp?view=msvc-170       
        */

        if (_wcsicmp(ToUpperString(pEntry->BaseDllName.Buffer).data(), ToUpperString(Module[1]).data()) == 0)
        {
            // Usare reinterpret cast para convertir el tipo PVOID de DllBase a PBYTE y asi poder hacer operaciones aritmeticas byte a byte
            // sin necesidad de estar haciendo conversion de tipo explicita en varias ocaciones

            auto pModule = reinterpret_cast<PBYTE>(pEntry->DllBase);
            pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pModule); // accedemos al header MZ DOS de ntdll.dll para verificar que el PE sea correcto

            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                break;

            std::wcout << "[+] Module loaded:\t" << pEntry->BaseDllName.Buffer << std::endl;
            std::wcout << "[+] Base address:\t 0x" << pModule << std::endl;
            std::cout << "[+] Found the MZ DOS header:\t 0x" << std::hex << pDosHeader << std::endl;
            

            /*
                Accedemos al header PE de tipo IMAGE_NT_HEADERS64 tomando el offset del miembro e_lfanew
                y sumando la direccion base del archivo PE (ntdll.dll).
            */

            pNtHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(pModule + pDosHeader->e_lfanew);
            if (pNtHeaders64->Signature != IMAGE_NT_SIGNATURE)
                break;

            std::cout << "[+] NT header base address:\t 0x" << pNtHeaders64 << std::endl;
            std::cout << "[+] Found the NT header signature:\t 0x" << std::hex << pNtHeaders64->Signature << std::endl;

            // Ya que IMAGE_DATA_DIRECTORY es un array de 16 miembros, quiero acceder al primer elemento, es decir el indice 0.
            // Microsoft ofrece un set de macros para ello. Usare "IMAGE_DIRECTORY_ENTRY_EXPORT".

            auto pImgExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pModule + pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            std::cout << "[+] EXPORT DIRECTORY:\t 0x" << pImgExportDir << "\n\n";

            auto Symbols = reinterpret_cast<PDWORD>(pModule + pImgExportDir->AddressOfNames);
            auto pAddNames = reinterpret_cast<PDWORD>(pModule + pImgExportDir->AddressOfFunctions);
            auto NumberNames = pImgExportDir->NumberOfNames;
            auto Ord = reinterpret_cast<PWORD>(pModule + pImgExportDir->AddressOfNameOrdinals);

            for (DWORD i = 0; i <= NumberNames - 1; i++)
                std::wcout << "Name: " << (PCHAR)(pModule + Symbols[i]) << ":\t0x" << (pModule + pAddNames[i]) << "\tOrdinal: " << (WORD)Ord[i] << std::endl;
            
            return 0;
        }  
        // Avanzar al siguiente modulo
        Current = Current->Flink;
    }

    if (Current == Head)
    {
        std::wcerr << "[-] Module \"" << Module[1] << "\" was not loaded into process VA space or is incorrect." << std::endl;
        return 1;
    }
    
}
{% endhighlight %}

**References:**

- https://www.gbppr.net/cracking/iczelion/pe-tut7.html
- https://dev.to/wireless90/exploring-the-export-table-windows-pe-internals-4l47

