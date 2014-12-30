/* mostly copied from the WINE headers, which in turn I'd guess took them from MSDN */

#define DUMMYUNIONNAME u

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef void *HANDLE;
typedef unsigned long long ULONGLONG;
typedef char *LPSTR;

typedef struct _IMAGE_DOS_HEADER {
	WORD  e_magic;      /* 00: MZ Header signature */
	WORD  e_cblp;       /* 02: Bytes on last page of file */
	WORD  e_cp;         /* 04: Pages in file */
	WORD  e_crlc;       /* 06: Relocations */
	WORD  e_cparhdr;    /* 08: Size of header in paragraphs */
	WORD  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
	WORD  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
	WORD  e_ss;         /* 0e: Initial (relative) SS value */
	WORD  e_sp;         /* 10: Initial SP value */
	WORD  e_csum;       /* 12: Checksum */
	WORD  e_ip;         /* 14: Initial IP value */
	WORD  e_cs;         /* 16: Initial (relative) CS value */
	WORD  e_lfarlc;     /* 18: File address of relocation table */
	WORD  e_ovno;       /* 1a: Overlay number */
	WORD  e_res[4];     /* 1c: Reserved words */
	WORD  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
	WORD  e_oeminfo;    /* 26: OEM information; e_oemid specific */
	WORD  e_res2[10];   /* 28: Reserved words */
	DWORD e_lfanew;     /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD  Machine;
	WORD  NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD  SizeOfOptionalHeader;
	WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD  Magic; /* 0x20b */
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	ULONGLONG ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Win32VersionValue;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


#define IMAGE_DIRECTORY_ENTRY_EXPORT            0
#define IMAGE_DIRECTORY_ENTRY_IMPORT            1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE          2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION         3
#define IMAGE_DIRECTORY_ENTRY_SECURITY          4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC         5
#define IMAGE_DIRECTORY_ENTRY_DEBUG             6
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT         7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR         8   /* (MIPS GP) */
#define IMAGE_DIRECTORY_ENTRY_TLS               9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      11
#define IMAGE_DIRECTORY_ENTRY_IAT               12  /* Import Address Table */
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    14

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD   Characteristics; /* 0 for terminating null import descriptor  */
		DWORD   OriginalFirstThunk;     /* RVA to original unbound IAT */
	} DUMMYUNIONNAME;
	DWORD   TimeDateStamp;  /* 0 if not bound,
				 * -1 if bound, and real date\time stamp
				 *    in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
				 * (new BIND)
				 * otherwise date/time stamp of DLL bound to
				 * (Old BIND)
				 */
	DWORD   ForwarderChain; /* -1 if no forwarders */
	DWORD   Name;
	/* RVA to IAT (if bound this IAT has actual addresses) */
	DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA64 {
	union {
		ULONGLONG ForwarderString;
		ULONGLONG Function;
		ULONGLONG Ordinal;
		ULONGLONG AddressOfData;
	} u1;
} IMAGE_THUNK_DATA64,*PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD    Hint;
	BYTE    Name[1];
} IMAGE_IMPORT_BY_NAME,*PIMAGE_IMPORT_BY_NAME;

typedef struct _PROCESS_INFORMATION{
	HANDLE  hProcess;
	HANDLE  hThread;
	DWORD           dwProcessId;
	DWORD           dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

/* STARTUPINFO.dwFlags */
#define STARTF_USESHOWWINDOW    0x00000001
#define STARTF_USESIZE          0x00000002
#define STARTF_USEPOSITION      0x00000004
#define STARTF_USECOUNTCHARS    0x00000008
#define STARTF_USEFILLATTRIBUTE 0x00000010
#define STARTF_RUNFULLSCREEN    0x00000020
#define STARTF_FORCEONFEEDBACK  0x00000040
#define STARTF_FORCEOFFFEEDBACK 0x00000080
#define STARTF_USESTDHANDLES    0x00000100
#define STARTF_USEHOTKEY        0x00000200

typedef struct _STARTUPINFOA{
        DWORD cb;               /* 00: size of struct */
        LPSTR lpReserved;       /* 04: */
        LPSTR lpDesktop;        /* 08: */
        LPSTR lpTitle;          /* 0c: */
        DWORD dwX;              /* 10: */
        DWORD dwY;              /* 14: */
        DWORD dwXSize;          /* 18: */
        DWORD dwYSize;          /* 1c: */
        DWORD dwXCountChars;    /* 20: */
        DWORD dwYCountChars;    /* 24: */
        DWORD dwFillAttribute;  /* 28: */
        DWORD dwFlags;          /* 2c: */
        WORD wShowWindow;       /* 30: */
        WORD cbReserved2;       /* 32: */
        BYTE *lpReserved2;      /* 34: */
        HANDLE hStdInput;       /* 38: */
        HANDLE hStdOutput;      /* 3c: */
        HANDLE hStdError;       /* 40: */
} STARTUPINFO, *LPSTARTUPINFO;

