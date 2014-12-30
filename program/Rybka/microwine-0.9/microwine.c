#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif
#include "microwine.h"

char *mybase, *patch_code_segment;
void *IMAGE_BASE;
void (*entry_point)(void) = NULL;

void thunk()
{
	printf("Error: Unknown WinAPI called\n");
	exit(1);
}

extern void GetProcessHeap();
extern void GetVersion();
extern void GetVersionExA();
extern void HeapCreate();
extern void HeapFree();
extern void HeapAlloc();
extern void LoadLibraryA();
extern void GetProcAddress();
extern void GetModuleHandleA();
extern void GetModuleHandleW();
extern void HeapSetInformation();
extern void FlsGetValue();
extern void FlsSetValue();
extern void FlsAlloc();
extern void EnterCriticalSection();
extern void LeaveCriticalSection();
extern void InitializeCriticalSection();
extern void InitializeCriticalSectionAndSpinCount();
extern void GetStartupInfoA();
extern void GetStartupInfoW();
extern void GetSystemTimeAsFileTime();
extern void GetCurrentProcessId();
extern void GetCurrentThreadId();
extern void GetTickCount();
extern void QueryPerformanceCounter();
extern void GetStdHandle();
extern void GetFileType();
extern void SetHandleCount();
extern void GetCommandLineA();
extern void GetEnvironmentStringsW();
extern void WideCharToMultiByte();
extern void FreeEnvironmentStringsW();
extern void GetEnvironmentStrings();
extern void FreeEnvironmentStringsA();
extern void GetLastError();
extern void SetLastError();
extern void GetACP();
extern void GetCPInfo();
extern void IsValidCodePage();
extern void GetModuleFileNameA();
extern void SetUnhandledExceptionFilter();
extern void HeapSize();
extern void CreateFileA();
extern void ReadFile();
extern void WriteFile();
extern void WriteFileEx();
extern void GetSystemInfo();
extern void CreateFileMappingA();
extern void OpenFileMappingA();
extern void MapViewOfFile();
extern void UnmapViewOfFile();
extern void CreatePipe();
extern void GetCurrentProcess();
extern void DuplicateHandle();
extern void CloseHandle();
extern void CreateProcessA();
extern void Sleep();
extern void GetConsoleMode();
extern void SetConsoleMode();
extern void FlushConsoleInputBuffer();
extern void GetNumberOfConsoleInputEvents();
extern void SetPriorityClass();
extern void GetLogicalDrives();
extern void SetFilePointer();
extern void FlushFileBuffers();
extern void ExitProcess();
extern void VirtualQuery();
extern void EncodePointer();
extern void DecodePointer();
extern void FindFirstFileA();
extern void GetTimeZoneInformation();
extern void RegOpenKeyExA();
extern void GlobalMemoryStatusEx();
extern void GetPriorityClass();

int local_exe;
char *argv0, *exe_file;
extern char cmdline[512], fixup_segment_code[4096];
extern unsigned num_cpus;
extern int alloc_shm[32];

#define PATCH_FUNC(x) else if (strcmp(name, #x) == 0) { /* printf("patching 0x%x from 0x%x to %s\n", offset, *ptr, #x); */ *ptr = (long)x; }

#ifdef __APPLE__
const void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
	int i;
	for (i = 0; i < haystacklen - needlelen; ++i) {
		if (memcmp(haystack + i, needle, needlelen) == 0) {
			return haystack + i;
		}
	}
	return NULL;
}
#endif

void fixup_code(char *base, unsigned length)
{
	// 65 4c 8b 1c 25 10 00     mov    %gs:0x10,%r11
	unsigned char *ptr = (unsigned char *)memmem(base, length, "\x65\x4c\x8b\x1c\x25\x10\x00\x00\x00", 9);
	if (ptr != NULL) {
		ptr[0] = ptr[1] = ptr[2] = ptr[3] = ptr[4] = ptr[5] = ptr[6] = ptr[7] = ptr[8] = 0x90;   // nop
	}

	// c1 e0 03        shl    $0x3,%eax
	// 45 8d 41 04     lea    0x4(%r9),%r8d
	// 48 8d 4a ff     lea    -0x1(%rdx),%rcx
	// 89 44 24 20     mov    %eax,0x20(%rsp)
	ptr = (unsigned char *)memmem(base, length, "\xc1\xe0\x03\x45\x8d\x41\x04\x48\x8d\x4a\xff\x89\x44\x24\x20", 15);
	if (ptr != NULL) {
		// callq  0x300000
		unsigned relative_addr = (unsigned)((unsigned char*)0x300000 - ptr - 5);
		//printf("Patching up: %x\n", relative_addr);
		ptr[0] = 0xe8;
		ptr[1] = (unsigned char)( relative_addr        & 0xff);
		ptr[2] = (unsigned char)((relative_addr >>  8) & 0xff);
		ptr[3] = (unsigned char)((relative_addr >> 16) & 0xff);
		ptr[4] = (unsigned char)((relative_addr >> 24) & 0xff);
		ptr[5] = ptr[6] = ptr[7] = ptr[8] = ptr[9] = ptr[10] = ptr[11] = ptr[12] = ptr[13] = ptr[14] = 0x90;   // nop
	}
}

void patch_iat(char *name, long offset)
{
	long *ptr = (long *)(mybase + offset);
	if (0) {
	}
	PATCH_FUNC(HeapFree)
	PATCH_FUNC(HeapAlloc)
	PATCH_FUNC(LoadLibraryA)
	PATCH_FUNC(GetProcAddress)
	PATCH_FUNC(GetModuleHandleA)
	PATCH_FUNC(GetModuleHandleW)
	PATCH_FUNC(EnterCriticalSection)
	PATCH_FUNC(LeaveCriticalSection)
	PATCH_FUNC(GetVersion)
	PATCH_FUNC(GetVersionExA)
	PATCH_FUNC(GetProcessHeap)
	PATCH_FUNC(HeapSetInformation)
	PATCH_FUNC(HeapCreate)
	PATCH_FUNC(FlsGetValue)
	PATCH_FUNC(FlsSetValue)
	PATCH_FUNC(FlsAlloc)
	PATCH_FUNC(GetStartupInfoA)
	PATCH_FUNC(GetStartupInfoW)
	PATCH_FUNC(InitializeCriticalSection)
	PATCH_FUNC(InitializeCriticalSectionAndSpinCount)
	PATCH_FUNC(GetSystemTimeAsFileTime)
	PATCH_FUNC(GetCurrentProcessId)
	PATCH_FUNC(GetCurrentThreadId)
	PATCH_FUNC(GetTickCount)
	PATCH_FUNC(QueryPerformanceCounter)
	PATCH_FUNC(GetStdHandle)
	PATCH_FUNC(GetFileType)
	PATCH_FUNC(SetHandleCount)
	PATCH_FUNC(GetCommandLineA)
	PATCH_FUNC(GetEnvironmentStringsW)
	PATCH_FUNC(WideCharToMultiByte)
	PATCH_FUNC(FreeEnvironmentStringsW)
	PATCH_FUNC(GetEnvironmentStrings)
	PATCH_FUNC(FreeEnvironmentStringsA)
	PATCH_FUNC(GetLastError)
	PATCH_FUNC(SetLastError)
	PATCH_FUNC(GetACP)
	PATCH_FUNC(GetCPInfo)
	PATCH_FUNC(IsValidCodePage)
	PATCH_FUNC(GetModuleFileNameA)
	PATCH_FUNC(SetUnhandledExceptionFilter)
	PATCH_FUNC(HeapSize)
	PATCH_FUNC(CreateFileA)
	PATCH_FUNC(ReadFile)
	PATCH_FUNC(WriteFile)
	PATCH_FUNC(WriteFileEx)
	PATCH_FUNC(GetSystemInfo)
	PATCH_FUNC(CreateFileMappingA)
	PATCH_FUNC(OpenFileMappingA)
	PATCH_FUNC(MapViewOfFile)
	PATCH_FUNC(UnmapViewOfFile)
	PATCH_FUNC(CreatePipe)
	PATCH_FUNC(GetCurrentProcess)
	PATCH_FUNC(DuplicateHandle)
	PATCH_FUNC(CloseHandle)
	PATCH_FUNC(CreateProcessA)
	PATCH_FUNC(Sleep)
	PATCH_FUNC(GetConsoleMode)
	PATCH_FUNC(SetConsoleMode)
	PATCH_FUNC(FlushConsoleInputBuffer)
	PATCH_FUNC(GetNumberOfConsoleInputEvents)
	PATCH_FUNC(SetPriorityClass)
	PATCH_FUNC(GetLogicalDrives)
	PATCH_FUNC(SetFilePointer)
	PATCH_FUNC(FlushFileBuffers)
	PATCH_FUNC(ExitProcess)
	PATCH_FUNC(VirtualQuery)
	PATCH_FUNC(EncodePointer)
	PATCH_FUNC(DecodePointer)
	PATCH_FUNC(FindFirstFileA)
	PATCH_FUNC(GetTimeZoneInformation)
	PATCH_FUNC(RegOpenKeyExA)
	PATCH_FUNC(GlobalMemoryStatusEx)
	PATCH_FUNC(GetPriorityClass)
	else {
		//printf("Warning: No patch for '%s' [offset=%lx]\n", name, offset);
		*ptr = (long)thunk;
	}
}

void abrupt_exit(int signum)
{
	int i;
	
	// clean up the allocated shm segments, then die
	for (i = 0; i < 32; ++i) {
		if (alloc_shm[i] != 0) {
			shmctl(alloc_shm[i], IPC_RMID, 0);
		}
	}

	signal(signum, SIG_DFL);
	raise(signum);
}

void decode_header(unsigned char *base)
{
	IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
	IMAGE_NT_HEADERS64 *nthdr = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
	IMAGE_SECTION_HEADER *sections;
	IMAGE_DATA_DIRECTORY *dir_imp, *dir_iat;
	int i;

	if (nthdr->FileHeader.Machine != 0x8664) {
		printf("no amd64 executable\n");
		exit(1);
	}

	//printf("Expected image base: 0x%x\n", nthdr->OptionalHeader.ImageBase);
	//printf("Relative address of entry point: 0x%x\n", nthdr->OptionalHeader.AddressOfEntryPoint);

	IMAGE_BASE = (void *)nthdr->OptionalHeader.ImageBase;
	sections = (IMAGE_SECTION_HEADER *)((char *)(&nthdr->OptionalHeader) + nthdr->FileHeader.SizeOfOptionalHeader);
	//printf("First section in RAM at %p\n", sections);

	// "map" in all sections
	for (i = 0; i < nthdr->FileHeader.NumberOfSections; ++i) {
#if 0
		printf("Mapping up section: %s (address=0x%x, real_address=0x%x, fileptr=0x%x, size=0x%x, relocs=%u)\n", sections[i].Name,
			nthdr->OptionalHeader.ImageBase + sections[i].VirtualAddress,
			mybase + sections[i].VirtualAddress,
			sections[i].PointerToRawData, sections[i].SizeOfRawData,
			sections[i].NumberOfRelocations);
#endif
		memcpy(mybase + sections[i].VirtualAddress, base + sections[i].PointerToRawData,
			sections[i].SizeOfRawData);

		if (strcmp((char *)sections[i].Name, ".text") == 0) {
			fixup_code(mybase + sections[i].VirtualAddress, sections[i].SizeOfRawData);
		}
	}

	// fix up some imports
	dir_imp = &nthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	dir_iat = &nthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

#if 0
	printf("imports at 0x%x, iat at 0x%x\n",
		nthdr->OptionalHeader.ImageBase + dir_imp->VirtualAddress,
		nthdr->OptionalHeader.ImageBase + dir_iat->VirtualAddress);
#endif

	for (i = 0; i < dir_imp->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR); ++i) {
		IMAGE_IMPORT_DESCRIPTOR *import =
			(IMAGE_IMPORT_DESCRIPTOR *)(mybase + dir_imp->VirtualAddress + i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
		IMAGE_THUNK_DATA64 *thunk;
		//long *iat = (long *)(mybase + import->FirstThunk);
		long iat = import->FirstThunk;

		if (import->u.Characteristics == 0)
			break;

		thunk = (IMAGE_THUNK_DATA64 *)(mybase + import->u.OriginalFirstThunk);
		/* printf("import dll name 0x%x (%s), rva to thunk=0x%x\n", import->Name, mybase + import->Name,
			import->FirstThunk); */

		while (thunk->u1.Ordinal) {
			IMAGE_IMPORT_BY_NAME *iibn = (IMAGE_IMPORT_BY_NAME *)(mybase + thunk->u1.AddressOfData);
//			printf("  import func name %s, iat entry = 0x%x\n", iibn->Name, *iat);

			//patch_iat(iibn->Name, *iat);
			patch_iat((char *)iibn->Name, iat);

			++thunk;
			iat += 8;
		}
	}

	// compute the entry point
	entry_point = (void (*)(void))(mybase + nthdr->OptionalHeader.AddressOfEntryPoint);
}

unsigned get_num_cpus(void)
{
#ifdef __APPLE__
	int mib[2], maxproc;
	size_t len;
	mib[0] = CTL_HW;
	mib[1] = HW_AVAILCPU;
	len = sizeof(maxproc);
	sysctl(mib, 2, &maxproc, &len, NULL, 0);
	return maxproc;
#else
	char buf[512];
	unsigned num_cpus = 0;

	FILE *cpuinfo = fopen("/proc/cpuinfo", "r");
	if (cpuinfo == NULL) {
		perror("/proc/cpuinfo");
		exit(1);
	}

	while (!feof(cpuinfo)) {
		if (fgets(buf, 512, cpuinfo) == NULL)
			break;

		if (strncmp(buf, "processor\t:", 11) == 0) {
			++num_cpus;
		}
	}

	fclose(cpuinfo);
	return num_cpus;
#endif
}
	
void build_cmdline(int argc, char **argv)
{
	int i = (local_exe ? 0 : 1);
	const char *exename_ptr = strchr(argv[i], '/');
	if (exename_ptr == NULL) {
		exename_ptr = argv[i];
	} else {
		++exename_ptr;
	}

	if (strlen(exename_ptr) < 4 || strcasecmp(exename_ptr + strlen(exename_ptr) - 4, ".exe") != 0) {
		sprintf(cmdline, "\"c:\\%s.exe\"", exename_ptr);
	} else {
		sprintf(cmdline, "\"c:\\%s\"", exename_ptr);
	}
	++i;

	for (; i < argc; ++i) {
		strcat(cmdline, " ");
		strcat(cmdline, argv[i]);
	}
}

void __attribute__((noreturn)) usage()
{
	fprintf(stderr, "Usage: ./microwine RYBKA-EXECUTABLE [arguments]\n");
	exit(1);
}

void start_program()
{
	//entry_point = (mybase + ENTRYPOINT_RVA);
	entry_point();
}

int find_local_exe(const char *self_exe, int *fd, int *size, int *offset)
{
	unsigned char *mem, *ptr, *image_base;

	/*
	 * We might have the required executable tacked onto our end.
	 * Detecting this reliably is sort of icky, but we can hack around
	 * it by looking for the infamous DOS stub. It's slightly tricky,
	 * though; we wouldn't want to find our _own_ string in the executable,
	 * so we obfuscate it a bit.
	 */
	char search[] = "tHIS PROGRAM CANNOT BE RUN IN dos MODE";
	int i;

	for (i = 0; i < sizeof(search) - 1; ++i) {
		if (search[i] != ' ') {
			search[i] ^= ('A' ^ 'a');
		}
	}

	*fd = open(self_exe, O_RDONLY);
	if (*fd == -1) {
		perror(self_exe);
		exit(1);
	}

	*size = lseek(*fd, 0, SEEK_END);
	mem = (unsigned char *)malloc(*size);
	lseek(*fd, 0, SEEK_SET);
	if (read(*fd, mem, *size) < *size) {
		perror("read");
		exit(1);
	}

	ptr = (unsigned char *)memmem(mem, *size, search, sizeof(search) - 1);
	if (ptr == NULL) {
		/* Not found. */
		return 0;
	}

	/* Now search backwards until we find the MZ header. */
	image_base = ptr;
	while (image_base >= mem && ptr - image_base < 512) {
		if (memcmp(image_base, "MZ", 2) == 0) {
			break;
		}
		--image_base;
	}

	/* Check that we really found MZ at most 512 bytes before the stub. */
	if (memcmp(image_base, "MZ", 2) != 0) {
		fprintf(stderr, "Broken executable tucked onto the end. Giving up.\n");
		exit(1);
	}

	*offset = image_base - mem;
	free(mem);
	return 1;
}

int main(int argc, char **argv)
{
	int fd, size, offset;
	unsigned char *base;

	local_exe = find_local_exe(argv[0], &fd, &size, &offset);
	if (!local_exe) {
		if (argc == 1) {
			usage();
		}
		exe_file = argv[1];
		fd = open(argv[1], O_RDONLY);
		if (fd == -1) {
			perror(argv[1]);
			exit(1);
		}
		size = lseek(fd, 0, SEEK_END);
		offset = 0;
	}

#ifdef __APPLE__
	// the linker has already made sure these point to usable places
	mybase = (void*)0x400000;
	patch_code_segment = (void*)0x300000;
#else
	// allocate 32MB, in which we will "map" up everything
	//mybase = (unsigned char *)malloc(32 * 1048576);
	mybase = mmap((void *)0x400000, 32 * 1048576, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
	if (mybase == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	// an extra page at a strategic place to patch our own code into
	patch_code_segment = mmap((void *)0x300000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
	if (patch_code_segment == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
#endif
	memcpy(patch_code_segment, fixup_segment_code, 4096);
	
	// initialize some variables we'll need
	argv0 = argv[0];
	num_cpus = get_num_cpus();
	build_cmdline(argc, argv);

	//base = mmap(IMAGE_BASE + 0x100000000, EXE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED, fd, 0);
	base = mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (base == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	decode_header(base + offset);
	munmap(base, size);
	close(fd);

	// set up panic handlers to avoid leaking shmem on abrupt exit
	signal(SIGINT, abrupt_exit);	
	signal(SIGHUP, abrupt_exit);	
	signal(SIGTERM, abrupt_exit);	
	signal(SIGSEGV, abrupt_exit);	

	start_program();
	return 0;
}

unsigned CreateProcessA_cthunk(char *cmd, LPSTARTUPINFO si, LPPROCESS_INFORMATION pi)
{
	char *cl;
	char *args[32];
	int i;
	pid_t pid;

	// Make sure we don't get any zombie processes.
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;

	pid = fork();
	
	switch (pid) {
	case -1:
		perror("fork()");
		exit(1);
	case 0: /* child */
		break;
	default: /* parent */
		pi->hProcess = pi->hThread = (HANDLE)(long)pid;
		pi->dwProcessId = pi->dwThreadId = pid;
		return 1;
	}

	if (si != NULL && ((si->dwFlags & STARTF_USESTDHANDLES) != 0)) {
		if (si->hStdInput != NULL) {
			dup2((long)si->hStdInput, 0);
		}
		if (si->hStdOutput != NULL) {
			dup2((long)si->hStdInput, 1);
		}
		if (si->hStdError != NULL) {
			dup2((long)si->hStdInput, 2);
		}
	}

	// split the command line (sort of ad-hoc, but should work)
	cl = cmd;
	args[0] = argv0;

	i = 1;
	{
		int in_quote = 0;
		char *ptr = cl;
		for ( ;; ) {
			if (*ptr == 0 || (*ptr == ' ' && !in_quote)) {
				// end of argument (or so we hope)
				args[i] = malloc(ptr - cl + 1);
				memcpy(args[i], cl, ptr - cl);
				args[i][ptr - cl] = 0;

				// hack for quotes
				if (*cl == '"') {
					args[i][ptr - cl - 1] = 0;
					++args[i];
				}

				++i;

				cl = ptr;
				if (*cl == 0) {
					break;
				}
				++cl;
			} else if (*ptr == '"') {
				in_quote = !in_quote;
			}
			++ptr;
		}
	}
	args[i] = NULL;

	if (local_exe) {
		args[1] = args[0];
		if (execvp(argv0, args + 1) == -1) {
			perror(argv0);
			exit(1);
		}
	} else {
		args[1] = exe_file;
		if (execvp(argv0, args) == -1) {
			perror(argv0);
			exit(1);
		}
	}
	return 0;
}

void warn_shm_failed_cthunk(long size)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "Shared memory allocation of %ld bytes failed; the program will\n", size);
	fprintf(stderr, "probably crash very soon. (shmget: %s)\n", strerror(errno));
	fprintf(stderr, "\n");
#ifdef __APPLE__
	fprintf(stderr, "Usually, this is the sign of too little shared memory allocated\n");
	fprintf(stderr, "on the system. Try editing /etc/sysctl.conf and change the kern.sysv.shmmax\n");
	fprintf(stderr, "value to %ld, then reboot. (You may also need to adjust\n", size+262144);
	fprintf(stderr, "kern.sysv.shmall to %ld or higher.)\n", (size+524288+sysconf(_SC_PAGESIZE)-1)/sysconf(_SC_PAGESIZE));
#else
	fprintf(stderr, "Usually, this is the sign of too little shared memory allocated\n");
	fprintf(stderr, "on the system. Try the following command as root and see if it\n");
	fprintf(stderr, "helps:\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  echo %ld > /proc/sys/kernel/shmmax\n", size+262144);
#endif
	fprintf(stderr, "\n");
}
