#ifdef __linux__
#define MANGLE(x) x
#define STRING(x) .string x
#define GLOBAL(x) x
#define PRE_LIBCALL
#define POST_LIBCALL
#endif
#ifdef __APPLE__
.cstring
#define MANGLE(x) _ ## x
#define STRING(x) .ascii x 
#define GLOBAL(x) MANGLE(x) (%rip)
.macro PRE_LIBCALL
mov %rsp,GLOBAL(real_rsp)
xchg %rsp,%rax
shr $$4,%rax
shl $$4,%rax
xchg %rsp,%rax
.endmacro
.macro POST_LIBCALL
mov GLOBAL(real_rsp),%rsp
.endmacro
.text
#endif

.globl	MANGLE(GetProcessHeap)
.globl	MANGLE(GetVersion)
.globl	MANGLE(GetVersionExA)
.globl	MANGLE(HeapCreate)
.globl	MANGLE(HeapFree)
.globl	MANGLE(HeapAlloc)
.globl	MANGLE(LoadLibraryA)
.globl	MANGLE(GetProcAddress)
.globl	MANGLE(GetModuleHandleA)
.globl	MANGLE(GetModuleHandleW)
.globl	MANGLE(HeapSetInformation)
.globl	MANGLE(FlsAlloc)
.globl	MANGLE(FlsGetValue)
.globl	MANGLE(FlsSetValue)
.globl	MANGLE(EnterCriticalSection)
.globl	MANGLE(LeaveCriticalSection)
.globl	MANGLE(InitializeCriticalSection)
.globl	MANGLE(InitializeCriticalSectionAndSpinCount)
.globl	MANGLE(GetStartupInfoA)
.globl	MANGLE(GetStartupInfoW)
.globl  MANGLE(GetSystemTimeAsFileTime)
.globl  MANGLE(GetCurrentProcessId)
.globl  MANGLE(GetCurrentThreadId)
.globl  MANGLE(GetTickCount)
.globl  MANGLE(QueryPerformanceCounter)
.globl  MANGLE(GetStdHandle)
.globl  MANGLE(GetFileType)
.globl  MANGLE(SetHandleCount)
.globl  MANGLE(GetCommandLineA)
.globl  MANGLE(GetEnvironmentStringsW)
.globl  MANGLE(WideCharToMultiByte)
.globl  MANGLE(FreeEnvironmentStringsW)
.globl  MANGLE(GetEnvironmentStrings)
.globl  MANGLE(FreeEnvironmentStringsA)
.globl  MANGLE(GetLastError)
.globl  MANGLE(SetLastError)
.globl  MANGLE(GetACP)
.globl  MANGLE(GetCPInfo)
.globl  MANGLE(IsValidCodePage)
.globl  MANGLE(GetModuleFileNameA)
.globl  MANGLE(SetUnhandledExceptionFilter)
.globl  MANGLE(HeapSize)
.globl  MANGLE(CreateFileA)
.globl  MANGLE(ReadFile)
.globl  MANGLE(GetSystemInfo)
.globl  MANGLE(CreateFileMappingA)
.globl  MANGLE(OpenFileMappingA)
.globl  MANGLE(MapViewOfFile)
.globl  MANGLE(UnmapViewOfFile)
.globl  MANGLE(CreatePipe)
.globl  MANGLE(GetCurrentProcess)
.globl  MANGLE(DuplicateHandle)
.globl  MANGLE(CloseHandle)
.globl  MANGLE(CreateProcessA)
.globl  MANGLE(Sleep)
.globl  MANGLE(GetConsoleMode)
.globl  MANGLE(SetConsoleMode)
.globl  MANGLE(FlushConsoleInputBuffer)
.globl  MANGLE(WriteFile)
.globl  MANGLE(WriteFileEx)
.globl  MANGLE(GetNumberOfConsoleInputEvents)
.globl  MANGLE(SetPriorityClass)
.globl  MANGLE(GetLogicalDrives)
.globl  MANGLE(SetFilePointer)
.globl  MANGLE(FlushFileBuffers)
.globl  MANGLE(ExitProcess)
.globl  MANGLE(VirtualQuery)
.globl  MANGLE(EncodePointer)
.globl  MANGLE(DecodePointer)
.globl  MANGLE(FindFirstFileA)
.globl  MANGLE(GetTimeZoneInformation)
.globl  MANGLE(RegOpenKeyExA)
.globl  MANGLE(GlobalMemoryStatusEx)
.globl  MANGLE(GetPriorityClass)

.globl  MANGLE(fib_value)
.globl  MANGLE(cmdline)
.globl  MANGLE(num_cpus)
.globl  MANGLE(alloc_shm)
.globl  MANGLE(fixup_segment_code)

MANGLE(newline): STRING("\n")
MANGLE(icsacs): STRING("InitializeCriticalSectionAndSpinCount")
MANGLE(ecs): STRING("EnterCriticalSection\n")
MANGLE(appname): STRING("\\\\?\\c:\\rybka\\Rybkav2.3.2a.mp.x64.exe")
MANGLE(env): STRING("TEST=foo\000\000")
MANGLE(envw): STRING("T\000E\000S\000T\000=\000f\000o\000o\000\000\000\000\000")


#ifdef __APPLE__
.section .bss, "b"
#else
.section .bss
#endif

MANGLE(fib_value):	.quad 0x0
MANGLE(last_err):	.quad 0x0
MANGLE(tmp):     	.quad 0x0, 0x0, 0x0
MANGLE(num_cpus):	.quad 0x0
#ifdef __APPLE__
MANGLE(real_rsp):	.quad 0x0
#endif
MANGLE(cmdline):	.fill 512,1,0
MANGLE(alloc_shm):	.fill 32*4,1,0
#ifdef __APPLE__
MANGLE(readfds):        .fill 128,1,0
MANGLE(timeout):        .fill 16,1,0
#endif
MANGLE(shmid_found):    .quad 0x0
MANGLE(shmid_ds):       .fill 112,1,0

#ifdef __APPLE__
.section .data, "dw"
#else
.section .data
#endif

#ifndef __APPLE__
MANGLE(pollfd):		STRING("\000\000\000\000\001\000\000\000")
#endif

#ifdef __APPLE__
.section .text, "rx"
#else
.section .text
#endif

MANGLE(GetProcessHeap):
	mov       $0xf00dbad, %eax 
	retq	

MANGLE(GetVersion):
	mov       $0x7a690105, %eax  # majorversion = 5, minorversion = 1, build = 31337
	retq

MANGLE(GetVersionExA):
	# stub
	mov       $5, %eax
	mov       %eax, 0x4(%rcx)    # dwMajorVersion = 5 (Windows XP, et al)

	mov       $1, %eax
	mov       %eax, 0x8(%rcx)    # dwMinorVersion = 1 (Windows XP)

	mov       $31337, %eax
	mov       %eax, 0xc(%rcx)    # dwBuildNumber = 31337
	
	mov       $2, %eax
	mov       %eax, 0x10(%rcx)   # dwPlatformId = VER_PLATFORM_WIN32_NT

	mov       $0x1, %eax
	retq

# HANDLE WINAPI HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
MANGLE(HeapCreate):
	mov       $0xf00df00d, %eax
	retq

# LPVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
MANGLE(HeapAlloc):
	# rcx = hHeap, rdx = dwFlags, r8 = dwBytes
	push      %rdx
	push      %rdi
	push      %rsi

	mov       %r8, %rdi
	mov       $0x1, %rsi
	PRE_LIBCALL
	call      MANGLE(calloc)
	POST_LIBCALL

	pop       %rsi
	pop       %rdi
	pop       %rdx
	retq

# BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
MANGLE(HeapFree):
	# rcx = hHeap, rdx = dwFlags, r8 = lpMem
	push      %rdx
	push      %rdi
	push      %rsi

	mov       %r8, %rdi
	PRE_LIBCALL
	call      MANGLE(free)
	POST_LIBCALL

	pop       %rsi
	pop       %rdi
	pop       %rdx
	mov	  $0x1, %eax
	retq

MANGLE(LoadLibraryA):
	# stub
	mov       $0xbadf00d, %rax
	ret

MANGLE(GetProcAddress):
	push      %rdi
	push      %rsi
	push      %rdx

	# see if it's the evil spinlock function
	mov       %rdx, %rdi
	lea       GLOBAL(icsacs), %rsi
	PRE_LIBCALL
	call      MANGLE(strcmp)
	POST_LIBCALL
	test      %eax, %eax
	jnz       .noticsacs

	# yes, it is
	lea       GLOBAL(InitializeCriticalSectionAndSpinCount), %eax
	jmp	  .epilogue

.noticsacs:
	# find the length of the argument
	#  mov       %rdx, %rdi         #buf
	#  call      strlen

	#  # output it
	#  mov       %rax, %rdx         # count
	#  mov       %rdi, %rsi         # buf
	#  mov       $0x1, %eax         # write syscall
	#  mov       $0x1, %rdi         # fd
	#  syscall

	#  # and attach a newline
	#  mov       $0x1, %eax         # write syscall
	#  mov       $0x1, %rdi         # fd
	#  lea       newline, %rsi      # buf
	#  mov       $0x1, %rdx         # count
	#  syscall


	# let's hope it's EncodePointer/DecodePointer
	#mov       $0xdeadbeef, %rax
	lea	  GLOBAL(EncodePointer), %rax
	
.epilogue:
	pop	  %rdx
	pop	  %rsi
	pop	  %rdi

	retq	

MANGLE(EncodePointer):
	mov       %rcx, %rax
	ret

MANGLE(DecodePointer):
	mov       %rcx, %rax
	retq

MANGLE(GetModuleHandleA):
	# used to load mscoree.dll, it seems
	mov       $0xbadf00d, %eax
	retq

MANGLE(GetModuleHandleW):
	# used to load mscoree.dll, it seems
	mov       $0xbadf00d, %eax
	retq

MANGLE(HeapSetInformation):
	mov       $0x1, %eax
	retq

MANGLE(FlsGetValue):
	#mov	  $0xc0ffee, %rax
	mov       GLOBAL(fib_value), %rax
	retq

MANGLE(FlsSetValue):
	#mov	  $0xc0ffee, %rax
	mov       %rdx, GLOBAL(fib_value)
	retq

MANGLE(FlsAlloc):
	mov       $0xf1baf1ba, %rax
	retq

MANGLE(EnterCriticalSection):
#	push    %rdx
#	push    %rdi
#	push    %rsi

#	mov     $0x1, %rdi
#	lea     ecs, %rsi
#	mov     $21, %rdx
#	call    write

#	pop     %rsi
#	pop     %rdi
#	pop     %rdx
	retq

MANGLE(LeaveCriticalSection):
	# stub
	retq

MANGLE(InitializeCriticalSectionAndSpinCount):
	mov	$0xc7171c41, %rax
	mov	%rax, (%rcx)
	mov	$0x555c7171c41, %rax
	mov	%rax, 24(%rcx)
	mov     $0x1, %rax
	retq

MANGLE(InitializeCriticalSection):
	mov     $0x1, %rax
	retq

MANGLE(GetStartupInfoA):
        push    %rdx

	mov     $84, %rdx     # sizeof(STARTUPINFOA)
.zeroa:
	movb    $0, (%rcx)
        inc     %rcx
        dec     %rdx
        jnz     .zeroa

        pop     %rdx
	mov     $0x1, %rax
	retq

MANGLE(GetStartupInfoW):
        push    %rdx

	mov     $84, %rdx     # sizeof(STARTUPINFOW)
.zerow:
	movb    $0, (%rcx)
        inc     %rcx
        dec     %rdx
        jnz     .zerow

        pop     %rdx
	mov     $0x1, %rax
	retq

MANGLE(GetSystemTimeAsFileTime):
	push    %rdx
	push    %rdi
	push    %rsi

	lea     GLOBAL(tmp), %rdi
	xor     %rsi, %rsi
	push    %rcx
	PRE_LIBCALL
	call    MANGLE(gettimeofday)
	POST_LIBCALL
	pop     %rcx
	
	# multiply tv_sec by a million and add tv_usec
	imul    $1000000, GLOBAL(tmp), %rax
#ifdef __APPLE__
	# year 2038 issue, blah blah
	add     GLOBAL(tmp+8), %eax
#else
	add     GLOBAL(tmp+8), %rax
#endif

	# add the difference between the epochs (1970 vs. 1601)
	mov     $11644477200000000, %rdx
	add     %rdx, %rax

	# multiply by 10 to get in units of 100ns
	lea     (%rax,%rax,4), %rax
	add     %rax, %rax
	mov     %rax, (%rcx)

	pop     %rsi
	pop     %rdi
	pop     %rdx
GetSystemTimeAsFileTime_end:
	retq

MANGLE(GetCurrentProcessId):
	push    %rdx
	push    %rdi
	push    %rsi

	PRE_LIBCALL
	call    MANGLE(getpid)
	POST_LIBCALL

	pop     %rsi
	pop     %rdi
	pop     %rdx
	retq

MANGLE(GetCurrentThreadId):
	push    %rdx
	push    %rdi
	push    %rsi

	PRE_LIBCALL
	call    MANGLE(getpid)
	POST_LIBCALL

	pop     %rsi
	pop     %rdi
	pop     %rdx
	retq

MANGLE(GetTickCount):
	push    %rdx
	push    %rdi
	push    %rsi

	lea     GLOBAL(tmp), %rdi
	xor     %rsi, %rsi
	PRE_LIBCALL
	call    MANGLE(gettimeofday)
	POST_LIBCALL
	
	# multiply tv_sec by a million and add tv_usec plus roundoff
	imul    $1000000, GLOBAL(tmp), %rax
#ifdef __APPLE__
	# year 2038 issue, blah blah
	add     GLOBAL(tmp+8), %eax
#else
	add     GLOBAL(tmp+8), %rax
#endif
	add     $500, %rax

	# now divide the whole thing by 1000 to get milliseconds
	xor     %rdx, %rdx
	mov     $1000, %rdi
	idiv    %rdi

	pop     %rsi
	pop     %rdi
	pop     %rdx
	retq

MANGLE(QueryPerformanceCounter):
	# stub
	mov    $0x87654321, %rax
	mov    %rax, (%rcx)
	mov    $1, %rax
	retq

MANGLE(GetStdHandle):
	mov    $0xc0501e, %rax
	retq

MANGLE(GetFileType):
	# mov    $0x2, %rax           # FILE_TYPE_CHAR
	mov    $0x1, %rax           # FILE_TYPE_DISK
	retq

MANGLE(SetHandleCount):
	# stub
	retq

MANGLE(GetCommandLineA):
	lea    GLOBAL(cmdline), %rax
	retq

MANGLE(GetEnvironmentStringsW):
	lea    GLOBAL(envw), %rax
	retq

MANGLE(WideCharToMultiByte):
	# stub
	mov    $10, %rax
	retq

MANGLE(FreeEnvironmentStringsW):
	# stub
	mov    $0x1, %rax
	retq

MANGLE(GetEnvironmentStrings):
	lea    GLOBAL(env), %rax
	retq

MANGLE(FreeEnvironmentStringsA):
	# stub
	mov    $0x1, %rax
	retq

MANGLE(GetLastError):
	mov    GLOBAL(last_err), %rax
	retq

MANGLE(SetLastError):
	mov    %rax, GLOBAL(last_err)
	retq

MANGLE(GetACP):
	mov    $0x08650865, %rax
	retq

MANGLE(GetCPInfo):
	# stub
	xor    %rax, %rax
	retq

MANGLE(IsValidCodePage):
	# stub
	mov    $0x1, %rax
	retq

MANGLE(GetModuleFileNameA):
	# stub
	push   %rdi
	push   %rsi
	push   %rdx
	
	lea    GLOBAL(appname), %rsi
	mov    %rdx, %rdi
	PRE_LIBCALL
	call   MANGLE(strcpy)
	POST_LIBCALL

	lea    GLOBAL(appname), %rdi
	PRE_LIBCALL
	call   MANGLE(strlen)
	POST_LIBCALL

	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(SetUnhandledExceptionFilter):
	# stub
	xor    %rax, %rax
	retq

MANGLE(HeapSize):
	# stub
	mov    $0x100, %rax
	retq

MANGLE(CreateFileA):
	push   %rdi
	push   %rsi
	push   %rdx

	# change all backslashes to forward-slashes
	mov    %rcx, %rdi
.loop:
	mov    (%rcx), %al
	cmp    $0x5c, %al    # backslash
	jne    .nobackslash
	mov    $0x2f, %al    # forward-slash
	mov    %al, (%rcx)  
.nobackslash:
	inc    %rcx
	test   %al, %al
	jnz    .loop

	xor    %rsi, %rsi
	mov    64(%rsp), %edx  # dwCreationDisposition
	cmp    $1, %edx       # CREATE_NEW
	je     .createnew
	cmp    $2, %edx       # CREATE_ALWAYS
	je     .createalways
	mov    $0x2, %rsi     # O_RDWR
 	jmp    .doopen
.createnew:
	mov    $0x42, %rsi    # O_RDWR | O_CREAT
	jmp    .doopen
.createalways:
	mov    $0xc2, %rsi    # O_RDWR | O_EXCL | O_CREAT
.doopen:
	mov    $0644, %rdx
	PRE_LIBCALL
	call   MANGLE(open)
	POST_LIBCALL

	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(ReadFile):
	push   %rdi
	push   %rsi
	push   %rdx

	# the console?
	xor    %rax, %rax
	cmp    $0xc0501e, %rcx
	cmove  %rax, %rcx

	mov    %rcx, %rdi    # fd
	mov    %rdx, %rsi    # buf
	mov    %r8, %rdx     # count
	PRE_LIBCALL
	call   MANGLE(read)
	POST_LIBCALL

	mov    %eax, (%r9)   # return value

	pop    %rdx
	pop    %rsi
	pop    %rdi

	mov    $0x1, %rax
	retq

MANGLE(WriteFile):
	push   %rdi
	push   %rsi
	push   %rdx

	# the console?
	mov    $0x1, %rax
	cmp    $0xc0501e, %rcx
	cmove  %rax, %rcx

	mov    %rcx, %rdi    # fd
	mov    %rdx, %rsi    # buf
	mov    %r8, %rdx     # count
	PRE_LIBCALL
	call   MANGLE(write)
	POST_LIBCALL

	mov    %rax, (%r9)   # return value

	pop    %rdx
	pop    %rsi
	pop    %rdi

	mov    $0x1, %rax
	retq

MANGLE(WriteFileEx):
	push   %rdi
	push   %rsi
	push   %rdx

	mov    %rcx, %rdi    # fd
	mov    %rdx, %rsi    # buf
	mov    %r8, %rdx     # count
	PRE_LIBCALL
	call   MANGLE(write)
	POST_LIBCALL

	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(GetSystemInfo):
	mov    $9, %ax          # PROCESSOR_ARCHITECTURE_AMD64
	mov    %eax, (%rcx)

	mov    $4096, %eax      # page size
	mov    %eax, 4(%rcx)

	# 8(%rcx): lpMinimumApplicationAddress
	# 16(%rcx): lpMaximumApplicationAddress

	mov    $1, %rax         # processor bit mask
	mov    %rax, 24(%rcx)

	mov    GLOBAL(num_cpus), %eax
	mov    %eax, 32(%rcx)

	mov    $8664, %eax      # amd64
	mov    %eax, 36(%rcx)

	retq

MANGLE(CreateFileMappingA):
	# create a new shm segment with hash(name) as the key and the given size
	push   %rdi
	push   %rsi
	push   %rdx
	push   %r8

	mov    %r9d, %eax            # sizeHi
	mov    0x48(%rsp), %edx      # sizeLo
	shl    $32, %rax

	# hups, hack
	#add    %rax, %rdx
	test   %rdx, %rdx
	cmovz  %rax, %rdx
	mov    %rdx, GLOBAL(tmp)

	mov    0x50(%rsp), %rdi      # lpName
	call   MANGLE(hash_str)
	mov    %rax, %r8

#ifdef __linux__
	# try with hugetlb first, if the allocation is a multiple of 2MB
	mov    GLOBAL(tmp), %rsi     # size
	test   $0x1fffff, %rsi
	jnz    .nohugetlb

	mov    %rax, %rdi            # hash(lpName)
	mov    $05600, %rdx          # SHM_HUGETLB | IPC_CREAT | 0600
	PRE_LIBCALL
	call   MANGLE(shmget)
	POST_LIBCALL
	cmp    $-1, %rax
	jne    .success

.nohugetlb:
#endif

	mov    %r8, %rdi             # hash(lpName)
	mov    GLOBAL(tmp), %rsi     # size
	mov    $01600, %rdx          # IPC_CREAT | 0600
	PRE_LIBCALL
	call   MANGLE(shmget)
	POST_LIBCALL

	cmp    $-1, %rax
	jne    .success

	mov    GLOBAL(tmp), %rdi     # size
	PRE_LIBCALL
	call   MANGLE(warn_shm_failed_cthunk)
	POST_LIBCALL
	jmp    .done

.success:
	# record this id in the table of allocated shm segments
	xor    %rdi, %rdi
	lea    GLOBAL(alloc_shm), %rsi
.shmloop:
	cmp    $0, (%rsi,%rdi,4)
	jne    .next
	mov    %rax, (%rsi,%rdi,4)
	jmp    .done
.next:
	inc    %rdi
	cmp    $32, %rdi
	jne    .shmloop

.done:
	pop    %r8
	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(OpenFileMappingA):
	# largely the same as CreateFileMappingA, only without IPC_CREAT
	push   %rdi
	push   %rsi
	push   %rdx

	mov    %r8, %rdi             # lpName
	call   MANGLE(hash_str)

	mov    %rax, %rdi            # hash(lpName)
	xor    %rsi, %rsi            # size
	mov    $0600, %rdx           # 0600 (no IPC_CREAT)
	PRE_LIBCALL
	call   MANGLE(shmget)
	POST_LIBCALL

	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(MapViewOfFile):
	push   %rdi
	push   %rsi
	push   %rdx

	mov    GLOBAL(shmid_found), %rdi
	test   %rdi, %rdi
	jnz    no_find_size

	# find the size of the shm segment for later use
	mov    %rcx, %rdi            # shmid
	mov    $2, %rsi              # IPC_STAT
	lea    GLOBAL(shmid_ds), %rdx
	push   %rcx
	PRE_LIBCALL
	call   MANGLE(shmctl)
	POST_LIBCALL

	mov    $1, %rcx
	mov    %rcx, GLOBAL(shmid_found)

	pop    %rcx

no_find_size:

	# attach to the shm segment
	mov    %rcx, %rdi            # shmid
	xor    %rsi, %rsi            # don't care about the address
	xor    %rdx, %rdx            # read/write
	PRE_LIBCALL
	call   MANGLE(shmat)
	POST_LIBCALL

	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(UnmapViewOfFile):
	# stubstubstub
	push   %rdi
	push   %rsi
	push   %rdx

	mov    %rcx, %rdi
	PRE_LIBCALL
	call   MANGLE(shmdt)
	POST_LIBCALL

	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(CreatePipe):
	push   %rdi
	push   %rsi

	lea    GLOBAL(tmp), %rdi
	push   %rcx
	push   %rdx
	PRE_LIBCALL
	call   MANGLE(pipe)
	POST_LIBCALL
	pop    %rdx
	pop    %rcx

	mov    GLOBAL(tmp), %eax
	mov    %rax, (%rcx)       # read handle

	mov    GLOBAL(tmp+4), %eax
	mov    %rax, (%rdx)       # write handle

	mov    $1, %rax
	
	pop    %rsi
	pop    %rdi
	retq

MANGLE(GetCurrentProcess):
	mov    $-1, %rax
	retq

MANGLE(DuplicateHandle):
	push   %rdi
	push   %rsi
	push   %rdx

	mov    %rdx, %rdi

	push   %r9
	PRE_LIBCALL
	call   MANGLE(dup)
	POST_LIBCALL
	pop    %r9
	mov    %rax, (%r9)
	mov    $0x1, %rax
	
	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(CloseHandle):
	push   %rdi
	push   %rsi
	push   %rdx

	# don't close stdin, no idea why this happens :-)
	test   %rcx, %rcx
	jz     .noclose

	# and if it's over 100, assume it's a shared segment
	cmp    $100, %rcx
	ja     .shmdestroy

	mov    %rcx, %rdi
	PRE_LIBCALL
	call   MANGLE(close)
	POST_LIBCALL
	jmp    .noclose
	
.shmdestroy:	
	# destroy the shared segment
	mov    %rcx, %rdi            # shmid
	xor    %rsi, %rsi            # IPC_RMID
	xor    %rdx, %rdx            # don't need the shmid_ds data
	PRE_LIBCALL
	call   MANGLE(shmctl)
	POST_LIBCALL

.noclose:
	mov    $0x1, %rax

	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(CreateProcessA):
	# complex enough to make a C thunk worthwhile	
	push   %rdi
	push   %rsi
	push   %rdx

	mov    %rdx, %rdi
	mov    0x60(%rsp), %rsi
	mov    0x68(%rsp), %rdx
	PRE_LIBCALL
	call   MANGLE(CreateProcessA_cthunk)
	POST_LIBCALL

	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(Sleep):
	push   %rdi
	push   %rsi
	push   %rdx

	imul   $1000, %rcx, %rdi
	PRE_LIBCALL
	call   MANGLE(usleep)
	POST_LIBCALL

	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(GetConsoleMode):
	mov    $0x3, %rax     # ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT (?)
	mov    %rax, (%rdx)
	mov    $0x1, %rax
	retq

MANGLE(SetConsoleMode):
	# stub
	retq

MANGLE(FlushConsoleInputBuffer):
	# stub
	retq

MANGLE(GetNumberOfConsoleInputEvents):
	push   %rdi
	push   %rsi
	push   %rdx

#ifdef __APPLE__
	# OS X 10.4 (Tiger) has a bug in that poll() on terminals is completely
	# broken, so use select instead -- it's useful to be able to talk raw
	# UCI on a terminal.
	mov    $0x1, %al
	mov    %al, GLOBAL(readfds)
	
	mov    $1024, %rdi                 # n
	lea    GLOBAL(readfds), %rsi       # readfds
	xor    %rdx, %rdx                  # writefds
	xor    %rcx, %rcx                  # exceptfds
	lea    GLOBAL(timeout), %r8        # timeout	
	PRE_LIBCALL
	call   MANGLE(select)
	POST_LIBCALL
	
	pop    %rdx
	
	add    %rax, %rax         # rybka needs at least two to react
	mov    %eax, (%rdx)
#else
	lea    GLOBAL(pollfd), %rdi 
	mov    $0x1, %rsi
	xor    %rdx, %rdx
	PRE_LIBCALL
	call   MANGLE(poll)
	POST_LIBCALL
	
	pop    %rdx

        xor    %rax, %rax
	mov    GLOBAL(pollfd+6), %ax
#ifdef __APPLE__
	test   $0x41, %rax        # POLLRDNORM|POLLIN
	sbb    %rax, %rax
	neg    %rax
#endif
	add    %rax, %rax         # rybka needs at least two to react
	mov    %eax, (%rdx)
#endif
	
	mov    $0x1, %rax

	pop    %rsi
	pop    %rdi
	retq

# standard djb hash
MANGLE(hash_str):
	push   %rdi
	push   %rcx
	xor    %rax, %rax
	xor    %rcx, %rcx

.hashloop:
	imul   $33, %rax, %rax
	movb   (%rdi), %cl
	add    %rcx, %rax
	add    $1, %rdi
	test   %rcx, %rcx
	jnz    .hashloop
	
	pop    %rcx
	pop    %rdi
#ifdef __APPLE__
	mov    %edi, %edi
#endif
	retq

MANGLE(SetPriorityClass):
	# stub
	retq

MANGLE(GetLogicalDrives):
	mov $0x4, %rax           # drive c: only
	retq

MANGLE(SetFilePointer):
	# maps 1:1 onto lseek
	push   %rdi
	push   %rsi
	push   %rdx

	mov    %rcx, %rdi
	mov    %rdx, %rsi
	mov    %r8, %rdx
	PRE_LIBCALL
	call   MANGLE(lseek)
	POST_LIBCALL

	pop    %rdx
	pop    %rsi
	pop    %rdi
	retq

MANGLE(FlushFileBuffers):
	# stub
	mov    $0x1, %rax
	retq

MANGLE(ExitProcess):
	mov    %rcx, %rdi
	PRE_LIBCALL
	call   MANGLE(exit)
	POST_LIBCALL
	retq

# SIZE_T WINAPI VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
MANGLE(VirtualQuery):
	# rcx = lpAddress, rdx = lpBuffer, r8 = dwLength
	mov    GLOBAL(shmid_ds+48), %rax
	mov    %rax, 0x18(%rdx)
	mov    %r8, %rax
	retq

MANGLE(FindFirstFileA):
	# rcx = lpFileName, rdx = lpFindFileData
	mov    $2, %rax           # ERROR_FILE_NOT_FOUND
	mov    %rax, GLOBAL(last_err)
	mov    $-1, %rax          # INVALID_HANDLE_VALUE
	retq

MANGLE(GetTimeZoneInformation):
	# stub
	retq

MANGLE(RegOpenKeyExA):
	# stub
	mov    $1, %rax           # fail
	retq

MANGLE(GlobalMemoryStatusEx):
	# stub
	xor    %rax, %rax         # fail
	retq

MANGLE(GetPriorityClass):
	# stub
	mov    $0x20, %eax        # NORMAL_PRIORITY_CLASS
	retq

MANGLE(fixup_segment_code):
	shl    $0x3,%rax
	lea    0x4(%r9),%r8d
	lea    -0x1(%rdx),%rcx
	mov    %eax,0x28(%rsp)
	shr    $32,%rax
	mov    %eax,0x24(%rsp)
	retq

	.fill 4096,1,0
