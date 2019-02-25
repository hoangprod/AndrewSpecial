#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <DbgHelp.h>


#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "ntdll.lib")
#pragma comment (lib, "advapi32.lib")

void getversion_long();
bool AndrewSpecial(const wchar_t * ProcessName);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* RtlGetVersion_t)(_Out_ PRTL_OSVERSIONINFOW lpVersionInformation);

enum supported_versions
{
	win8    = 0x060200,
	win81   = 0x060300,
	win10   = 0x0A0000,
};