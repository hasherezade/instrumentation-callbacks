﻿#include <iostream>
#include <fstream>
#include <sstream>
#include <mutex>

#include <cstdio>
#include <vector>

#include <Windows.h>
#include <psapi.h>

#include "minwin.hpp"

namespace TraceLog {

	std::ofstream m_traceFile;
	std::string m_logFileName = "syscall.log";

	bool createFile()
	{
		if (m_traceFile.is_open()) {
			return true;
		}
		m_traceFile.open(m_logFileName.c_str());
		if (m_traceFile.is_open()) {
			return true;
		}
		return false;
	}

	void logLine(const std::string& str)
	{
		if (!createFile()) return;

		m_traceFile
			<< str
			<< std::endl;
		m_traceFile.flush();
	}
};

//---

// Callback struct
PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION callback = { 0 };


std::vector<uintptr_t> g_hooked = {};
std::vector<uintptr_t> g_intercepted = {};
std::mutex g_intercepted_mtx;
bool g_isWatchEnabled = false;


void dump_symbol(uintptr_t R10)
{
	uint8_t buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };

	const auto symbol_info = (PSYMBOL_INFO)buffer;
	symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
	symbol_info->MaxNameLen = MAX_SYM_NAME;
	uintptr_t displacement;

	// MSDN: Retrieves symbol information for the specified address.
	const auto result = SymFromAddr(GetCurrentProcess(), R10, &displacement, symbol_info);

	// Deny access if function is hooked
	if (result)
	{
		// Print what we know
		std::stringstream ss;
		ss << "\tFunction: " << symbol_info->Name << " Return address: " << std::hex << R10;
		TraceLog::logLine(ss.str());
	}
}

void dump_results()
{
	for (auto itr = g_intercepted.begin(); itr != g_intercepted.end(); ++itr) {
		uintptr_t R10 = *itr;
		std::stringstream ss;
		ss << "\tReturn address: " << std::hex << R10;
		TraceLog::logLine(ss.str());
	}
}

void storeFunc(uintptr_t R10)
{
	const std::lock_guard<std::mutex> lock(g_intercepted_mtx);
	g_intercepted.push_back(R10);
}

uintptr_t hook(uintptr_t R10, uintptr_t RAX/* ... */) {
	if (!g_isWatchEnabled) return RAX;

	static bool flag = false;
	// This flag is there for prevent recursion
	if (!flag) {
		
		flag = true;
		storeFunc(R10);
		flag = false;
		
		return RAX;
	}

	return RAX;
}



int run_demo()
{
	// sample calls
	CreateFile(L"X:", GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
	SetCurrentDirectory(L"C:/");
	// WinExec("calc.exe", 0);

	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682623(v=vs.85).aspx

	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 1;
	}

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.
	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			OpenProcess(PROCESS_QUERY_INFORMATION |
				PROCESS_VM_READ,
				FALSE, aProcesses[i]);
		}
	}

	// We can not hook RtlRandomEx, it does not crosses kernel
	typedef ULONG RtlRandomEx(
		_Inout_ PULONG Seed
	);
	RtlRandomEx* rand = (RtlRandomEx*)GetProcAddress(GetModuleHandle(L"ntdll"), "RtlRandomEx");
	ULONG seed = 1;
	ULONG rand_value = rand(&seed);
	return 0;
}


bool install_hook()
{
	static bool isHooked = false;
	if (isHooked) return true;

	SymSetOptions(SYMOPT_UNDNAME);
	SymInitialize(GetCurrentProcess(), nullptr, TRUE);

	// Reserved is always 0
	callback.Reserved = 0;
	// x64 = 0, x86 = 1
	callback.Version = CALLBACK_VERSION;
	// Set our asm callback handler
	callback.Callback = medium;

	// Add hook for NtQVM
	//g_hooked.push_back((uintptr_t)GetProcAddress(GetModuleHandleA("ntdll"), "ZwAllocateVirtualMemory"));

	// Setup the hook
	NTSTATUS res = NtSetInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x28, &callback, sizeof(callback));
	isHooked = true;
	bool isOk = res == 0 ? true : false;
	g_isWatchEnabled = isOk;
	return isOk;
}

bool uninstall_hook()
{
	g_isWatchEnabled = false;
	// Check if unaffected functions don't crash
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0, nullptr, 0, nullptr);

	callback.Callback = nullptr;

	// Remove callback
	NTSTATUS res = NtSetInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x28, &callback, sizeof(callback));

	return res == 0 ? true : false;
}


#define USE_DLL
#ifdef USE_DLL
BOOL WINAPI DllMain(HANDLE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		install_hook();
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		uninstall_hook();
		dump_results();
		break;
	}
	return TRUE;
}
#else 
int main()
{
	if (install_hook()) {
		printf("[+] hooked\n");
	}
	/*
	// Run hooked function to test the hook
	MEMORY_BASIC_INFORMATION region = {nullptr};
	const auto status = NtQueryVirtualMemory(GetCurrentProcess(), GetModuleHandle(nullptr), MemoryBasicInformation, &region, sizeof(region), nullptr);

	// Print spoofed status
	printf("[+] NtQVM status: 0x%04X\n", status);
	*/

	int res = run_demo();
	std::cout << "Demo res: " << res << std::endl;
	if (uninstall_hook()) {
		printf("[+] unhooked\n");
	}
	return 0;
}
#endif
