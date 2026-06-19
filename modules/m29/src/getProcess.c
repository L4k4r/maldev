#include "glassBox.h"
#include <Tlhelp32.h>

/*
typedef struct tagPROCESSENTRY32 {
	DWORD     dwSize;
	DWORD     cntUsage;
	DWORD     th32ProcessID;		 // The Process ID
	ULONG_PTR th32DefaultHeapID;
	DWORD     th32ModuleID;
	DWORD     cntThreads;
	DWORD     th32ParentProcessID;	// Process ID of the parent process
	LONG      pcPriClassBase;
	DWORD     dwFlags;
	CHAR      szExeFile[MAX_PATH];	// The name of the executable file for the process
} PROCESSENTRY32;
*/


BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {



	// According to the documentation:
	// Before calling the Process32First function, set this member of sizeof(PROCESSENTRY32).
	// If dwSize is not initialized, Process32First fails.
	PROCESSENTRY32W	Proc = {
		.dwSize = sizeof(PROCESSENTRY32W)
	};

	HANDLE hSnapShot = NULL;

	// Takes a snapshot of the current running processes
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		warn("CreateToolhelp32Snapshot Failed with Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot
	if (!Process32FirstW(hSnapShot, &Proc)) {
		warn("Process32First Failed with Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// Use the dot operator to extract the process name from the populated struct
		// If the process name matches the process we are looking for
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
			// Use the dot operator to extract the process ID from the populated struct
			// Save the PID
			*dwProcessId = Proc.th32ProcessID;
			info("Found Process at PID: %d", Proc.th32ProcessID);
			// Open a handle to the process
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				warn("OpenProcess Failed with Error : %d \n", GetLastError());
			break; // Exit the loop
		}

		// Retrives information about the next process in the snapshot
		// While a process still remains in the snapshot, continue looping
	} while (Process32NextW(hSnapShot, &Proc));


_EndOfFunction:
	if (hSnapShot != NULL) {
		CloseHandle(hSnapShot);
		if (*dwProcessId == 0 || *hProcess == NULL)
			return FALSE;
		return TRUE;
	}
	return FALSE;
}