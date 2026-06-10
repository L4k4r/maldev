#include "glassBox.h"
#include "getProcess.h"
#include "injectDll.h"

int wmain(int argc, wchar_t* argv[]) {

	if (argc < 3) {
		warn("Usage : RemoteDllInjection.exe <Complete Dll path> <Process Name>");
		return EXIT_FAILURE;
	}

	LPWSTR szDllPath = argv[1];
	LPWSTR szProcessName = argv[2];

	info("Injecting DLL: %ls Into Process: %ls", szDllPath, szProcessName);


	DWORD dwProcessId = 0;
	HANDLE hProcess = NULL;

	if (!GetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
		warn("Failed to get handle for process : %ls", szProcessName);
		return EXIT_FAILURE;
	}

	if (!InjectDllToRemoteProcess(hProcess, szDllPath)) {
		warn("Failed to Inject DLL with Error : %d", GetLastError());
		return EXIT_FAILURE;
	}

	in("Press <Enter> to Exit...");
	getchar();

	return EXIT_SUCCESS;
}