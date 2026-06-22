#pragma once 
#pragma comment(lib, "Wininet.lib")

#include <Windows.h>
#include <stdio.h>
#include <wininet.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)
#define in(msg, ...) printf("[#] " msg "\n", ##__VA_ARGS__)
