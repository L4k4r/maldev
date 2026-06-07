#pragma once

#include <Windows.h>

BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);