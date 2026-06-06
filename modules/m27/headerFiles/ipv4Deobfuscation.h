#pragma once
#include <Windows.h>

BOOL Ipv4Deobfuscation(IN CHAR* ipv4Array[], IN SIZE_T NmbrOfElements, IN SIZE_T OriginalPayloadSize, OUT PBYTE* ppDAdderss, OUT SIZE_T* pDsize);
