#pragma once

#include <Windows.h>
#include <stdint.h>
#include "aes.h"


#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

BOOL AesDecryptBuffer(IN PBYTE pEncryptedData, IN SIZE_T DataSize, IN PBYTE pKey, IN PBYTE pIv);