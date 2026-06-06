#include "glassBox.h"
#include "aesDecryption.h"

BOOL AesDecryptBuffer(IN PBYTE pEncryptedData, IN SIZE_T DataSize, IN PBYTE pKey, IN PBYTE pIv) {

	struct AES_ctx ctx;

	if (pEncryptedData == NULL || pKey == NULL || pIv == NULL) {
		return FALSE;
	}

	if ((DataSize % AES_BLOCKLEN) != 0) {
		return FALSE;
	}

	AES_init_ctx_iv(&ctx, pKey, pIv);
	AES_CBC_decrypt_buffer(&ctx, pEncryptedData, (uint32_t)DataSize);

	return TRUE;
}