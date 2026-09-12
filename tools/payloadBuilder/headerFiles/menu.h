#pragma once

void PrintMenu(void);
int GetEncryptionChoice(void);
int GetObfuscationChoice(void);

BOOL ReadPayload(unsigned char** Payload, DWORD* PayloadSize);