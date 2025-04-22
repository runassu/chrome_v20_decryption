**Update**  
In Chrome 133+, the encryption algorithm in `elevation_service.exe` has changed to `ChaCha20_Poly1305`  
Key hardcoded in `elevation_service.exe`:
```
001e94f0                           e9 8f 37 d7 f4 e1 fa 43  |..........7....C|
001e9500  3d 19 30 4d c2 25 80 42  09 0e 2d 1d 7e ea 76 70  |=.0M.%.B..-.~.vp|
001e9510  d4 1f 73 8d 08 72 96 60                           |..s..r.`........|
```
---
Chrome cookie encrypted_value v20 use `app_bound_encrypted_key` in Local State file. To decrypt this, we first need to decrypt `app_bound_encrypted_key` with the SYSTEM DPAPI, followed by the user DPAPI. In other brand browsers, we can directly get the 32-bytes AES key to decrypt encrypted cookies. Chrome requires some additional steps.  
ref:  
[https://github.com/chromium/chromium/blob/35afbc6f6b81d51d697ea615364a972832dab418/chrome/elevation_service/elevator.cc#L199](https://github.com/chromium/chromium/blob/35afbc6f6b81d51d697ea615364a972832dab418/chrome/elevation_service/elevator.cc#L199)

For example, after the double step DPAPI decryption, the resulting value comes with Chrome path, then 1-byte flag 0x01, 12-bytes IV, 32-bytes ciphertext, 16-bytes TAG.
```
00000000  1f 00 00 00 02 43 3a 5c 50 72 6f 67 72 61 6d 20  |.....C:\Program |
00000010  46 69 6c 65 73 5c 47 6f 6f 67 6c 65 5c 43 68 72  |Files\Google\Chr|
00000020  6f 6d 65 3d 00 00 00 01 ca bf 17 e5 f2 f4 47 b0  |ome=....Ê¿.åòôG°|
00000030  e8 1b 64 1b f2 7c 22 49 66 e2 5f fc ed d2 e0 cf  |è.d.ò|"Ifâ_üíÒàÏ|
00000040  c0 4e 1f 21 f6 1b c2 da a2 eb 6f 53 2c 47 d3 9e  |ÀN.!ö.ÂÚ¢ëoS,GÓ.|
00000050  7b 50 e6 7f 4d 5c 34 3f e6 ee d9 43 58 91 9e d2  |{Pæ.M\4?æîÙCX..Ò|
00000060  3a d8 96 30                                      |:Ø.0|
```
IV: `ca bf 17 e5 f2 f4 47 b0 e8 1b 64 1b`  
ciphertext: `f2 7c 22 49 66 e2 5f fc ed d2 e0 cf c0 4e 1f 21 f6 1b c2 da a2 eb 6f 53 2c 47 d3 9e 7b 50 e6 7f `  
TAG: `4d 5c 34 3f e6 ee d9 43 58 91 9e d2 3a d8 96 30`  

We can decrypt it using AES-256-GCM, with the key hardcoded in `elevation_service.exe`:
```
01455184   B3 1C 6E 24 1A C8 46 72  8D A9 C1 FA C4 93 66 51
01455200   CF FB 94 4D 14 3A B8 16  27 6B CC 6D A0 28 47 87
```

This will yield the decrypted key, which works exactly as the v10 `encrypted_key` did.
```
00000000  6d 29 6e e5 7a 29 25 6e 74 5e 26 25 15 97 1e 66
00000010  c1 98 cd 32 2c a6 9f fd 57 de 15 73 8b ed cd 6c
```
