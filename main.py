#original code: https://github.com/taizan-hokuto/chrome_cookie/blob/master/chrome_cookie.py

import sys
import sqlite3
import os
import json, base64
import aesgcm
import argparse

def dpapi_decrypt(encrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result

def dpapi_encrypt(decrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(decrypted, len(decrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result


def get_key_from_local_state():
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'],"Google\\Chrome\\User Data\\Local State"),encoding='utf-8',mode ="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]

def aes_decrypt(encrypted_txt):
    encoded_key = get_key_from_local_state()
    encrypted_key = base64.b64decode(encoded_key.encode())
    #remove prefix 'DPAPI'
    encrypted_key = encrypted_key[5:]
    key = dpapi_decrypt(encrypted_key)
    #get nonce. ignore prefix 'v10', length is 12 bytes.
    nonce = encrypted_txt[3:15]
    cipher = aesgcm.get_cipher(key)
    return aesgcm.decrypt(cipher,encrypted_txt[15:],nonce)

def chrome_decrypt(encrypted_txt):
    if sys.platform == 'win32':
        try:
            if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                decrypted_txt = dpapi_decrypt(encrypted_txt)
                return decrypted_txt
            elif encrypted_txt[:3] == b'v10':
                decrypted_txt = aes_decrypt(encrypted_txt)
                return decrypted_txt[:-16]
        except WindowsError:
            return None
    else:
        return None


if __name__ == "__main__":
    default_source = os.path.join(os.environ['LOCALAPPDATA'], 'Google\\Chrome\\User Data\\Default\\Cookies')
    default_dest = os.path.join(os.environ['APPDATA'], 'obs-studio\\plugin_config\\obs-browser\\Cookies')
    default_host_key = '.youtube.com'

    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=default_source)
    parser.add_argument("--dest", default=default_dest)
    parser.add_argument("--host", default=default_host_key)
    args = parser.parse_args()

    source = args.source
    dest = args.dest
    host_key = args.host

    source_conn = sqlite3.connect(source)
    source_cur = source_conn.cursor()

    dest_conn = sqlite3.connect(dest)
    dest_cur = dest_conn.cursor()

    source_cur.execute('select * from cookies where host_key=?', (host_key,))
    cookies = source_cur.fetchall()

    for c in cookies:
        decrypted = chrome_decrypt(c[12])
        encrypted = dpapi_encrypt(decrypted)
        dest_cur.execute('replace into cookies values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (
            c[0],c[1],c[2],c[3],c[4],c[5],c[6],c[7],c[8],c[9],c[10],c[11],encrypted,0
        ))
        print('replace host:{} name:{}'.format(c[1], c[2]))

    dest_conn.commit()

    dest_cur.close()
    dest_conn.close()

    source_cur.close()
    source_conn.close()

    print('complete!')
