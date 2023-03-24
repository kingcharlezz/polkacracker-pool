from base64 import b64decode
import sys
import struct
import scrypt
from nacl.secret import SecretBox
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from threading import Lock

SCRYPT_DEFAULT_N = 32768
SCRYPT_DEFAULT_P = 1
SCRYPT_DEFAULT_R = 8

password_found = False
password_found_lock = threading.Lock()

ENCODED = "L//SdVuVLDwr1xTBRdE/36I0uekYanqvVQ/mzBttMh0AgAAAAQAAAAgAAACApnc4Fxc3dxmhdAz2JNwRmNs2wqNvA/KSbfM8Qe16aId2B+Goq1FVscgVSe8FzTu6DONP+el8K8gv4+nx9qxcGBlEoBf2KhUuHo6ZSi7nHNoui5ciT7Yd8WpkIcdwiCeJEcw9huysjfuPVQZXx0KuXODfA3UhW4oICKunifDQ+AkucS0Af+l1kPGpMM5uSZbcx8BYtxe9D9UtzrXL"

counter_lock = Lock()
counter = 0

def update_counter():
    global counter
    with counter_lock:
        counter += 1
    return counter

def try_decrypt(password, salt, nonce, encrypted):
    global password_found
    with password_found_lock:
        if password_found:
            return None

    key = scrypt.hash(password.strip(), salt, N=SCRYPT_DEFAULT_N, r=SCRYPT_DEFAULT_R, p=SCRYPT_DEFAULT_P, buflen=32)
    box = SecretBox(key)
    try:
	@@ -33,16 +41,22 @@ def try_decrypt(password, salt, nonce, encrypted, index):
    except:
        return None

def process_line(line, salt, nonce, encrypted):
    password = line.strip()
    current_line = update_counter()
    print(f"Checking password at line {current_line}", end="\r")
    result = try_decrypt(password, salt, nonce, encrypted)
    if result:
        print(f"Password found: '{result}'")
    return result

def main():
    if len(sys.argv) < 2:
        print("ERROR: Please specify the dict file within the command line", file=sys.stderr)
        sys.exit(1)

    try:
        fp = open(sys.argv[1])
    except:
        print("ERROR: Could not open dictionary file '%s'" % sys.argv[1], file=sys.stderr)
        sys.exit(1)
	

    cracked = False

    num_processes = 8  # Change this value to modify the number of processes

    with ThreadPoolExecutor(max_workers=num_processes) as executor:
        futures = [executor.submit(process_line, line, salt, nonce, encrypted) for line in fp]

        for future in as_completed(futures):
            result = future.result()
            if result:
                cracked = True
                break

    fp.close()

    if cracked:
        print('cracked')
        sys.exit(0)
