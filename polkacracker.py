
from base64 import b64decode
import sys
import struct
import scrypt
from nacl.secret import SecretBox
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

SCRYPT_DEFAULT_N = 32768
SCRYPT_DEFAULT_P = 1
SCRYPT_DEFAULT_R = 8

ENCODED = "6YQ09y3SrOBIzgUqvV7N47q/jKHbHa2aKUqQCpq77KIAgAAAAQAAAAgAAABux0VeXlE/TOqqw2izAt7Hy5sh+B99q+BMNHU6NIUCev7mNmwV4wICnz0rEEv2ll4i28mfTlZpbzDlP0KHikztX3WHscVKjAwy88jBZ4FXLWmShPkQkI8Nf2JxToG4OnwwMv24dMKjvaCKN1mglPjmfhkLVwzl+bgeCH2DTaJfW9oDW2sjwFq7IznXcTfk2njIFTUpIrlVboqoaZml"

password_found = False
password_found_lock = threading.Lock()

def try_decrypt(password, salt, nonce, encrypted, index):
    global password_found
    with password_found_lock:
        if password_found:
            return None

    print(f"Checking password at line {index}")
    key = scrypt.hash(password.strip(), salt, N=SCRYPT_DEFAULT_N, r=SCRYPT_DEFAULT_R, p=SCRYPT_DEFAULT_P, buflen=32)
    box = SecretBox(key)
    try:
        box.decrypt(encrypted, nonce)
        with password_found_lock:
            password_found = True
        return password.strip()
    except:
        return None

def main():
    if len(sys.argv) < 2:
        print("ERROR: Please specify the dict file within the command line", file=sys.stderr)
        sys.exit(1)

    try:
        fp = open(sys.argv[1], 'r')
    except:
        print("ERROR: Could not open dictionary file '%s'" % sys.argv[1], file=sys.stderr)
        sys.exit(1)

    raw_data = b64decode(ENCODED)

     salt = raw_data[0:32]
    scrypt_n = struct.unpack("<I", raw_data[32:36])[0]
    scrypt_p = struct.unpack("<I", raw_data[36:40])[0]
    scrypt_r = struct.unpack("<I", raw_data[40:44])[0]

    offset = 32 + (3 * 4)
    nonce = raw_data[offset:offset + 24]
    encrypted = raw_data[offset + 24:]

    cracked = False

    num_processes = 12  # Change this value to modify the number of processes

    with ThreadPoolExecutor(max_workers=num_processes) as executor:
        futures = []

        for index, password in enumerate(fp):
            future = executor.submit(try_decrypt, password, salt, nonce, encrypted, index + 1)
            futures.append(future)

            # Cancel remaining tasks if password is found
            for future in as_completed(futures):
                result = future.result()
                if result:
                    print("Password found: '%s'" % result)
                    cracked = True
                    for future in futures:
                        future.cancel()
                    break

    fp.close()

    if cracked:
        print('cracked')
        sys.exit(0)
    else:
        print('not cracked')
        sys.exit(1)

if __name__ == "__main__":
    main()
