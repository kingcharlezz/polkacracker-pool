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

password_found = False
password_found_lock = threading.Lock()

ENCODED = "6YQ09y3SrOBIzgUqvV7N47q/jKHbHa2aKUqQCpq77KIAgAAAAQAAAAgAAABux0VeXlE/TOqqw2izAt7Hy5sh+B99q+BMNHU6NIUCev7mNmwV4wICnz0rEEv2ll4i28mfTlZpbzDlP0KHikztX3WHscVKjAwy88jBZ4FXLWmShPkQkI8Nf2JxToG4OnwwMv24dMKjvaCKN1mglPjmfhkLVwzl+bgeCH2DTaJfW9oDW2sjwFq7IznXcTfk2njIFTUpIrlVboqoaZml"

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
        box.decrypt(encrypted, nonce)
        with password_found_lock:
            password_found = True
        return password.strip()
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

    raw_data = b64decode(ENCODED)

    salt = raw_data[0:32]
    scrypt_n = struct.unpack("<I", raw_data[32:36])[0]
    scrypt_p = struct.unpack("<I", raw_data[36:40])[0]
    scrypt_r = struct.unpack("<I", raw_data[40:44])[0]

    offset = 32 + (3 * 4)
    nonce = raw_data[offset:offset + 24]
    encrypted = raw_data[offset + 24:]

    cracked = False

    num_processes = 4  # Change this value to modify the number of processes

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
    else:
        print('not cracked')
        sys.exit(1)

if __name__ == "__main__":
    main()
