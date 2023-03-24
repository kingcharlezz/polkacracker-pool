from base64 import b64decode
import sys
import struct
import scrypt
from nacl.secret import SecretBox
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from threading import Lock
from itertools import islice
import os

SCRYPT_DEFAULT_N = 32768
SCRYPT_DEFAULT_P = 1
SCRYPT_DEFAULT_R = 8

password_found = False
password_found_lock = threading.Lock()

ENCODED = "T/ej+6KLpBVeFNaTxx6IVjNxKK3ToqJxti7R/vrg02sAgAAAAQAAAAgAAACCiUOMV0Wp7JrqGtw+IgebYqOMI8Nc81z97BXeCQ/gcji1YgRZICr6236rMy5OPfa6da/Aq8yR4ef7LJ40CFI4an4bIonqg3a40+KMu9QZ+iHVWf39U/TsI+XubAiLrqRcRIBrAq20CEw4TwRjsLYV41spkKocDB4SscxfpwuopUiKEuQ2+unxabsOC3poe4PH161TitOKiXAlXGrW"

counter_lock = Lock()
counter = 0
last_line = 0


def update_counter(offset=0):
    global counter
    with counter_lock:
        counter += 1
    return counter + offset


def read_last_line():
    global last_line
    try:
        with open('last_line.txt', 'r') as f:
            last_line = int(f.readline())
    except:
        last_line = 0


read_last_line()


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


def process_line(line, salt, nonce, encrypted, last_line):
    password = line.strip()
    current_line = update_counter()
    print(f"Checking password at line {last_line} + {current_line}", end="\r")
    result = try_decrypt(password, salt, nonce, encrypted)
    if result:
        print(f"Password found: '{result}'")
    return result


def main():
    global last_line
    if len(sys.argv) < 2:
        print("ERROR: Please specify the dict file within the command line", file=sys.stderr)
        sys.exit(1)

    fp = None
    try:
        fp = open(sys.argv[1], 'r', encoding='utf-8')
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

    num_processes = os.cpu_count() or 8

    # Seek to the last line that was successfully processed and start from there
    fp.seek(last_line)

    # Create a new file to store the line number when the program stops
    with open('last_line.txt', 'w') as f:
        with ThreadPoolExecutor(max_workers=num_processes) as executor:
            chunk_size = 1000
            lines = (line.strip() for line in fp)
            futures = []

            while not password_found:
                chunk = list(islice(lines, chunk_size))
                if not chunk:
                    break
                futures.extend(executor.submit(process_line, line, salt, nonce, encrypted, last_line) for line in chunk)

            for future in as_completed(futures):
                result = future.result()
                if result:
                    cracked = True
                    break

                # Save the current line number to the file every 1000 lines
                if update_counter() % 1000 == 0:
                    f.write(str(fp.tell()) + '\n')

        # Save the final line number to the file
        f.write(str(fp.tell()) + '\n')

    fp.close()

    if cracked:
        print('cracked')
        sys.exit(0)
    else:
        print('not cracked')
        sys.exit(1)


if __name__ == "__main__":
    main()
