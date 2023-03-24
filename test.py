
from base64 import b64decode
import sys
import struct
import scrypt
from nacl.secret import SecretBox
from concurrent.futures import ProcessPoolExecutor, as_completed


# Constants

SCRYPT_DEFAULT_N = 32768
SCRYPT_DEFAULT_P = 1
SCRYPT_DEFAULT_R = 8


# Define a function to crack the password

def crack_password(encrypted, nonce, salt, password):
    key = scrypt.hash(password.strip(), salt, N=SCRYPT_DEFAULT_N, r=SCRYPT_DEFAULT_R, p=SCRYPT_DEFAULT_P, buflen=32)
    box = SecretBox(key)
    try:
        box.decrypt(encrypted, nonce)
        return password.strip()
    except:
        return None


# Start

if len(sys.argv) < 2:
    print("ERROR: Please specify the dict file within the command line", file=sys.stderr)
    sys.exit(1)

fp = None
try:
    fp = open(sys.argv[1])
except:
    print("ERROR: Could not open dictionary file '%s'" % sys.argv[1], file=sys.stderr)
    sys.exit(1)

raw_data = b64decode("6YQ09y3SrOBIzgUqvV7N47q/jKHbHa2aKUqQCpq77KIAgAAAAQAAAAgAAABux0VeXlE/TOqqw2izAt7Hy5sh+B99q+BMNHU6NIUCev7mNmwV4wICnz0rEEv2ll4i28mfTlZpbzDlP0KHikztX3WHscVKjAwy88jBZ4FXLWmShPkQkI8Nf2JxToG4OnwwMv24dMKjvaCKN1mglPjmfhkLVwzl+bgeCH2DTaJfW9oDW2sjwFq7IznXcTfk2njIFTUpIrlVboqoaZml")
salt = raw_data[0:32]
scrypt_n = struct.unpack("<I", raw_data[32:36])[0]
scrypt_p = struct.unpack("<I", raw_data[36:40])[0]
scrypt_r = struct.unpack("<I", raw_data[40:44])[0]

if scrypt_n != SCRYPT_DEFAULT_N:
    print("ERROR: Scrypt N value not valid", file=sys.stderr)
    sys.exit(1)

if scrypt_p != SCRYPT_DEFAULT_P:
    print("ERROR: Scrypt P value not valid", file=sys.stderr)
    sys.exit(1)

if scrypt_r != SCRYPT_DEFAULT_R:
    print("ERROR: Scrypt R value not valid", file=sys.stderr)
    sys.exit(1)

offset = 32 + (3 * 4) # 32 byte salt + 3 numbers (N, p, r)
nonce     = raw_data[offset +  0:offset + 24]
encrypted = raw_data[offset + 24:]

cracked = False

# Split the dictionary file into chunks
chunk_size = 10000  # number of passwords to check in each chunk
passwords = fp.readlines()
chunks = [passwords[i:i+chunk_size] for i in range(0, len(passwords), chunk_size)]

# Define a function to check passwords in a chunk
def check_passwords(chunk):
    results = []
    for password in chunk:
        result = crack_password(encrypted, nonce, salt, password)
        if result:
            results.append(result)
    return results

# Use multiple processes to check passwords in parallel
with ProcessPoolExecutor() as executor:
    futures = [executor.submit(check_passwords, chunk) for chunk in chunks]
    for future in as_completed(futures):
        results = future.result()
        if results:
            for result in results:
                print("Password found: '%s'" % result)
            cracked = True
            break
