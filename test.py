#!/usr/bin/env python3

# Author: philsmd
# Date: July 2021
# License: public domain, credits go to philsmd and hashcat

# Note: NaCl uses XSalsa20 and Poly1305 for decrypting the data.
# Key derivation is done by scrypt (32768, 8, 1)

# only tested with version 3 of a PolkaWallet test wallet

from base64 import b64decode

import sys
import struct
import scrypt # py-scrypt (or use hashlib.scrypt or passlib.hash.scrypt)

from nacl.secret import SecretBox # install PyNaCl
import multiprocessing

#
# Constants
#

SCRYPT_DEFAULT_N = 32768 # 1 << 15 (2^15)
SCRYPT_DEFAULT_P =     1
SCRYPT_DEFAULT_R =     8


#
# Functions
#

def crack_password(password):
    global cracked
    global count
    if __name__ == '__main__':
                
    if not cracked:
        key = scrypt.hash(password.strip(), salt, N=SCRYPT_DEFAULT_N, r=SCRYPT_DEFAULT_R, p=SCRYPT_DEFAULT_P, buflen=32)

        box = SecretBox(key)

        try:
            box.decrypt(encrypted, nonce)

            print("Password found: '%s'" % password.strip())
            cracked = True

        except:
            count += 1
            if count % 100 == 0: # print progress every 100 attempts
                print("Tried %d passwords..." % count)


#
# Examples
#

ENCODED = "6YQ09y3SrOBIzgUqvV7N47q/jKHbHa2aKUqQCpq77KIAgAAAAQAAAAgAAABux0VeXlE/TOqqw2izAt7Hy5sh+B99q+BMNHU6NIUCev7mNmwV4wICnz0rEEv2ll4i28mfTlZpbzDlP0KHikztX3WHscVKjAwy88jBZ4FXLWmShPkQkI8Nf2JxToG4OnwwMv24dMKjvaCKN1mglPjmfhkLVwzl+bgeCH2DTaJfW9oDW2sjwFq7IznXcTfk2njIFTUpIrlVboqoaZml";

#
# Start
#

if len(sys.argv) < 2:
    print("ERROR: Please specify the dict file within the command line", file=sys.stderr)
    sys.exit(1)

fp = None

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
count = 0

passwords = fp.readlines()

with multiprocessing.Pool() as pool:
    pool.map(crack_password, passwords)

# Cleanup:
fp.close()

# Exit codes:
if cracked:
    print('cracked')
    sys.exit(0)
else:
    print('not cracked')
    sys.exit(1)
