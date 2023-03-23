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

#
# Constants
#

SCRYPT_DEFAULT_N = 32768 # 1 << 15 (2^15)
SCRYPT_DEFAULT_P =     1
SCRYPT_DEFAULT_R =     8


#
# Examples
#

const PAIR = '{"address":"5Dd3gwmR8FuE7JUZXSYUQ4uzzLuCXUHZr1k41cDk5q4f2p7X","encoded":"L//SdVuVLDwr1xTBRdE/36I0uekYanqvVQ/mzBttMh0AgAAAAQAAAAgAAACApnc4Fxc3dxmhdAz2JNwRmNs2wqNvA/KSbfM8Qe16aId2B+Goq1FVscgVSe8FzTu6DONP+el8K8gv4+nx9qxcGBlEoBf2KhUuHo6ZSi7nHNoui5ciT7Yd8WpkIcdwiCeJEcw9huysjfuPVQZXx0KuXODfA3UhW4oICKunifDQ+AkucS0Af+l1kPGpMM5uSZbcx8BYtxe9D9UtzrXL""encoding":{"content":
["pkcs8","sr25519"],"type":["scrypt","xsalsa20-poly1305"],"version":"3"},"address":"5Dd3gwmR8FuE7JUZXSYUQ4uzzLuCXUHZr1k41cDk5q4f2p7X","meta":
{"genesisHash":"0xadcb639cec07168f455d8bd3a43badf1114a414836829f5000e8279f70d4c667","isHardware":false,"name":"Wallet 1","tags":
[],"whenCreated":1650491676498}}'; 
my $ENCODED = "L//SdVuVLDwr1xTBRdE/36I0uekYanqvVQ/mzBttMh0AgAAAAQAAAAgAAACApnc4Fxc3dxmhdAz2JNwRmNs2wqNvA/KSbfM8Qe16aId2B+Goq1FVscgVSe8FzTu6DONP+el8K8gv4+nx9qxcGBlEoBf2KhUuHo6ZSi7nHNoui5ciT7Yd8WpkIcdwiCeJEcw9huysjfuPVQZXx0KuXODfA3UhW4oICKunifDQ+AkucS0Af+l1kPGpMM5uSZbcx8BYtxe9D9UtzrXL";

#
# Start
#

if len (sys.argv) < 2:
  print ("ERROR: Please specify the dict file within the command line", file=sys.stderr)

  sys.exit (1)

fp = None

try:
  fp = open (sys.argv[1])
except:
  print ("ERROR: Could not open dictionary file '%s'" % sys.argv[1], file=sys.stderr)

  sys.exit (1)

raw_data = b64decode (ENCODED)

salt = raw_data[0:32]

scrypt_n = struct.unpack ("<I", raw_data[32:36])[0]
scrypt_p = struct.unpack ("<I", raw_data[36:40])[0]
scrypt_r = struct.unpack ("<I", raw_data[40:44])[0]

if scrypt_n != SCRYPT_DEFAULT_N:
  print ("ERROR: Scrypt N value not valid", file=sys.stderr)

  sys.exit (1)

if scrypt_p != SCRYPT_DEFAULT_P:
  print ("ERROR: Scrypt P value not valid", file=sys.stderr)

  sys.exit (1)

if scrypt_r != SCRYPT_DEFAULT_R:
  print ("ERROR: Scrypt R value not valid", file=sys.stderr)

  sys.exit (1)

offset = 32 + (3 * 4) # 32 byte salt + 3 numbers (N, p, r)

nonce     = raw_data[offset +  0:offset + 24]
encrypted = raw_data[offset + 24:]

cracked = False

password = fp.readline ()

while password:
  key = scrypt.hash (password.strip (), salt, N = SCRYPT_DEFAULT_N, r = SCRYPT_DEFAULT_R, p = SCRYPT_DEFAULT_P, buflen = 32)

  box = SecretBox (key)

  try:
    box.decrypt (encrypted, nonce)

    print ("Password found: '%s'" % password.strip ())

    cracked = True

    break
  except:
    password = fp.readline ()


# Cleanup:

fp.close ()


# Exit codes:

if cracked:
  sys.exit (0)
else:
  sys.exit (1)
