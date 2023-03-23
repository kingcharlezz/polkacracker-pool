#!/usr/bin/env perl

# Author: philsmd
# Date: July 2021
# License: public domain, credits go to philsmd and hashcat

# Note: NaCl uses XSalsa20 and Poly1305 for decrypting the data.
# Key derivation is done by scrypt (32768, 8, 1)

# only tested with version 3 of a PolkaWallet test wallet

use strict;
use warnings;

use MIME::Base64     qw (decode_base64);
use Crypt::ScryptKDF qw (scrypt_raw);
use Crypt::Sodium    qw (crypto_secretbox_open);
# Unfortunately, Crypt::NaCl::Sodium seems to be outdated (and not compiling)

#
# Constants
#

my $SCRYPT_DEFAULT_N = 32768; # 1 << 15 (2 ^ 15)
my $SCRYPT_DEFAULT_P =     1;
my $SCRYPT_DEFAULT_R =     8;


#
# Examples
#

const PAIR = '{"address":"FLiSDPCcJ6auZUGXALLj6jpahcP6adVFDBUQznPXUQ7yoqH","encoded":"ILjSgYaGvq1zaCz/kx+aqfLaHBjLXz0Qsmr6RnkOVU4AgAAAAQAAAAgAAAB5R2hm5kgXyc0NQYFxvMU4zCdjB+ugs/ibEooqCvuudbaeKn3Ee47NkCqU1ecOJV+eeaVn4W4dRvIpj5kGmQOGsewR+MiQ/B0G9NFh7JXV0qcPlk2QMNW1/mbJrTO4miqL448BSkP7ZOhUV6HFUpMt3B9HwjiRLN8RORcFp0ID/Azs4Jl/xOpXNzbgQGIffWgCIKTxN9N1ku6tdlG4","encoding":{"content":["pkcs8","sr25519"],"type":["scrypt","xsalsa20-poly1305"],"version":"3"},"meta":{"genesisHash":"0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe","name":"version3","tags":[],"whenCreated":1595277797639,"whenEdited":1595278378596}}';
my $PASS    = "version3";

my $ENCODED = "ILjSgYaGvq1zaCz/kx+aqfLaHBjLXz0Qsmr6RnkOVU4AgAAAAQAAAAgAAAB5R2hm5kgXyc0NQYFxvMU4zCdjB+ugs/ibEooqCvuudbaeKn3Ee47NkCqU1ecOJV+eeaVn4W4dRvIpj5kGmQOGsewR+MiQ/B0G9NFh7JXV0qcPlk2QMNW1/mbJrTO4miqL448BSkP7ZOhUV6HFUpMt3B9HwjiRLN8RORcFp0ID/Azs4Jl/xOpXNzbgQGIffWgCIKTxN9N1ku6tdlG4";


#
# Start
#

my $raw_data = decode_base64 ($ENCODED);

my $salt = substr ($raw_data, 0, 32);

my $scrypt_n = unpack ("I<", substr ($raw_data, 32, 4));
my $scrypt_p = unpack ("I<", substr ($raw_data, 36, 4));
my $scrypt_r = unpack ("I<", substr ($raw_data, 40, 4));

if ($scrypt_n != $SCRYPT_DEFAULT_N)
{
  print STDERR "ERROR: Scrypt N value not valid\n";

  exit (1);
}

if ($scrypt_p != $SCRYPT_DEFAULT_P)
{
  print STDERR "ERROR: Scrypt P value not valid\n";

  exit (1);
}

if ($scrypt_r != $SCRYPT_DEFAULT_R)
{
  print STDERR "ERROR: Scrypt R value not valid\n";

  exit (1);
}

my $nonce     = substr ($raw_data, 32 + (3 * 4) +  0, 24);
my $encrypted = substr ($raw_data, 32 + (3 * 4) + 24);

while (my $pass = <>)
{
  chomp ($pass);

  my $key = scrypt_raw ($pass, $salt, $SCRYPT_DEFAULT_N, $SCRYPT_DEFAULT_R, $SCRYPT_DEFAULT_P, 32);

  my $decrypted = crypto_secretbox_open ($encrypted, $nonce, $key);

  next if (! defined ($decrypted));

  print "Password found: '$pass'\n";

  exit (0);
}

exit (1);
