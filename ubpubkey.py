#!/usr/bin/env python


#
# A script to convert RSA pubkey to u-boot dts format.
#
# Copyright (c) 2020, Roman Kraevskiy <rkraevskiy@gmail.com>
# All rights reserved.
#
# This software is dual licensed and available under the MPL-2.0
# or under the GPL-2.0-or-later.
#




"""
A script to convert RSA public key(s) to uboot dts format and
write them to a flattened device tree.
2020 Roman Kraievskyi <rkraevskiy@gmail.com>
"""




from __future__ import print_function

from Crypto.PublicKey import RSA
import fdt


VERSION = "1.0a"
NAME = "ubpubkey-ftd"



def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q,r = b//a,b%a;
        m,n = x-u*q,y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    return b, x, y

# reciprocal 
def inverse(v,mod):
    g,x,y = egcd(v,mod)
    if x<0:
        x+=mod
    return x

def bytelen(x):
    return (x.bit_length() + 7) // 8


def int_to_hex(x,bits):
    h = hex(x)[2:].rstrip('L')
    lreq = ((bits+7)//8)*2

    if len(h)<lreq:
        h = "0"*(lreq-len(h)) + h

    return h

def nsplit(l,size):
    n = max(1, size)
    r = list(l[i:i+n] for i in range(len(l)-n,-n,-n))
    r.reverse()
    return r


def int_to_str(x):
    res = []
    while x > 0:
        res.append(chr(x&0xff))
        x = x>>8
    res.reverse()
    return ''.join(res)

def int_to_hexlist(x,nbits,nbytes):
    h = int_to_hex(x,nbits)
    l = [ "0x"+(i.lstrip('0') if i.lstrip('0') else '00') for i in nsplit(h,nbytes*2)]
    return l

class UbootKeyData:
    def __init__(self,rsakey):
        self.rsa_modulus = rsakey.n
        self.rsa_exponent = rsakey.e
        self.rsa_num_bits = rsakey.n.bit_length()
        self.rsa_r_squared = ((2 ** self.rsa_num_bits) ** 2) % self.rsa_modulus
        mod32 = 2**32
        modmask = mod32-1
        self.rsa_n0_inverse = (mod32 - inverse(self.rsa_modulus&modmask,mod32))%mod32

def n_int(i, n):
    return (i & 0xffffffff<<n*32) >> n*32

if __name__ == "__main__":
    import time
    import sys
    import datetime
    import ssl
    from Crypto.Util.asn1 import DerSequence
    import hashlib
    import os
    import argparse

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=__doc__)
    parser.add_argument('-o', '--outfile', help="Output dtb file")
    parser.add_argument('-p', '--pubkey', nargs='+', help="Input public key file(s)")
    parser.add_argument('-k', '--keynode', default=None, nargs='+', help = "Name of the public key node(s)")
    parser.add_argument('-i', '--dtb_in', default=None, help="Optional input dtb file")
    parser.add_argument('-r', '--required', choices=['image', 'conf'], default='conf', help='"required" property for the key(s), default is "conf"')
    parser.add_argument('-a', '--algo', default='sha256,rsa4096', help='"algo" property for the key(s), default is "sha256,rsa4096"')
    parser.add_argument('--set-any-key', action='store_true', help='Set the signature required-mode property to "any"')
    parser.add_argument('--version', action='version', version="%s %s"%(NAME,VERSION))
    args = parser.parse_args()

    keys_nodes = zip(args.pubkey, args.keynode)

    if args.dtb_in:
        dtb_file = args.dtb_in
    else:
        dtb_file = args.outfile
    try:
        with open(dtb_file, 'rb') as f:
            dtb = fdt.parse_dtb(f.read())
    except:
        sys.exit(f'"Failed to parse dtb file {dtb_file}')

    if args.set_any_key:
        dtb.set_property('required-mode', 'any', path='/signature', create=True)

    for ifname, keynode in keys_nodes:
        try:
            f = open(ifname,"r")
            key_data = f.read()
        except:
            sys.exit("Failed to open file '%s'"%ifname)

        ifsrc = os.path.basename(ifname)
        try:
            # try to import as public key
            key = RSA.importKey(key_data)
            src = "pubk"
        except:
            # certificate?
            try:
                der_data = ssl.PEM_cert_to_DER_cert(str(key_data))
                cert = DerSequence()
                cert.decode(der_data)
                tbsCertificate = DerSequence()
                tbsCertificate.decode(cert[0])
                cert = tbsCertificate[6]
                key = RSA.importKey(cert)
                src = "cert"
            except:
                sys.exit("Failed to import key from '%s'"%ifname)

        try:
            der_data = key.exportKey('DER')
            x = UbootKeyData(key)
            h = hashlib.sha256()
            h.update(der_data)
            k_gen = "%s/%s/%s"%(NAME,VERSION,int(time.mktime(datetime.datetime.now().timetuple())))
            k_sha256_fp = "%s"%(h.hexdigest()[:64])
            k_src = "%s/%s"%(src,ifsrc)

            keypath = f'/signature/{keynode}'
            dtb.set_property('required', 'conf', path=keypath)
            dtb.set_property('algo', args.algo, path=keypath, create=True)
            dtb.set_property('rsa,r-squared', [n_int(x.rsa_r_squared, a) for a in reversed(range(((x.rsa_r_squared.bit_length()+31) // 32)))], path=keypath)
            dtb.set_property('rsa,modulus', [n_int(x.rsa_modulus, a) for a in reversed(range((x.rsa_num_bits+31) // 32))], path=keypath)
            dtb.set_property('rsa,exponent', [n_int(x.rsa_exponent, a) for a in reversed(range(64 // 32))], path=keypath)
            dtb.set_property('rsa,modulus', [n_int(x.rsa_modulus, a) for a in reversed(range((x.rsa_num_bits+31) // 32))], path=keypath)
            dtb.set_property('rsa,n0-inverse', x.rsa_n0_inverse, path=keypath)
            dtb.set_property('rsa,num-bits', x.rsa_num_bits, path=keypath)
            dtb.set_property('k-gen ', k_gen, path=keypath)
            dtb.set_property('k-sha256-fp', k_sha256_fp, path=keypath)
            dtb.set_property('k-src', k_src, path=keypath)
        except:
            sys.exit('Failed to generate public key information')
    with open(args.outfile, 'wb') as f:
        f.write(dtb.to_dtb())

