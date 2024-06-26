#!/bin/sh

BASEDIR=$(dirname "$0")

OUTDIR=$BASEDIR/output/dynamic
KEYS=$OUTDIR/keys

rm -r $OUTDIR
mkdir -p $KEYS

echo "=[Generate key1 info]=================================="
openssl genrsa -out $KEYS/uboot_sign_key.key 4096
openssl rsa -in $KEYS/uboot_sign_key.key -pubout -out $KEYS/uboot_sign_key.pem

echo "=[Create FIT]========================================="
mkimage -f $BASEDIR/uboot/fitImage.its -r $OUTDIR/fitImage

echo "=[Sign FIT with key1]================================="
mkimage -F -k $KEYS/ -r $OUTDIR/fitImage

echo "=[Compile dtb without public keys]===================="
dtc -I dts $BASEDIR/uboot/u-boot.dts -O dtb -o $OUTDIR/u-boot.dtb

echo "=[Add key1 to the dtb]======================="
$BASEDIR/../../ubpubkey.py --pubkey $KEYS/uboot_sign_key.pem --keynode key-my_key --outfile $OUTDIR/u-boot.dtb

echo "=[Check FIT]=========================================="

fit_check_sign -f $OUTDIR/fitImage -k $OUTDIR/u-boot.dtb


