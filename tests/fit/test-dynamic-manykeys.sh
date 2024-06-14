#!/bin/sh

BASEDIR=$(dirname "$0")

OUTDIR=$BASEDIR/output/dynamic
KEYS=$OUTDIR/keys
KEYS2=$OUTDIR/keys2

rm -r $OUTDIR
mkdir -p $KEYS
mkdir -p $KEYS2

echo "=[Generate key1 info]=================================="
openssl genrsa -out $KEYS/uboot_sign_key.key 4096
openssl rsa -in $KEYS/uboot_sign_key.key -pubout -out $KEYS/uboot_sign_key.pem

echo "=[Generate key2 info]=================================="
openssl genrsa -out $KEYS2/uboot_sign_key.key 4096
openssl rsa -in $KEYS2/uboot_sign_key.key -pubout -out $KEYS2/uboot_sign_key.pem

echo "=[Create FIT]========================================="
mkimage -f $BASEDIR/uboot/fitImage.its -r $OUTDIR/fitImage

echo "=[Sign FIT with key2]================================="
mkimage -F -k $KEYS2/ -r $OUTDIR/fitImage

echo "=[Compile dtb without public keys]===================="
dtc -I dts $BASEDIR/uboot/u-boot.dts -O dtb -o $OUTDIR/u-boot.dtb

echo "=[Add key1 and key2 to the dtb]======================="
$BASEDIR/../../ubpubkey.py --pubkey $KEYS/uboot_sign_key.pem $KEYS2/uboot_sign_key.pem --keynode key-my_key key-my_key2 --outfile $OUTDIR/u-boot.dtb --set-any-key

echo "=[Check FIT]=========================================="

fit_check_sign -f $OUTDIR/fitImage -k $OUTDIR/u-boot.dtb


