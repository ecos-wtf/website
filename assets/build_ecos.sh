#!/bin/sh
#
# Build and export object files from TC72XX_BFC5.5.1 to generate eCOS functionID
#
#
#################################################################################
TOOLCHAIN_BIN="$CURDIR/ecos20/gnutools/mipsisa32-elf/bin"
TOOLCHAIN_BIN_PATH=`echo $PATH | grep "$TOOLCHAIN_BIN"`
CURDIR=$PWD

if [ -z "$TOOLCHAIN_BIN_PATH" ]; then
    export PATH=$TOOLCHAIN_BIN:$PATH
fi

echo "[+] Extracting source code"
tar xf ProdD30_BFC5.5.10_eCos_OpenSrc.tar.bz2

echo "[+] Extracting mipsisa32 toolchain"
tar xf usr_local__ecos20.tgz

echo "[+] Setting path"
export PATH="$PATH:$PWD/ecos20/gnutools/mipsisa32-elf/bin"

echo "[+] Launching build"
cd $CURDIR/rbb_cm_ecos/ecos-src/bcm33xx
sh build.bash 2>/dev/null
cd $CURDIR/rbb_cm_ecos/ecos-src/bcm33xx_ipv6
sh build.bash 2>/dev/null
cd $CURDIR/rbb_cm_ecos/ecos-src/bcm33xx_smp
sh build.bash 2>/dev/null

echo "[+] Exporting object files"
mkdir -p $CURDIR/output
find $CURDIR/rbb_cm_ecos/ecos-src/ -name "*\.o" -exec mv {} $CURDIR/output/ \;

echo "[+] Removing"
rm -rf $CURDIR/ecos20
rm -rf $CURDIR/rbb_cm_ecos
