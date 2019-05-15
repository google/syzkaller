#!/bin/bash
# Generate upstream-kmsan.config from upstream-kasan.config.
# Make sure $CC points to the Clang binary and $SOURCEDIR - to the kernel tree.

THISDIR=`cd $(dirname $0); pwd`
KASAN_CONFIG=${THISDIR}/upstream-kasan.config
KMSAN_CONFIG=${THISDIR}/upstream-kmsan.config
KMSAN_ADD=${THISDIR}/bits-kmsan.config
. ${THISDIR}/util.sh

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit
[ -z "${SOURCEDIR}" ] && echo 'Please set $SOURCEDIR to point to the kernel tree!' && exit

(
cd $SOURCEDIR
cp ${KASAN_CONFIG} .config
scripts/kconfig/merge_config.sh .config ${KMSAN_ADD}
make CC="${CC}" oldconfig < /dev/null

util_add_usb_bits
util_add_extra_syzbot_configs "${KMSAN_CONFIG}"

cat .config >> ${KMSAN_CONFIG}
cp ${KMSAN_CONFIG} .config
)
