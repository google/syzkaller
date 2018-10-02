#!/bin/bash
# Generate upstream-kmsan.config from upstream-kasan.config.
# Make sure $CC points to the Clang binary and $SOURCEDIR - to the kernel tree.

THISDIR=`cd $(dirname $0); pwd`
KASAN_CONFIG=${THISDIR}/upstream-kasan.config
KMSAN_CONFIG=${THISDIR}/upstream-kmsan.config
KMSAN_ADD=${THISDIR}/kmsan-syzbot-bits.config

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit
[ -z "${SOURCEDIR}" ] && echo 'Please set $SOURCEDIR to point to the kernel tree!' && exit

(
cd $SOURCEDIR
cp ${KASAN_CONFIG} .config
scripts/kconfig/merge_config.sh .config ${KMSAN_ADD}
make CC="${CC}" oldconfig < /dev/null

echo "# The following configs are added manually, preserve them.
# CONFIG_DEBUG_MEMORY was once added to mm tree and cause disabling of KASAN,
# which in turn caused storm of assorted crashes after silent memory
# corruptions. The config was reverted, but we keep it here for the case
# it is reintroduced to kernel again.
CONFIG_DEBUG_MEMORY=y
# This config can be used to enable any additional temporal debugging
# features in linux-next tree.
CONFIG_DEBUG_AID_FOR_SYZBOT=y
" > ${KMSAN_CONFIG}

cat .config >> ${KMSAN_CONFIG}
cp ${KMSAN_CONFIG} .config
)
