#!/bin/bash

export CROSS_COMPILE="${PWD}/los-4.9-64/bin/aarch64-linux-gnu-"
export CC="${PWD}/clang"
export CLANG_TRIPLE="${PWD}/los-4.9-64/bin/aarch64-linux-gnu-"
export ARCH=arm64
export ANDROID_MAJOR_VERSION=s

export KCFLAGS=-w
export CONFIG_SECTION_MISMATCH_WARN_ONLY=y

make -C $(pwd) O=$(pwd)/out KCFLAGS=-w CONFIG_SECTION_MISMATCH_WARN_ONLY=y f22_defconfig
make -C $(pwd) O=$(pwd)/out KCFLAGS=-w CONFIG_SECTION_MISMATCH_WARN_ONLY=y -j16

cp out/arch/arm64/boot/Image $(pwd)/arch/arm64/boot/Image
