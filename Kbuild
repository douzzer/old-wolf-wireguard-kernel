# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

ccflags-y := -O3 -fvisibility=hidden
ccflags-$(CONFIG_WIREGUARD_DEBUG) += -DDEBUG -g
ccflags-y += -I/home/douzzer/com/wolfssl/src/wolfssl
ccflags-y += -D'pr_fmt(fmt)=KBUILD_MODNAME ": " fmt'
ccflags-y += -Wframe-larger-than=2048
ccflags-y += -include $(src)/wolfcrypto_shim.h



wireguard-y := wolfcrypto_shim.o main.o noise.o device.o peer.o timers.o queueing.o send.o receive.o socket.o peerlookup.o allowedips.o ratelimiter.o cookie.o netlink.o

#include $(src)/crypto/Kbuild.include
include $(src)/compat/Kbuild.include

obj-$(if $(KBUILD_EXTMOD),m,$(CONFIG_WIREGUARD)) := wireguard.o

KBUILD_EXTRA_SYMBOLS := /home/douzzer/com/wolfssl/src/wolfssl/linuxkm/Module.symvers
