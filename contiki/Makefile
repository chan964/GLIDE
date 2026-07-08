CONTIKI_PROJECT = device_auth_main
all: $(CONTIKI_PROJECT)

TARGET ?= sky

PROJECT_SOURCEFILES += device_auth.c
PROJECT_SOURCEFILES += hkdf_sha256.c
PROJECT_SOURCEFILES += sha256_impl.c
PROJECT_SOURCEFILES += syscalls_stub.c

MODULES += os/net/security/micro-ecc
CFLAGS += -DuECC_SUPPORTS_secp256r1=1
CFLAGS += -DuECC_SUPPORT_COMPRESSED_POINT=1
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=2

CFLAGS += -Os
CFLAGS += -Wno-error=format -Wno-error=format-extra-args

CONTIKI_NG_PATH ?= /home/csp/Desktop/contiki-ng
MAKE_ROUTING = MAKE_ROUTING_NULLROUTING
MAKE_NET = MAKE_NET_NULLNET
include $(CONTIKI_NG_PATH)/Makefile.include
