
RTE_SDK=/root/pktgen/dpdk-stable-18.11.11

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc
include $(RTE_SDK)/mk/rte.vars.mk
CC = g++
C-suffix=c
# binary name
APP = l2fwd-node-hop16

# all source are stored in SRCS-y
SRCS-y := node.c
# SRCS-y := node.c

CFLAGS += -std=c++11 # -v
CFLAGS += -O0 -g 
# CFLAGS += $(WERROR_FLAGS) -Wno-error -Wno-unused-function

LDLIBS += -lpthread -lcrypto
# LDLIBS += -L/usr/local/openssl/lib -lcrypto
# CPPFLAGS += -I/usr/local/openssl/include
LDFLAGS += -lstdc++
# $(info $$LDLIBS ${LDLIBS})
# $(info $$CPPFLAGS ${CPPFLAGS})
# $(info $$LDFLAGS ${LDFLAGS})

include $(RTE_SDK)/mk/rte.extapp.mk