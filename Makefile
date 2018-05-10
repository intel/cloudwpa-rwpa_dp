##############################################################################
#   BSD LICENSE
# 
#   Copyright(c) 2007-2017 Intel Corporation. All rights reserved.
#   All rights reserved.
# 
#   Redistribution and use in source and binary forms, with or without 
#   modification, are permitted provided that the following conditions 
#   are met:
# 
#     * Redistributions of source code must retain the above copyright 
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright 
#       notice, this list of conditions and the following disclaimer in 
#       the documentation and/or other materials provided with the 
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its 
#       contributors may be used to endorse or promote products derived 
#       from this software without specific prior written permission.
# 
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
#  version: RWPA_VNF.L.18.02.0-42
##############################################################################

ifeq ($(RTE_SDK),)
$(error Please define RTE_SDK environment variable)
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

APP = r-wpa2_dataplane

ifndef RWPA_SKIP_MAKE_CHECKS

CRYPTO_PMD_FOUND=n
ifeq ($(CONFIG_RTE_LIBRTE_PMD_OPENSSL), y)
CRYPTO_PMD_FOUND=y
endif
ifeq ($(CONFIG_RTE_LIBRTE_PMD_AESNI_MB), y)
CRYPTO_PMD_FOUND=y
endif
ifeq ($(CRYPTO_PMD_FOUND), n)
$(error OPENSSL or AESNI MB PMD not enabled. Please set CONFIG_RTE_LIBRTE_PMD_OPENSSL=y or CONFIG_RTE_LIBRTE_PMD_AESNI_MB=y in $(RTE_SDK)/config/common_base)
endif

ifneq ($(CONFIG_RTE_LIBRTE_IP_FRAG_MAX_FRAG), 2)
$(error MAX FRAGMENTS IS NOT 2. PLEASE SET CONFIG_RTE_LIBRTE_IP_FRAG_MAX_FRAG=2 in $(RTE_SDK)/config/common_base)
endif

endif # RWPA_SKIP_MAKE_CHECKS

CFLAGS += $(WERROR_FLAGS) $(EXTRA_CFLAGS)

ifdef RWPA_RELEASE_BUILD
$(info )
$(info ...Release Build of $(APP)...)
$(info )
CFLAGS += -O3 -g
else
$(info )
$(info ...Debug Build of $(APP)...)
$(info )
CFLAGS += -O0 -g -Wno-error
endif

$(info )
$(info DPDK CONFIGURATION:)
$(info . RTE_SDK                             = $(RTE_SDK))
$(info . CONFIG_RTE_LIBRTE_PMD_OPENSSL       = $(CONFIG_RTE_LIBRTE_PMD_OPENSSL))
$(info . CONFIG_RTE_LIBRTE_PMD_AESNI_MB      = $(CONFIG_RTE_LIBRTE_PMD_AESNI_MB))
$(info . CONFIG_RTE_LIBRTE_IP_FRAG_MAX_FRAG  = $(CONFIG_RTE_LIBRTE_IP_FRAG_MAX_FRAG))
$(info )
$(info ENVIRONMENTAL VARIABLES USED:)
$(info )
$(info . RWPA_RELEASE_BUILD                  = $(RWPA_RELEASE_BUILD))
$(info . RWPA_SKIP_MAKE_CHECKS               = $(RWPA_SKIP_MAKE_CHECKS))
$(info . RWPA_VALIDATION_PLUS                = $(RWPA_VALIDATION_PLUS))
$(info . RWPA_EXTRA_DEBUG                    = $(RWPA_EXTRA_DEBUG))
$(info . RWPA_STATS_CAPTURE                  = $(RWPA_STATS_CAPTURE))
$(info .   RWPA_STATS_CAPTURE_PORTS_OFF      = $(RWPA_STATS_CAPTURE_PORTS_OFF))
$(info .   RWPA_STATS_CAPTURE_STA_LOOKUP_OFF = $(RWPA_STATS_CAPTURE_STA_LOOKUP_OFF))
$(info .   RWPA_STATS_CAPTURE_CRYPTO_OFF     = $(RWPA_STATS_CAPTURE_CRYPTO_OFF))
$(info .   RWPA_STATS_CAPTURE_UPLINK_OFF     = $(RWPA_STATS_CAPTURE_UPLINK_OFF))
$(info .   RWPA_STATS_CAPTURE_DOWNLINK_OFF   = $(RWPA_STATS_CAPTURE_DOWNLINK_OFF))
$(info .   RWPA_STATS_CAPTURE_CONTROL_OFF    = $(RWPA_STATS_CAPTURE_CONTROL_OFF))
$(info . RWPA_CYCLE_CAPTURE                  = $(RWPA_CYCLE_CAPTURE))
$(info . RWPA_NO_REPLAY_CHECK                = $(RWPA_NO_REPLAY_CHECK))
$(info . RWPA_STORE_NO_LOCKS                 = $(RWPA_STORE_NO_LOCKS))
$(info . RWPA_NO_TLS                         = $(RWPA_NO_TLS))
$(info . RWPA_PRELOAD_STORE                  = $(RWPA_PRELOAD_STORE))
$(info . RWPA_CLEAR_STATS_FILENAME           = $(RWPA_CLEAR_STATS_FILENAME))
$(info . RWPA_DYNAMIC_AP_CONF_UPDATE_OFF     = $(RWPA_DYNAMIC_AP_CONF_UPDATE_OFF))
$(info . RWPA_AP_TUNNELLING_GRE              = $(RWPA_AP_TUNNELLING_GRE))
$(info . RWPA_HW_CKSUM_OFFLOAD_OFF           = $(RWPA_HW_CKSUM_OFFLOAD_OFF))
$(info )
$(info EXTRA_CFLAGS = $(EXTRA_CFLAGS))
$(info )

# all source are stored in SRCS-y
SRCS-y := \
	ap_config.c                \
	config.c                    \
	cpu_core_map.c              \
	init.c                      \
	ring.c                      \
	main.c                      \
	parser.c                    \
	eapol_mic_sha1.c            \
	tls_msg_handler.c           \
	tls_socket.c                \
	store.c                     \
	gre.c                       \
	vap_hdrs.c                  \
	convert.c                   \
	uplink_thread.c             \
	downlink_thread.c           \
	arp.c                       \
	wpapt_cdi_helper.c          \
	classifier.c                \
	ieee80211_utils.c           \
	ccmp.c                      \
	crypto.c                    \
	ccmp_sa.c                   \
	vap_frag.c                  \

ifndef RWPA_AP_TUNNELLING_GRE
        SRCS-y += udp.c
endif

ifdef RWPA_PRELOAD_STORE
        SRCS-y += store_load.c
        CFLAGS += -DRWPA_PRELOAD_STORE
endif

ifdef RWPA_CYCLE_CAPTURE
        CFLAGS += -DRWPA_CYCLE_CAPTURE=$(RWPA_CYCLE_CAPTURE)
        SRCS-y += cycle_capture.c
        SRCS-y += statistics_handler_cycles.c
endif

ifdef RWPA_STATS_CAPTURE
        CFLAGS += -DRWPA_STATS_CAPTURE
        SRCS-y += thread_statistics_handler.c
        SRCS-y += statistics_capture.c
        SRCS-y += statistics_capture_common.c

ifndef RWPA_STATS_CAPTURE_PORTS_OFF
        SRCS-y += statistics_capture_ports.c
        SRCS-y += statistics_handler_ports.c
else
        CFLAGS += -DRWPA_STATS_CAPTURE_PORTS_OFF
endif

ifndef RWPA_STATS_CAPTURE_STA_LOOKUP_OFF
        SRCS-y += statistics_capture_sta_lookup.c
        SRCS-y += statistics_handler_sta_lookup.c
else
        CFLAGS += -DRWPA_STATS_CAPTURE_STA_LOOKUP_OFF
endif

ifndef RWPA_STATS_CAPTURE_CRYPTO_OFF
        SRCS-y += statistics_capture_crypto.c
        SRCS-y += statistics_handler_crypto.c
else
        CFLAGS += -DRWPA_STATS_CAPTURE_CRYPTO_OFF
endif

ifndef RWPA_STATS_CAPTURE_UPLINK_OFF
        SRCS-y += statistics_capture_uplink.c
        SRCS-y += statistics_handler_uplink.c
else
        CFLAGS += -DRWPA_STATS_CAPTURE_UPLINK_OFF
endif

ifndef RWPA_STATS_CAPTURE_DOWNLINK_OFF
        SRCS-y += statistics_capture_downlink.c
        SRCS-y += statistics_handler_downlink.c
else
        CFLAGS += -DRWPA_STATS_CAPTURE_DOWNLINK_OFF
endif

ifndef RWPA_STATS_CAPTURE_CONTROL_OFF
        SRCS-y += statistics_capture_control.c
        SRCS-y += statistics_handler_control.c
else
        CFLAGS += -DRWPA_STATS_CAPTURE_CONTROL_OFF
endif

endif # RWPA_STATS_CAPTURE

DEPDIRS-y += lib
CFLAGS += -I$(SRCDIR) -I$(SRCDIR)/stats -I$(SRCDIR)/cycle_capture
VPATH += $(SRCDIR)/stats $(SRCDIR)/cycle_capture

LDFLAGS = -L/usr/local/ssl/lib
LDLIBS = -lssl -lcrypto

ifdef RWPA_EXTRA_DEBUG
	CFLAGS += -DRWPA_EXTRA_DEBUG
endif

ifdef RWPA_NO_TLS
	CFLAGS += -DRWPA_NO_TLS
endif

ifdef RWPA_STORE_NO_LOCKS
	CFLAGS += -DRWPA_STORE_NO_LOCKS
endif

ifdef RWPA_NO_REPLAY_CHECK
	CFLAGS += -DRWPA_NO_REPLAY_CHECK
endif

ifdef RWPA_CLEAR_STATS_FILENAME
	CFLAGS += -DRWPA_CLEAR_STATS_FILENAME=\"$(RWPA_CLEAR_STATS_FILENAME)\"
endif

ifdef RWPA_DYNAMIC_AP_CONF_UPDATE_OFF
	CFLAGS += -DRWPA_DYNAMIC_AP_CONF_UPDATE_OFF
endif

ifdef RWPA_AP_TUNNELLING_GRE
	CFLAGS += -DRWPA_AP_TUNNELLING_GRE
endif

ifdef RWPA_HW_CKSUM_OFFLOAD_OFF
	CFLAGS += -DRWPA_HW_CKSUM_OFFLOAD_OFF
endif

include $(RTE_SDK)/mk/rte.extapp.mk

ifdef RWPA_VALIDATION_PLUS
        CFLAGS += -DRWPA_VALIDATION_PLUS
endif

$(info CFLAGS = $(CFLAGS))

ifndef KW_TEAM_NAME
	KW_TEAM_NAME = R-WPA_VNF
endif

ifndef KW_URL
	KW_URL = https://klocwork.ir.intel.com:8070
endif

klocwork: clean
	@test -d tables_dir || mkdir -p tables_dir
	kwinject -o $(KW_TEAM_NAME).out make
	kwbuildproject -url $(KW_URL)/$(KW_TEAM_NAME) $(KW_TEAM_NAME).out -f -o tables_dir
	kwadmin -url $(KW_URL)/ load $(KW_TEAM_NAME) tables_dir
