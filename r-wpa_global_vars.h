/*
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2017 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without 
 *   modification, are permitted provided that the following conditions 
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright 
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright 
 *       notice, this list of conditions and the following disclaimer in 
 *       the documentation and/or other materials provided with the 
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its 
 *       contributors may be used to endorse or promote products derived 
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 *  version: RWPA_VNF.L.18.02.0-42
 */

#ifndef __INCLUDE_RWPA_GLOBAL_VARS_H__
#define __INCLUDE_RWPA_GLOBAL_VARS_H__

/*
 * DEFINES
 */

#ifdef RWPA_VALIDATION_PLUS
#define RWPA_ERROR_ARRAY_OVERFLOW   1
#define RWPA_ERROR_NOTNULL          2
#endif // RWPA_VALIDATION_PLUS

#define RTE_LOGTYPE_RWPA_INIT       RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_RWPA_AP_CONFIG  RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_RWPA_UL         RTE_LOGTYPE_USER2
#define RTE_LOGTYPE_RWPA_DL         RTE_LOGTYPE_USER3
#define RTE_LOGTYPE_RWPA_TLS        RTE_LOGTYPE_USER4
#define RTE_LOGTYPE_RWPA_STORE      RTE_LOGTYPE_USER5
#ifdef RWPA_PRELOAD_STORE
#define RTE_LOGTYPE_RWPA_STORE_LOAD RTE_LOGTYPE_USER5
#endif
#define RTE_LOGTYPE_RWPA_CRYPTO     RTE_LOGTYPE_USER6
#define RTE_LOGTYPE_RWPA_CCMP       RTE_LOGTYPE_USER6
#define RTE_LOGTYPE_RWPA_STATS      RTE_LOGTYPE_USER7

/* Boolean flags */
#define TRUE                        1
#define FALSE                       0

/* TLS Init Constants */
#define R_WPA_PEER_ID               "R-WPA Dataplane"
#define R_WPA_PEER_ID_LEN           15
#define R_WPA_PEER_VERISON          0x00000001 /* 0.0.0.1 */

/* TX drain every ~100us */
#define BURST_TX_DRAIN_US           100
#define MAX_PKT_BURST               32

#define MAX_UL_WRR_ELEMS            2

#define NUM_VAP_MAX                 16000
#define NUM_STA_PER_VAP_MAX         10
#define NUM_STA_MAX                 NUM_VAP_MAX * NUM_STA_PER_VAP_MAX

/*
 * MACROS
 */

/*
 * Additional (optional) validation
 * - NOTE: will impact performance if enabled
 */
#ifdef RWPA_VALIDATION_PLUS

#define RWPA_CHECK_ARRAY_OFFSET(offset, len)          \
     if ((offset) >= (len)) exit(RWPA_ERROR_ARRAY_OVERFLOW);

#define RWPA_CHECK_NOT_NULL(ptr_val)                  \
     if (ptr_val == NULL) exit(RWPA_ERROR_NOTNULL);

#else // RWPA_VALIDATION_PLUS

#define RWPA_CHECK_ARRAY_OFFSET(offset, len)
#define RWPA_CHECK_NOT_NULL(ptr_val)

#endif // RWPA_VALIDATION_PLUS

#define DROP(p_mbuf)                                  \
({                                                    \
     rte_pktmbuf_free(p_mbuf);                        \
     p_mbuf = NULL;                                   \
})

#ifdef RWPA_EXTRA_DEBUG
#define RWPA_LOG(level, log_type, err_msg)            \
     RTE_LOG(level, log_type, err_msg);
#else
#define RWPA_LOG(level, log_type, err_msg)
#endif

#define UNUSED(x) ((void)(x))

#define PERCENT(v, t)                                 \
     (float)(t > 0 ? (((double)v / (double)t) * 100.00) : 0)

/*
 * ENUMS
 */

/* Status */
enum rwpa_status {
    RWPA_STS_OK = 0,
    RWPA_STS_ERR,
};

/*
 * STRUCTS
 */

struct src_port_params {
    uint8_t port_id;
};

struct dst_port_params {
    uint8_t port_id;
    uint16_t queue_id;
    struct rte_eth_dev_tx_buffer *tx_buffer;
};

struct pkt_buffer {
    unsigned len;
    struct rte_mbuf *buffer[MAX_PKT_BURST] __rte_cache_aligned;
};

#endif // __INCLUDE_RWPA_GLOBAL_VARS_H__
