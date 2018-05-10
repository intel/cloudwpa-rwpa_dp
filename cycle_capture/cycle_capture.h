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

#ifndef __INCLUDE_CYCLE_CAPTURE_H__
#define __INCLUDE_CYCLE_CAPTURE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define CYCLE_CAPTURE_LEVEL_LOW                         1
#define CYCLE_CAPTURE_LEVEL_HIGH                        2

/* cycles capture off */
#ifndef RWPA_CYCLE_CAPTURE

#define CYCLE_CAPTURE_START(module_name)                do{}while(0)
#define CYCLE_CAPTURE_STOP(module_name)                 do{}while(0)
#define CYCLE_CAPTURE_START_CUMULATIVE(module_name)     do{}while(0)
#define CYCLE_CAPTURE_STOP_CUMULATIVE(module_name)      do{}while(0)
#define CYCLE_CAPTURE_GET_LAST_CALL_CYCLES(module_name) (0)
#define CYCLE_CAPTURE_GET_TOTAL_CYCLES(module_name)     (0)
#define CYCLE_CAPTURE_COPY_LAST(to_module_name, from_module_name) \
                                                        do{}while()
#define CYCLE_CAPTURE_RAW_DEFINE_VARS(start, stop)      do{}while(0)
#define CYCLE_CAPTURE_RAW_START(cycle_ptr)              do{}while(0)
#define CYCLE_CAPTURE_RAW_STOP(cycle_ptr)               do{}while(0)
#define CYCLE_CAPTURE_RAW_CALC_DIFF_AND_INC(target, stop, start) \
                                                        do{}while(0)
#define CYCLE_CAPTURE_INIT()                            do{}while(0)
#define CYCLE_CAPTURE_FREE()                            do{}while(0)

/* cycles capture on */
#else  // #ifndef RWPA_CYCLE_CAPTURE

#include <stdint.h>
#include <stddef.h>

#include <rte_malloc.h>
#include <rte_cycles.h>

#define CYCLE_CAPTURE_START(module_name)                cycle_capture_start((module_name))
#define CYCLE_CAPTURE_STOP(module_name)                 cycle_capture_stop((module_name))
#define CYCLE_CAPTURE_START_CUMULATIVE(module_name)     cycle_capture_start_cumulative((module_name))
#define CYCLE_CAPTURE_STOP_CUMULATIVE(module_name)      cycle_capture_stop_cumulative((module_name))
#define CYCLE_CAPTURE_GET_LAST_CALL_CYCLES(module_name) cycle_capture_get_last_call_cycles((module_name))
#define CYCLE_CAPTURE_GET_TOTAL_CYCLES(module_name)     cycle_capture_get_total_cycles((module_name))
#define CYCLE_CAPTURE_COPY_LAST(to_module_name, from_module_name)                                 \
                                                        cycle_capture_copy_last((to_module_name), \
                                                                                (from_module_name))
#define CYCLE_CAPTURE_RAW_DEFINE_VARS(start, stop)      uint64_t start, stop
#define CYCLE_CAPTURE_RAW_START(cycle_ptr)              cycle_capture_raw_start((cycle_ptr))
#define CYCLE_CAPTURE_RAW_STOP(cycle_ptr)               cycle_capture_raw_stop((cycle_ptr))
#define CYCLE_CAPTURE_RAW_CALC_DIFF_AND_INC(target, stop, start)                    \
                                                        do {                        \
                                                            target += stop - start; \
                                                        } while(0)
#define CYCLE_CAPTURE_INIT()                            cycle_capture_init()
#define CYCLE_CAPTURE_FREE()                            cycle_capture_free()

enum e_capture_funcs {
    /* uplink */
    CYCLE_CAPTURE_UL_PMD_RX = 0,
    CYCLE_CAPTURE_UL_PMD_RX_EXCL_EMPTIES,

    CYCLE_CAPTURE_UL_PROCESS_FULL,

    CYCLE_CAPTURE_UL_INITIAL_PKT_CLASSIFY,
    CYCLE_CAPTURE_UL_AP_TUNNEL_DECAP,
    CYCLE_CAPTURE_UL_VAP_HDR_PARSE,
    CYCLE_CAPTURE_UL_VAP_PAYLOAD_REASSEMBLE,
    CYCLE_CAPTURE_UL_VAP_HDR_DECAP,
    CYCLE_CAPTURE_UL_VAP_TLV_DECAP,
    CYCLE_CAPTURE_UL_IEEE80211_PKT_PARSE,
    CYCLE_CAPTURE_UL_STA_LOOKUP,
    CYCLE_CAPTURE_UL_STA_LOCK,
    CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_GET,
    CYCLE_CAPTURE_UL_CCMP_REPLAY_DETECT,
    CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_UPDATE,
    CYCLE_CAPTURE_UL_CRYPTO_ENQUEUE,
    CYCLE_CAPTURE_UL_CRYPTO_DEQUEUE,
    CYCLE_CAPTURE_UL_STA_UNLOCK,
    CYCLE_CAPTURE_UL_IEEE80211_PKT_CLASSIFY,
    CYCLE_CAPTURE_UL_IEEE80211_TO_ETHER_CONV,
    CYCLE_CAPTURE_UL_GRE_ENCAP,
    CYCLE_CAPTURE_UL_PMD_TX,
    CYCLE_CAPTURE_UL_CCMP_DECAP,
    CYCLE_CAPTURE_UL_WPAPT_CDI_FRAME_ENCAP,
    CYCLE_CAPTURE_UL_WPAPT_CDI_HDR_ENCAP,
    CYCLE_CAPTURE_UL_TLS_TX,

    /* downlink */
    CYCLE_CAPTURE_DL_PMD_RX,
    CYCLE_CAPTURE_DL_PMD_RX_EXCL_EMPTIES,

    CYCLE_CAPTURE_DL_PROCESS_FULL,

    CYCLE_CAPTURE_DL_INITIAL_PKT_CLASSIFY,
    CYCLE_CAPTURE_DL_GRE_DECAP,
    CYCLE_CAPTURE_DL_STA_LOOKUP,
    CYCLE_CAPTURE_DL_STA_LOCK,
    CYCLE_CAPTURE_DL_STA_ENCRYPT_DATA_GET,
    CYCLE_CAPTURE_DL_ETHER_TO_IEEE80211_CONV,
    CYCLE_CAPTURE_DL_CCMP_HDR_GENERATE,
    CYCLE_CAPTURE_DL_CRYPTO_ENQUEUE,
    CYCLE_CAPTURE_DL_CRYPTO_DEQUEUE,
    CYCLE_CAPTURE_DL_STA_UNLOCK,
    CYCLE_CAPTURE_DL_VAP_TLV_ENCAP,
    CYCLE_CAPTURE_DL_VAP_PAYLOAD_FRAGMENT,
    CYCLE_CAPTURE_DL_VAP_HDR_ENCAP,
    CYCLE_CAPTURE_DL_AP_TUNNEL_ENCAP,
    CYCLE_CAPTURE_DL_PMD_TX,
};

struct cycle_stats {
    uint16_t function_id;
    uint64_t call_count;
    uint64_t start_cycles;
    uint64_t last_call_cycles;
    uint64_t total_cycles;
    uint8_t  reset;
};

void
cycle_capture_init(void);

void
cycle_capture_free(void);

void
cycle_capture_start(enum e_capture_funcs func);

void
cycle_capture_stop(enum e_capture_funcs func);

/*
 * used in between cycle capture START and STOP, in order to exclude some
 * actions from final cycle count. Main purpose is to exclude cycles
 * spent in sleep (as those cycles will be used by other threads/processes)
 */
void
cycle_capture_start_cumulative(enum e_capture_funcs func);

/*
 * used in between cycle capture START and STOP, in order to exclude some
 * actions from final cycle count. Main purpose is to exclude cycles
 * spent in sleep (as those cycles will be used by other threads/processes)
 */
void
cycle_capture_stop_cumulative(enum e_capture_funcs func);

uint64_t
cycle_capture_get_last_call_cycles(enum e_capture_funcs func);

uint64_t
cycle_capture_get_total_cycles(enum e_capture_funcs func);

void
cycle_capture_copy_last(enum e_capture_funcs to_func,
                        enum e_capture_funcs from_func);

void
cycle_capture_raw_start(uint64_t *cycle_ptr);

void
cycle_capture_raw_stop(uint64_t *cycle_ptr);

struct cycle_stats *
cycle_capture_get_mem_info(uint32_t *mem_sz);

#ifdef __cplusplus
}
#endif

#endif // #ifndef RWPA_STATS_CAPTURE

#endif // __INCLUDE_CYCLE_CAPTURE_H__
