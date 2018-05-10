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

#include <rte_common.h>
#include <rte_memory.h>

#include "r-wpa_global_vars.h"
#include "cycle_capture.h"

const char *function_names[] = {
    /* uplink */
    "UL_PMD_RX",
    "UL_PMD_RX_EXCL_EMPTIES",

    "UL_PROCESS_FULL",

    "UL_INITIAL_PKT_CLASSIFY",
    "UL_AP_TUNNEL_DECAP",
    "UL_VAP_HDR_PARSE",
    "UL_VAP_PAYLOAD_REASSEMBLE",
    "UL_VAP_HDR_DECAP",
    "UL_VAP_TLV_DECAP",
    "UL_IEEE80211_PKT_PARSE",
    "UL_STA_LOOKUP",
    "UL_STA_LOCK",
    "UL_STA_DECRYPT_DATA_GET",
    "UL_CCMP_REPLAY_DETECT",
    "UL_STA_DECRYPT_DATA_UPDATE",
    "UL_CRYPTO_ENQUEUE",
    "UL_CRYPTO_DEQUEUE",
    "UL_STA_UNLOCK",
    "UL_IEEE80211_PKT_CLASSIFY",
    "UL_IEEE80211_TO_ETHER_CONV",
    "UL_GRE_ENCAP",
    "UL_PMD_TX",
    "UL_CCMP_DECAP",
    "UL_WPAPT_CDI_FRAME_ENCAP",
    "UL_WPAPT_CDI_HDR_ENCAP",
    "UL_TLS_TX",

    /* downlink */
    "DL_PMD_RX",
    "DL_PMD_RX_EXCL_EMPTIES",

    "DL_PROCESS_FULL",

    "DL_INITIAL_PKT_CLASSIFY",
    "DL_GRE_DECAP",
    "DL_STA_LOOKUP",
    "DL_STA_LOCK",
    "DL_STA_ENCRYPT_DATA_GET",
    "DL_ETHER_TO_IEEE80211_CONV",
    "DL_CCMP_HDR_GENERATE",
    "DL_CRYPTO_ENQUEUE",
    "DL_CRYPTO_DEQUEUE",
    "DL_STA_UNLOCK",
    "DL_VAP_TLV_ENCAP",
    "DL_VAP_PAYLOAD_FRAGMENT",
    "DL_VAP_HDR_ENCAP",
    "DL_AP_TUNNEL_ENCAP",
    "DL_PMD_TX",
};
static const uint32_t cycle_capture_function_num =
                                sizeof(function_names)/sizeof(function_names[0]);
static struct cycle_stats *cycle_stats_arr;

void
cycle_capture_init(void)
{
    uint16_t i = 0;

    cycle_stats_arr = rte_malloc("cycle_capture_stats_array",
                                 sizeof(struct cycle_stats) * cycle_capture_function_num,
                                 RTE_CACHE_LINE_SIZE);

    if (NULL == cycle_stats_arr) {
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate mem for cycle counts\n");
    }

    for (i = 0; i < cycle_capture_function_num; i++) {
        cycle_stats_arr[i].function_id = i;
        cycle_stats_arr[i].call_count = 0;
        cycle_stats_arr[i].start_cycles = 0;
        cycle_stats_arr[i].last_call_cycles = 0;
        cycle_stats_arr[i].total_cycles = 0;
        cycle_stats_arr[i].reset = FALSE;
    }
}

void
cycle_capture_free(void)
{
    rte_free(cycle_stats_arr);
}

void
cycle_capture_start(enum e_capture_funcs func)
{
    struct cycle_stats *stats = &(cycle_stats_arr[func]);

    if (stats->reset == TRUE) {
        stats->call_count = 0;
        stats->start_cycles = 0;
        stats->last_call_cycles = 0;
        stats->total_cycles = 0;
        stats->reset = FALSE;
    }

    stats->last_call_cycles = 0;
    cycle_capture_raw_start(&(stats->start_cycles));
}

void
cycle_capture_stop(enum e_capture_funcs func)
{
    uint64_t stop_cycles;
    struct cycle_stats *stats = &(cycle_stats_arr[func]);

    /* race condition handling when reseting stats */
    if (stats->reset == TRUE)
        return;

    cycle_capture_raw_stop(&stop_cycles);
    stats->last_call_cycles += stop_cycles - stats->start_cycles;
    stats->total_cycles += stats->last_call_cycles;
    stats->call_count++;
}

void
cycle_capture_start_cumulative(enum e_capture_funcs func)
{
    struct cycle_stats *stats = &(cycle_stats_arr[func]);

    /* race condition handling when reseting stats */
    if (stats->reset == TRUE)
        return;

    cycle_capture_raw_start(&(stats->start_cycles));
}

void
cycle_capture_stop_cumulative(enum e_capture_funcs func)
{
    uint64_t stop_cycles;
    struct cycle_stats *stats = &(cycle_stats_arr[func]);

    /* race condition handling when reseting stats */
    if (stats->reset == TRUE)
        return;

    cycle_capture_raw_stop(&stop_cycles);
    stats->last_call_cycles += stop_cycles - stats->start_cycles;
}

uint64_t
cycle_capture_get_last_call_cycles(enum e_capture_funcs func)
{
    return cycle_stats_arr[func].last_call_cycles;
}

uint64_t
cycle_capture_get_total_cycles(enum e_capture_funcs func)
{
    return cycle_stats_arr[func].total_cycles;
}

void
cycle_capture_copy_last(enum e_capture_funcs to_func,
                        enum e_capture_funcs from_func)
{
    struct cycle_stats *to_stats = &(cycle_stats_arr[to_func]);
    struct cycle_stats *from_stats = &(cycle_stats_arr[from_func]);

    /* race condition handling when reseting stats */
    if (from_stats->reset == TRUE)
        return;

    if (to_stats->reset == TRUE) {
        to_stats->call_count = 0;
        to_stats->start_cycles = 0;
        to_stats->last_call_cycles = 0;
        to_stats->total_cycles = 0;
        to_stats->reset = FALSE;
    }

    to_stats->last_call_cycles = from_stats->last_call_cycles;
    to_stats->total_cycles += to_stats->last_call_cycles;
    to_stats->call_count++;
}

void
cycle_capture_raw_start(uint64_t *cyc)
{
    *cyc = rte_get_tsc_cycles();
}

void
cycle_capture_raw_stop(uint64_t *cyc)
{
    *cyc = rte_get_tsc_cycles();
}

struct cycle_stats *
cycle_capture_get_mem_info(uint32_t *mem_sz)
{
    *mem_sz = sizeof(struct cycle_stats) * cycle_capture_function_num;
    return cycle_stats_arr;
}
