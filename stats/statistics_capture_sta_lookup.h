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

#ifndef __INCLUDE_STATISTICS_CAPTURE_STA_LOOKUP_H__
#define __INCLUDE_STATISTICS_CAPTURE_STA_LOOKUP_H__

#define STA_LOOKUP_BURST_LEN 16

enum stats_sta_lookup_type {
    /* add new types after this one */
    STATS_STA_LOOKUP_TYPE_L_DELIM = -1,

    STATS_STA_LOOKUP_TYPE_UL,
    STATS_STA_LOOKUP_TYPE_DL,

    /* add new types before this one */
    STATS_STA_LOOKUP_TYPE_U_DELIM
};

struct stats_sta_lookup {
    uint64_t call_num;   /* Total call count of this component */
    uint64_t cycles_num; /* Total cycle count spent in component */
    uint64_t matched;
    uint64_t unmatched;
    uint64_t num_pkts;
    uint32_t last_burst_index;
    uint32_t last_burst[STA_LOOKUP_BURST_LEN];
};

void
stats_capture_sta_lookup_init(struct app_params *app);

void
stats_capture_sta_lookup_free(void);

uint8_t
stats_capture_sta_lookup_is_inited(void);

struct stats_sta_lookup *
stats_capture_sta_lookup_get_mem_info(enum stats_sta_lookup_type type);

size_t
stats_capture_sta_lookup_get_mem_info_size(void);

const char *
stats_capture_sta_lookup_get_type_str(enum stats_sta_lookup_type type);

#endif // __INCLUDE_STATISTICS_CAPTURE_STA_LOOKUP_H__
