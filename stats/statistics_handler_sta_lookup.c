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

#include <stdio.h>

#include <rte_common.h>
#include <rte_malloc.h>

#include "app.h"
#include "statistics_capture_sta_lookup.h"
#include "statistics_handler_sta_lookup.h"

/* reference to original mem locations of STA Lookup stats */
static struct stats_sta_lookup *original_sta_lookup_sts = NULL;

/* 
 * mem where shadow copy of original data is kept.
 * - memcpy is performed between original and shadow copy regions, as
 *   original stat counters change continuously as application runs
 */
static struct stats_sta_lookup *shadow_sta_lookup_sts = NULL;
static size_t shadow_sta_lookup_sts_sz = 0;

static void
init_shadow_mem_sta_lookup(void)
{
    /* grab pointers to mem locations of original stats */
    original_sta_lookup_sts =
        stats_capture_sta_lookup_get_mem_info(STATS_STA_LOOKUP_TYPE_L_DELIM);
    shadow_sta_lookup_sts_sz = stats_capture_sta_lookup_get_mem_info_size();

    /*
     * allocate memory for shadow stats, during the runtime original stats
     * will be 'memcpy' to this memory in order to process the most current
     * snapshot of stats.
     */
    shadow_sta_lookup_sts = rte_zmalloc("sta_lookup_shadow_stats_capture",
                                        shadow_sta_lookup_sts_sz,
                                        RTE_CACHE_LINE_SIZE);

    if (NULL == shadow_sta_lookup_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate shadow mem for STA Lookup stats\n");
}

static void
print_stats_sta_lookup(void)
{
    unsigned i, j;

    printf("+---------------------------------------------------------------------------------------------------------------------------------+\n");
    printf("|   STA LOOKUP   |     MATCHED    |    UNMATCHED   | AVG NO PKTS PER LOOKUP | LAST RX BURST SIZE                                  |\n");
    printf("+----------------+----------------+----------------+------------------------+-----------------------------------------------------+\n");

    for (j = 0; j < STATS_STA_LOOKUP_TYPE_U_DELIM; j++) {
        printf("|%15s |%15lu |%15lu |%23lu |",
               stats_capture_sta_lookup_get_type_str(j),
               shadow_sta_lookup_sts[j].matched,
               shadow_sta_lookup_sts[j].unmatched,
               shadow_sta_lookup_sts[j].call_num == 0 ? 0 :
                   shadow_sta_lookup_sts[j].num_pkts /
                   shadow_sta_lookup_sts[j].call_num);

        for (i = 0; i < STA_LOOKUP_BURST_LEN; i++) {
            if (i == ((shadow_sta_lookup_sts[j].last_burst_index - 1) % STA_LOOKUP_BURST_LEN))
                printf(" **%02u**", shadow_sta_lookup_sts[j].last_burst[i]);
            else
                printf(" %02u", shadow_sta_lookup_sts[j].last_burst[i]);
        }
        printf(" |\n");
    }

    printf("+---------------------------------------------------------------------------------------------------------------------------------+\n\n");
}

void
sts_hdlr_sta_lookup_init(__attribute__((unused)) struct app_params *app)
{
    init_shadow_mem_sta_lookup();
}

void
sts_hdlr_sta_lookup_free(void)
{
    if (NULL != shadow_sta_lookup_sts) {
        rte_free(shadow_sta_lookup_sts);
    }
}

void
sts_hdlr_sta_lookup_update_shadow_stats(void)
{
    /* simple struct copy - no underlying pointers, just plain data */
    rte_memcpy(shadow_sta_lookup_sts, original_sta_lookup_sts, shadow_sta_lookup_sts_sz);
}

void
sts_hdlr_sta_lookup_update_parsed_stats(void)
{
}

void
sts_hdlr_sta_lookup_clear_stats(void)
{
    memset(original_sta_lookup_sts, 0, shadow_sta_lookup_sts_sz);
}

void
sts_hdlr_sta_lookup_print(enum rwpa_stats_lvl sts_lvl)
{
    switch (sts_lvl) {
    case RWPA_STS_LVL_APP:
    case RWPA_STS_LVL_DETAILED:
        print_stats_sta_lookup();
        break;
    case RWPA_STS_LVL_OFF:
    case RWPA_STS_LVL_PORTS_ONLY:
    default:
        break;
    }
}

struct stats_sta_lookup *
sts_hdlr_sta_lookup_get_mem_info_parsed(void)
{
    return shadow_sta_lookup_sts;
}
