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
#include "r-wpa_global_vars.h"
#include "statistics_capture_common.h"
#include "statistics_capture_downlink.h"
#include "statistics_handler_common.h"
#include "statistics_handler_downlink.h"

/* reference to original mem locations of Downlink stats */
static struct stats_downlink_drops *original_downlink_drops_sts = NULL;
static struct stats_pmd_reads *original_downlink_pmd_reads_sts = NULL;

/* 
 * mem where shadow copy of original data is kept.
 * - memcpy is performed between original and shadow copy regions, as
 *   original stat counters change continuously as application runs
 */
static struct stats_downlink_drops *shadow_downlink_drops_sts = NULL;
static size_t shadow_downlink_drops_sts_sz = 0;

static struct stats_pmd_reads *shadow_downlink_pmd_reads_sts = NULL;
static size_t shadow_downlink_pmd_reads_sts_sz = 0;

static struct parsed_stats_downlink_drops *parsed_downlink_drops_sts = NULL;
static struct parsed_stats_pmd_reads *parsed_downlink_pmd_reads_sts = NULL;

static void
init_parsed_mem_downlink(void)
{
    parsed_downlink_drops_sts = rte_zmalloc("downlink_drops_parsed_stats",
                                            sizeof(struct parsed_stats_downlink_drops),
                                            RTE_CACHE_LINE_SIZE);

    if (NULL == parsed_downlink_drops_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate parsed mem for Downlink Drop stats\n");

    parsed_downlink_pmd_reads_sts = rte_zmalloc("downlink_pmd_reads_parsed_stats",
                                                sizeof(struct parsed_stats_pmd_reads),
                                                RTE_CACHE_LINE_SIZE);

    if (NULL == parsed_downlink_pmd_reads_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate parsed mem for Downlink PMD Read stats\n");
}

static void
init_shadow_mem_downlink(void)
{
    /* grab pointers to mem locations of original stats */
    original_downlink_drops_sts = stats_capture_downlink_drops_get_mem_info();
    shadow_downlink_drops_sts_sz = stats_capture_downlink_drops_get_mem_info_size();

    original_downlink_pmd_reads_sts = stats_capture_downlink_pmd_reads_get_mem_info();
    shadow_downlink_pmd_reads_sts_sz = stats_capture_common_pmd_reads_get_mem_info_size();

    /*
     * allocate memory for shadow stats, during the runtime original stats
     * will be 'memcpy' to this memory in order to process the most current
     * snapshot of stats.
     */
    shadow_downlink_drops_sts = rte_zmalloc("downlink_drops_shadow_stats_capture",
                                            shadow_downlink_drops_sts_sz,
                                            RTE_CACHE_LINE_SIZE);

    if (NULL == shadow_downlink_drops_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate shadow mem for Downlink Drop stats\n");

    shadow_downlink_pmd_reads_sts = rte_zmalloc("downlink_pmd_reads_shadow_stats_capture",
                                                shadow_downlink_pmd_reads_sts_sz,
                                                RTE_CACHE_LINE_SIZE);

    if (NULL == shadow_downlink_pmd_reads_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate shadow mem for Downlink PMD Read stats\n");
}

static void
print_stats_downlink_drops(void)
{
    printf("|       PACKET DROPS       |               #                |\n");
    printf("+------------------------- +--------------------------------+\n");
    printf("|   Packet Decap Errors    | %20lu (%6.2f%%) |\n",
           shadow_downlink_drops_sts->packet_decap_error,
           parsed_downlink_drops_sts->packet_decap_error_percent);
    printf("|    Station Not Found     | %20lu (%6.2f%%) |\n",
           shadow_downlink_drops_sts->station_not_found,
           parsed_downlink_drops_sts->station_not_found_percent);
    printf("|      No Station Key      | %20lu (%6.2f%%) |\n",
           shadow_downlink_drops_sts->no_station_key,
           parsed_downlink_drops_sts->no_station_key_percent);
    printf("|   Wifi Convert Errors    | %20lu (%6.2f%%) |\n",
           shadow_downlink_drops_sts->wifi_convert_error,
           parsed_downlink_drops_sts->wifi_convert_error_percent);
    printf("|    Encryption Errors     | %20lu (%6.2f%%) |\n",
           shadow_downlink_drops_sts->encryption_error,
           parsed_downlink_drops_sts->encryption_error_percent);
    printf("|   Fragmentation Errors   | %20lu (%6.2f%%) |\n",
           shadow_downlink_drops_sts->fragmentation_error,
           parsed_downlink_drops_sts->fragmentation_error_percent);
    printf("|   Packet Encap Errors    | %20lu (%6.2f%%) |\n",
           shadow_downlink_drops_sts->packet_encap_error,
           parsed_downlink_drops_sts->packet_encap_error_percent);
    printf("|  Broad/Multicast Packet  | %20lu (%6.2f%%) |\n",
           shadow_downlink_drops_sts->broad_multi_cast_packet,
           parsed_downlink_drops_sts->broad_multi_cast_packet_percent);
    printf("|  Unexpected Packet Type  | %20lu (%6.2f%%) |\n",
           shadow_downlink_drops_sts->unexpected_packet_type,
           parsed_downlink_drops_sts->unexpected_packet_type_percent);
    printf("+-----------------------------------------------------------+\n");
}

static void
print_stats_downlink_pmd_reads(void)
{
    printf("|        PMD READS         |               #                |\n");
    printf("+------------------------- +--------------------------------+\n");
    printf("|          Empty           | %20lu (%6.2f%%) |\n",
           shadow_downlink_pmd_reads_sts->empty,
           parsed_downlink_pmd_reads_sts->empty_percent);
    printf("|        Non Empty         | %20lu (%6.2f%%) |\n",
           shadow_downlink_pmd_reads_sts->non_empty,
           parsed_downlink_pmd_reads_sts->non_empty_percent);
    printf("+-----------------------------------------------------------+\n");
}

void
sts_hdlr_downlink_init(__attribute__((unused)) struct app_params *app)
{
    init_shadow_mem_downlink();
    init_parsed_mem_downlink();
}

void
sts_hdlr_downlink_free(void)
{
    if (NULL != shadow_downlink_drops_sts) {
        rte_free(shadow_downlink_drops_sts);
    }

    if (NULL != shadow_downlink_pmd_reads_sts) {
        rte_free(shadow_downlink_pmd_reads_sts);
    }

    if (NULL != parsed_downlink_drops_sts) {
        rte_free(parsed_downlink_drops_sts);
    }

    if (NULL != parsed_downlink_pmd_reads_sts) {
        rte_free(parsed_downlink_pmd_reads_sts);
    }
}

void
sts_hdlr_downlink_update_shadow_stats(void)
{
    /* simple struct copy - no underlying pointers, just plain data */
    rte_memcpy(shadow_downlink_drops_sts,
               original_downlink_drops_sts,
               shadow_downlink_drops_sts_sz);
    rte_memcpy(shadow_downlink_pmd_reads_sts,
               original_downlink_pmd_reads_sts,
               shadow_downlink_pmd_reads_sts_sz);
}

void
sts_hdlr_downlink_update_parsed_stats(void)
{
    /* drops */
    struct stats_downlink_drops *od = shadow_downlink_drops_sts;
    struct parsed_stats_downlink_drops *pd = parsed_downlink_drops_sts;

    uint64_t total_drops =
        od->packet_decap_error +
        od->station_not_found +
        od->no_station_key +
        od->wifi_convert_error +
        od->encryption_error +
        od->fragmentation_error +
        od->packet_encap_error +
        od->broad_multi_cast_packet +
        od->unexpected_packet_type;

    pd->packet_decap_error_percent = PERCENT(od->packet_decap_error, total_drops);
    pd->station_not_found_percent = PERCENT(od->station_not_found, total_drops);
    pd->no_station_key_percent = PERCENT(od->no_station_key, total_drops);
    pd->wifi_convert_error_percent = PERCENT(od->wifi_convert_error, total_drops);
    pd->encryption_error_percent = PERCENT(od->encryption_error, total_drops);
    pd->fragmentation_error_percent = PERCENT(od->fragmentation_error, total_drops);
    pd->packet_encap_error_percent = PERCENT(od->packet_encap_error, total_drops);
    pd->broad_multi_cast_packet_percent = PERCENT(od->broad_multi_cast_packet, total_drops);
    pd->unexpected_packet_type_percent = PERCENT(od->unexpected_packet_type, total_drops);

    /* pmd reads */
    struct stats_pmd_reads *or = shadow_downlink_pmd_reads_sts;
    struct parsed_stats_pmd_reads *pr = parsed_downlink_pmd_reads_sts;

    uint64_t total_reads = or->empty + or->non_empty;

    pr->empty_percent = PERCENT(or->empty, total_reads);
    pr->non_empty_percent = PERCENT(or->non_empty, total_reads);
}

void
sts_hdlr_downlink_clear_stats(void)
{
    memset(original_downlink_drops_sts, 0, shadow_downlink_drops_sts_sz);
    memset(original_downlink_pmd_reads_sts, 0, shadow_downlink_pmd_reads_sts_sz);
}

void
sts_hdlr_downlink_print(enum rwpa_stats_lvl sts_lvl)
{
    printf("+-----------------------------------------------------------+\n"
           "| DOWNLINK                                                  |\n"
           "+-----------------------------------------------------------+\n");

    switch (sts_lvl) {
    case RWPA_STS_LVL_APP:
    case RWPA_STS_LVL_DETAILED:
        print_stats_downlink_drops();
        print_stats_downlink_pmd_reads();
        break;
    case RWPA_STS_LVL_OFF:
    case RWPA_STS_LVL_PORTS_ONLY:
    default:
        break;
    }

    printf("\n");
}
