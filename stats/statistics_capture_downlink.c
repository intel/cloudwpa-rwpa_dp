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
#include <rte_malloc.h>

#include "app.h"
#include "r-wpa_global_vars.h"
#include "statistics_capture_common.h"
#include "statistics_capture_downlink.h"

static struct stats_downlink_drops *stats_downlink_drops = NULL;
static struct stats_pmd_reads *stats_downlink_pmd_reads = NULL;

/* flag that lets other components check if this class is ready for use */
static uint8_t is_stats_capture_downlink_initialised = 0;

void
stats_capture_downlink_init(__attribute__((unused)) struct app_params *app)
{
    if (is_stats_capture_downlink_initialised) {
        RTE_LOG(ERR, RWPA_STATS,
                "Attempted Downlink stats re-initialisation\n");
        return;
    }

    stats_downlink_drops = rte_zmalloc("downlink_drops_stats_capture",
                                       sizeof(struct stats_downlink_drops),
                                       RTE_CACHE_LINE_SIZE);

    if (NULL == stats_downlink_drops)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate mem for Downlink Drop stats\n");

    stats_downlink_pmd_reads = rte_zmalloc("downlink_pmd_reads_stats_capture",
                                           sizeof(struct stats_pmd_reads),
                                           RTE_CACHE_LINE_SIZE);

    if (NULL == stats_downlink_pmd_reads)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate mem for Downlink PMD Read stats\n");

    is_stats_capture_downlink_initialised = 1;
}

void
stats_capture_downlink_free(void)
{
    if (NULL != stats_downlink_drops)
        rte_free(stats_downlink_drops);

    if (NULL != stats_downlink_pmd_reads)
        rte_free(stats_downlink_pmd_reads);

    is_stats_capture_downlink_initialised = 0;
}

uint8_t
stats_capture_downlink_is_inited(void)
{
    return is_stats_capture_downlink_initialised;
}

struct stats_downlink_drops *
stats_capture_downlink_drops_get_mem_info(void)
{
    return stats_downlink_drops;
}

size_t
stats_capture_downlink_drops_get_mem_info_size(void)
{
    return sizeof(struct stats_downlink_drops);
}

void
stats_capture_downlink_drops_inc(enum stats_downlink_drops_type type,
                                 uint64_t amt)
{
    if (is_stats_capture_downlink_initialised) {
        switch (type) {
        case STATS_DL_DROPS_TYPE_PACKET_DECAP_ERROR:
            stats_downlink_drops->packet_decap_error += amt;
            break;
        case STATS_DL_DROPS_TYPE_STATION_NOT_FOUND:
            stats_downlink_drops->station_not_found += amt;
            break;
        case STATS_DL_DROPS_TYPE_NO_STATION_KEY:
            stats_downlink_drops->no_station_key += amt;
            break;
        case STATS_DL_DROPS_TYPE_WIFI_CONVERT_ERROR:
            stats_downlink_drops->wifi_convert_error += amt;
            break;
        case STATS_DL_DROPS_TYPE_ENCRYPTION_ERROR:
            stats_downlink_drops->encryption_error += amt;
            break;
        case STATS_DL_DROPS_TYPE_FRAGMENTATION_ERROR:
            stats_downlink_drops->fragmentation_error += amt;
            break;
        case STATS_DL_DROPS_TYPE_PACKET_ENCAP_ERROR:
            stats_downlink_drops->packet_encap_error += amt;
            break;
        case STATS_DL_DROPS_TYPE_BROAD_MULTI_CAST_PACKET:
            stats_downlink_drops->broad_multi_cast_packet += amt;
            break;
        case STATS_DL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE:
            stats_downlink_drops->unexpected_packet_type += amt;
            break;
        default:
            break;
        }
    }

    return;
}

struct stats_pmd_reads *
stats_capture_downlink_pmd_reads_get_mem_info(void)
{
    return stats_downlink_pmd_reads;
}

void
stats_capture_downlink_pmd_reads_inc(enum stats_pmd_reads_type type,
                                     uint64_t amt)
{
    if (is_stats_capture_downlink_initialised) {
        switch (type) {
        case STATS_PMD_READS_TYPE_EMPTY:
            stats_downlink_pmd_reads->empty += amt;
            break;
        case STATS_PMD_READS_TYPE_NON_EMPTY:
            stats_downlink_pmd_reads->non_empty += amt;
            break;
        default:
            break;
        }
    }

    return;
}
