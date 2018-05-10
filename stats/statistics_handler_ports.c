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
#include <rte_sched.h>

#include "app.h"
#include "statistics_capture_ports.h"
#include "statistics_handler_ports.h"

static struct stats_ports *original_ports_sts = NULL;
static struct stats_ports *shadow_ports_sts   = NULL;
static struct stats_ports *per_sec_ports_sts = NULL;
static struct stats_ports *temp_ports_sts = NULL;
static size_t ports_sts_sz = 0;

static uint32_t stats_refresh_period_s = 0;

static void
calculate_parsed_stats_ports(struct rte_eth_stats *start,
                             struct rte_eth_stats *end,
                             struct rte_eth_stats *per_sec_stats)
{
    per_sec_stats->ipackets  = (end->ipackets  - start->ipackets)  / stats_refresh_period_s;
    per_sec_stats->ibytes    = (end->ibytes    - start->ibytes)    / stats_refresh_period_s;
    per_sec_stats->opackets  = (end->opackets  - start->opackets)  / stats_refresh_period_s;
    per_sec_stats->obytes    = (end->obytes    - start->obytes)    / stats_refresh_period_s;
    per_sec_stats->imissed   = (end->imissed   - start->imissed)   / stats_refresh_period_s;
    per_sec_stats->oerrors   = (end->oerrors   - start->oerrors)   / stats_refresh_period_s;
    per_sec_stats->rx_nombuf = (end->rx_nombuf - start->rx_nombuf) / stats_refresh_period_s;
}

static void
stats_port_print(uint32_t port_id,
                 struct rte_eth_stats *stats,
                 struct rte_eth_stats *per_sec)
{
    printf("| Port %d: Rx: %12"PRIu64" pkts, %12"PRIu64" pkts/s, %16"PRIu64" B,"
           " %12"PRIu64" B/s, avg pkt size %4"PRIu64" (over s %4"PRIu64"),"
           " dropped %12"PRIu64", dropped/s %12"PRIu64" |\n"
           "|         Tx: %12"PRIu64" pkts, %12"PRIu64" pkts/s, %16"PRIu64" B,"
           " %12"PRIu64" B/s, avg pkt size %4"PRIu64" (over s %4"PRIu64"),"
           " dropped %12"PRIu64", dropped/s %12"PRIu64" |\n",
           port_id,
           stats->ipackets, per_sec->ipackets,
           stats->ibytes,   per_sec->ibytes,
           stats->ipackets == 0 ? 0 : stats->ibytes / stats->ipackets,
           per_sec->ipackets == 0 ? 0 : per_sec->ibytes / per_sec->ipackets,
           stats->imissed,  per_sec->imissed,
           stats->opackets, per_sec->opackets,
           stats->obytes,   per_sec->obytes,
           stats->opackets == 0 ? 0 : stats->obytes / stats->opackets,
           per_sec->opackets == 0 ? 0 : per_sec->obytes / per_sec->opackets,
           stats->oerrors,  per_sec->oerrors);
}

static void
stats_ports_print_all(void)
{
    uint8_t port_id;

    printf("+---------------------------------------------------------------------"
           "----------------------------------------------------------------------"
           "------------------------------+\n"
           "| PORTS Rx/Tx                                                         "
           "                                                                      "
           "                              |\n"
           "+---------------------------------------------------------------------"
           "----------------------------------------------------------------------"
           "------------------------------+\n");

    for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        if (shadow_ports_sts->port_mask & (1 << port_id)) {
            stats_port_print(port_id,
                             &shadow_ports_sts->stats[port_id],
                             &per_sec_ports_sts->stats[port_id]);
        }
    }

    printf("+---------------------------------------------------------------------"
           "----------------------------------------------------------------------"
           "------------------------------+\n\n");
}

static void
init_shadow_mem_ports(void)
{
    /* grab pointers to mem locations of original stats */
    original_ports_sts = stats_capture_ports_get_mem_info();

    ports_sts_sz = sizeof(struct stats_ports);

    shadow_ports_sts= rte_zmalloc("ports_shadow_stats_capture",
                                  ports_sts_sz,
                                  RTE_CACHE_LINE_SIZE);

    if (NULL == shadow_ports_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate shadow mem for ports stats\n");

    shadow_ports_sts->port_mask = original_ports_sts->port_mask;
}

static void
init_temp_stats_mem(void)
{
    temp_ports_sts = rte_zmalloc("temp_ports_sts",
                                 ports_sts_sz,
                                 RTE_CACHE_LINE_SIZE);

    if (NULL == temp_ports_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate mem for temp ports stats\n");
}

static void
init_per_sec_stats_mem(void)
{
    per_sec_ports_sts = rte_zmalloc("per_sec_ports_sts",
                                    ports_sts_sz,
                                    RTE_CACHE_LINE_SIZE);

    if (NULL == per_sec_ports_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate mem for per sec ports stats\n");
}

void
sts_hdlr_ports_init(struct app_params *app)
{
    init_shadow_mem_ports();
    init_temp_stats_mem();
    init_per_sec_stats_mem();

    stats_refresh_period_s = app->stat_params.stats_refresh_period_global_ms / 1000;
}

void
sts_hdlr_ports_free(void)
{
    if (NULL != shadow_ports_sts)
        rte_free(shadow_ports_sts);

    if (NULL != temp_ports_sts)
        rte_free(temp_ports_sts);

    if (NULL != per_sec_ports_sts)
        rte_free(per_sec_ports_sts);
}

void
sts_hdlr_ports_capture(void)
{
    stats_capture_ports_get_stats();
}

void
sts_hdlr_ports_update_shadow_stats(void)
{
    rte_memcpy(shadow_ports_sts, original_ports_sts, ports_sts_sz);
}

void
sts_hdlr_ports_update_parsed_stats(void)
{
    uint8_t port_id;

    for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        if (shadow_ports_sts->port_mask & (1 << port_id)) {
            calculate_parsed_stats_ports(&temp_ports_sts->stats[port_id],
                                         &shadow_ports_sts->stats[port_id],
                                         &per_sec_ports_sts->stats[port_id]);
        }
    }

    rte_memcpy(temp_ports_sts, shadow_ports_sts, ports_sts_sz);
}

void
sts_hdlr_ports_clear_stats(void)
{
    stats_capture_ports_reset_stats();
    memset(original_ports_sts->stats,
           0,
           sizeof(struct rte_eth_stats) * RTE_MAX_ETHPORTS);
}

void
sts_hdlr_ports_print(enum rwpa_stats_lvl sts_lvl)
{
    switch (sts_lvl) {
    case RWPA_STS_LVL_PORTS_ONLY:
    case RWPA_STS_LVL_APP:
    case RWPA_STS_LVL_DETAILED:
        stats_ports_print_all();
        break;
    case RWPA_STS_LVL_OFF:
    default:
        break;
    }
}

struct stats_ports *
sts_hdlr_ports_get_mem_info_parsed(void)
{
    return shadow_ports_sts;
}
