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

#include <rte_log.h>
#include <rte_common.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>

#include "app.h"
#include "r-wpa_global_vars.h"
#include "statistics_capture_ports.h"

static struct stats_ports *stats_ports = NULL;
static uint8_t is_stats_capture_ports_initialised = 0;

void
stats_capture_ports_init(struct app_params *app)
{
    uint8_t port_id;

    if (is_stats_capture_ports_initialised) {
        RTE_LOG(ERR, RWPA_STATS,
                "Attempted ports stats re-initialisation\n");
        return;
    }

    stats_ports = rte_zmalloc("ports_stats_capture",
                              sizeof(struct stats_ports),
                              RTE_CACHE_LINE_SIZE);
    if (NULL == stats_ports)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate mem for port stats\n");

    stats_ports->port_mask = app->port_mask;

    for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        if (stats_ports->port_mask & (1 << port_id)) {
            rte_eth_stats_reset((uint8_t)port_id);
        }
    }

    is_stats_capture_ports_initialised = 1;
}

void
stats_capture_ports_free(void)
{
    if (NULL != stats_ports)
        rte_free(stats_ports);

    is_stats_capture_ports_initialised = 0;
}

uint8_t
stats_capture_ports_is_inited(void)
{
    return is_stats_capture_ports_initialised;
}

struct stats_ports *
stats_capture_ports_get_mem_info(void)
{
    return stats_ports;
}

void
stats_capture_ports_get_stats(void)
{
    uint8_t port_id;

    for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        if (stats_ports->port_mask & (1 << port_id)) {
            rte_eth_stats_get(port_id, &stats_ports->stats[port_id]);
        }
    }
}

void
stats_capture_ports_reset_stats(void)
{
    uint8_t port_id;

    for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        if (stats_ports->port_mask & (1 << port_id)) {
            rte_eth_stats_reset(port_id);
        }
    }
}
