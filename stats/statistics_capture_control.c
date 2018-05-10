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
#include "statistics_capture_control.h"

static struct stats_control_drops *stats_control_drops = NULL;

/* flag that lets other components check if this class is ready for use */
static uint8_t is_stats_capture_control_initialised = 0;

void
stats_capture_control_init(__attribute__((unused)) struct app_params *app)
{
    if (is_stats_capture_control_initialised) {
        RTE_LOG(ERR, RWPA_STATS,
                "Attempted Control stats re-initialisation\n");
        return;
    }

    stats_control_drops = rte_zmalloc("control_drops_stats_capture",
                                      sizeof(struct stats_control_drops),
                                      RTE_CACHE_LINE_SIZE);

    if (NULL == stats_control_drops)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate mem for Control Drop stats\n");

    is_stats_capture_control_initialised = 1;
}

void
stats_capture_control_free(void)
{
    if (NULL != stats_control_drops)
        rte_free(stats_control_drops);

    is_stats_capture_control_initialised = 0;
}

uint8_t
stats_capture_control_is_inited(void)
{
    return is_stats_capture_control_initialised;
}

struct stats_control_drops *
stats_capture_control_drops_get_mem_info(void)
{
    return stats_control_drops;
}

size_t
stats_capture_control_drops_get_mem_info_size(void)
{
    return sizeof(struct stats_control_drops);
}

void
stats_capture_control_drops_inc(enum stats_control_drops_type type,
                                uint64_t amt)
{
    if (is_stats_capture_control_initialised) {
        switch (type) {
        case STATS_CTRL_DROPS_TYPE_MSG_HANDLING_ERROR:
            stats_control_drops->msg_handling_error += amt;
            break;
        case STATS_CTRL_DROPS_TYPE_PACKET_DECAP_ERROR:
            stats_control_drops->packet_decap_error += amt;
            break;
        case STATS_CTRL_DROPS_TYPE_STATION_NOT_FOUND:
            stats_control_drops->station_not_found += amt;
            break;
        case STATS_CTRL_DROPS_TYPE_ENCRYPTION_ERROR:
            stats_control_drops->encryption_error += amt;
            break;
        case STATS_CTRL_DROPS_TYPE_PACKET_ENCAP_ERROR:
            stats_control_drops->packet_encap_error += amt;
            break;
        case STATS_CTRL_DROPS_TYPE_NO_AP_TUNNEL_PORT:
            stats_control_drops->no_ap_tunnel_port += amt;
            break;
        case STATS_CTRL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE:
            stats_control_drops->unexpected_packet_type += amt;
            break;
        default:
            break;
        }
    }

    return;
}
