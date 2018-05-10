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
#include "statistics_capture_crypto.h"
#include "cycle_capture.h"

static struct stats_crypto *stats_crypto = NULL;

/* flag that lets other components check if this class is ready for use */
static uint8_t is_stats_capture_crypto_initialised = 0;

void
stats_capture_crypto_init(__attribute__((unused)) struct app_params *app)
{
    unsigned i;

    if (is_stats_capture_crypto_initialised) {
        RTE_LOG(ERR, RWPA_STATS,
                "Attempted Crypto stats re-initialisation\n");
        return;
    }

    stats_crypto = rte_zmalloc("crypto_stats_capture",
                               STATS_CRYPTO_TYPE_U_DELIM *
                               sizeof(struct stats_crypto),
                               RTE_CACHE_LINE_SIZE);

    if (NULL == stats_crypto) {
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate mem for Crypto stats\n");
    }

    /* initialize driver_id with unknown value first */
    for (i = 0; i < STATS_CRYPTO_TYPE_U_DELIM; i++)
        stats_crypto[i].driver_id = 0xFF;

    is_stats_capture_crypto_initialised = 1;
}

void
stats_capture_crypto_free(void)
{
    if (NULL != stats_crypto)
        rte_free(stats_crypto);

    is_stats_capture_crypto_initialised = 0;
}

uint8_t
stats_capture_crypto_is_inited(void)
{
    return is_stats_capture_crypto_initialised;
}

struct stats_crypto *
stats_capture_crypto_get_mem_info(enum stats_crypto_type type)
{
    /*
     * if type is between the 2 limits, return pointer
     * to the specified type's stats struct
     */
    if (type > STATS_CRYPTO_TYPE_L_DELIM &&
        type < STATS_CRYPTO_TYPE_U_DELIM)
        return &(stats_crypto[type]);
    /*
     * otherwise, return pointer to stats memory
     * area
     */
    else
        return stats_crypto;
}

size_t
stats_capture_crypto_get_mem_info_size(void)
{
    return STATS_CRYPTO_TYPE_U_DELIM *
           sizeof(struct stats_crypto);
}

const char *
stats_capture_crypto_get_type_str(enum stats_crypto_type type)
{
    const char *str = "";

    switch (type) {
    case STATS_CRYPTO_TYPE_UL:
        str = "UPLINK";
        break;
    case STATS_CRYPTO_TYPE_DL:
        str = "DOWNLINK";
        break;
    default:
        str = "UNKNOWN";
        break;
    }

    return str;
}

#ifdef RWPA_CYCLE_CAPTURE
enum e_capture_funcs
stats_capture_crypto_get_enqueue_cycle_id(enum stats_crypto_type type)
{
    enum e_capture_funcs id = 0;

    switch (type) {
    case STATS_CRYPTO_TYPE_UL:
        id = CYCLE_CAPTURE_UL_CRYPTO_ENQUEUE;
        break;
    case STATS_CRYPTO_TYPE_DL:
        id = CYCLE_CAPTURE_DL_CRYPTO_ENQUEUE;
        break;
    default:
        id = 0;
        break;
    }

    return id;
}

enum e_capture_funcs
stats_capture_crypto_get_dequeue_cycle_id(enum stats_crypto_type type)
{
    enum e_capture_funcs id = 0;

    switch (type) {
    case STATS_CRYPTO_TYPE_UL:
        id = CYCLE_CAPTURE_UL_CRYPTO_DEQUEUE;
        break;
    case STATS_CRYPTO_TYPE_DL:
        id = CYCLE_CAPTURE_DL_CRYPTO_DEQUEUE;
        break;
    default:
        id = 0;
        break;
    }

    return id;
}
#endif
