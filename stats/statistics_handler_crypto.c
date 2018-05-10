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
#include <rte_cryptodev.h>

#include "app.h"
#include "statistics_capture_crypto.h"
#include "statistics_handler_crypto.h"
#include "cycle_capture.h"

/* reference to original mem locations of Crypto stats */
static struct stats_crypto *original_crypto_sts = NULL;

/* 
 * mem where shadow copy of original data is kept.
 * - memcpy is performed between original and shadow copy regions, as
 *   original stat counters change continuously as application runs
 */
static struct stats_crypto *shadow_crypto_sts = NULL;
static size_t shadow_crypto_sts_sz = 0;

static struct parsed_stats_crypto *parsed_crypto_sts = NULL;

static void
init_parsed_stats_mem(void)
{
    parsed_crypto_sts = rte_zmalloc("crypto_parsed_stats",
                                    STATS_CRYPTO_TYPE_U_DELIM *
                                    sizeof(struct parsed_stats_crypto),
                                    RTE_CACHE_LINE_SIZE);

    if (NULL == parsed_crypto_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate parsed mem for Crypto stats\n");
}

static void
init_shadow_mem_crypto(void)
{
    /* grab pointers to mem locations of original stats */
    original_crypto_sts =
        stats_capture_crypto_get_mem_info(STATS_CRYPTO_TYPE_L_DELIM);
    shadow_crypto_sts_sz = stats_capture_crypto_get_mem_info_size();

    /*
     * allocate memory for shadow stats, during the runtime original stats
     * will be 'memcpy' to this memory in order to process the most current
     * snapshot of stats.
     */
    shadow_crypto_sts = rte_zmalloc("crypto_shadow_stats_capture",
                                     shadow_crypto_sts_sz,
                                     RTE_CACHE_LINE_SIZE);

    if (NULL == shadow_crypto_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate shadow mem for Crypto stats\n");
}

static void
calculate_parsed_stats_crypto(enum stats_crypto_type type)
{
    struct parsed_stats_crypto *p;
    struct stats_crypto *o;

    /* check param */
    if (type <= STATS_CRYPTO_TYPE_L_DELIM ||
        type >= STATS_CRYPTO_TYPE_U_DELIM)
        return;

    p = &(parsed_crypto_sts[type]);
    o = &(shadow_crypto_sts[type]);

    p->total_calls = o->call_num;

    p->total_cycles = o->cycles_num;
    p->total_enqueue_cycles = o->total_enqueue_cycles;
    p->total_dequeue_cycles = o->total_dequeue_cycles;

    p->total_enqueue_calls = o->total_enqueue_calls;
    p->total_dequeue_calls = o->total_dequeue_calls;

    p->total_packets_enqueued = o->total_packets_enqueued;
    p->total_packets_dequeued = o->total_packets_dequeued;

    p->total_enqueue_errors = o->total_enqueue_errors;
    p->total_dequeue_errors = o->total_dequeue_errors;

    if (p->total_enqueue_calls) {
        p->avg_packets_enqueued_per_call = ((float) p->total_packets_enqueued) / p->total_enqueue_calls;
        p->avg_cycles_per_enqueue_call = ((float) p->total_enqueue_cycles) / p->total_enqueue_calls;
    }

    if (p->total_dequeue_calls) {
        p->avg_packets_dequeued_per_call = ((float) p->total_packets_dequeued) / p->total_dequeue_calls;
        p->avg_cycles_per_dequeue_call = ((float) p->total_dequeue_cycles) / p->total_dequeue_calls;
    }

    if (p->total_packets_enqueued)
        p->avg_cycles_per_enqueued_packet = ((float) p->total_enqueue_cycles) / p->total_packets_enqueued;

    if (p->total_packets_dequeued)
        p->avg_cycles_per_dequeued_packet = ((float) p->total_dequeue_cycles) / p->total_packets_dequeued;
}

static void
print_parsed_stats_crypto(enum stats_crypto_type type)
{
    struct parsed_stats_crypto *p;
    struct stats_crypto *o;
    const char *driver_name;

    /* check param */
    if (type <= STATS_CRYPTO_TYPE_L_DELIM ||
        type >= STATS_CRYPTO_TYPE_U_DELIM)
        return;

    p = &(parsed_crypto_sts[type]);
    o = &(shadow_crypto_sts[type]);

    printf("| %-120s |\n"
           "+--------------------------------------------------------------------------------------------------------------------------+\n",
           stats_capture_crypto_get_type_str(type));

    driver_name = rte_cryptodev_driver_name_get(o->driver_id);

    if (!p->total_packets_enqueued &&
        !p->total_enqueue_errors) {
        if (o->driver_id == 0xFF)
            printf("| NO PACKETS ENQUEUED FOR DEVICE                                                                                           |\n");
        else if (strncmp(driver_name, "crypto_openssl", strlen("crypto_openssl")) == 0)
            printf("| NO PACKETS ENQUEUED FOR DEVICE (crypto_openssl)                                                                          |\n");
        else if (strncmp(driver_name, "crypto_aesni_mb", strlen("crypto_aesni_mb")) == 0)
            printf("| NO PACKETS ENQUEUED FOR DEVICE (crypto_aesni_mb)                                                                         |\n");
        else
            printf("| NO PACKETS ENQUEUED FOR DEVICE (unknown)                                                                                 |\n");
        printf("+--------------------------------------------------------------------------------------------------------------------------+\n");
    } else {
        if (strncmp(driver_name, "crypto_openssl", strlen("crypto_openssl")) == 0)
            printf("| ENQUEUE (PACKETS) DEVICE (crypto_openssl)                                                                                |\n");
        else if (strncmp(driver_name, "crypto_aesni_mb", strlen("crypto_aesni_mb")) == 0)
            printf("| ENQUEUE (PACKETS) DEVICE (crypto_aesni_mb)                                                                               |\n");
        else
            printf("| ENQUEUE (PACKETS) DEVICE (unknown)                                                                                       |\n");

        printf("+--------------------------------------------------------------------------------------------------------------------------+\n"
               "|    Enqueue calls    |    Packets enqueued    |    Enqueue errors    | Average number of packets enqueued per crypto call |\n"
               "+--------------------------------------------------------------------------------------------------------------------------+\n"
               "|%20lu |%23lu |%21lu |%51f |\n"
               "+--------------------------------------------------------------------------------------------------------------------------+\n",
               p->total_enqueue_calls,
               p->total_packets_enqueued,
               p->total_enqueue_errors,
               p->avg_packets_enqueued_per_call);
    }

    if (p->total_enqueue_calls) {
        printf("| ENQUEUE (CYCLES)                                                                                                         |\n"
               "+--------------------------------------------------------------------------------------------------------------------------+\n"
               "| Total enqueue calls | Total enqueue cycles | Average cycles per crypto enqueue call | Average cycles per enqueued packet |\n"
               "+--------------------------------------------------------------------------------------------------------------------------+\n"
               "|%20lu |%21lu |%39f |%35f |\n"
               "+--------------------------------------------------------------------------------------------------------------------------+\n",
               p->total_enqueue_calls,
               p->total_enqueue_cycles,
               p->avg_cycles_per_enqueue_call,
               p->avg_cycles_per_enqueued_packet);
    }

    if (!p->total_packets_dequeued &&
        !p->total_dequeue_errors) {
        if (o->driver_id == 0xFF)
            printf("| NO PACKETS DEQUEUED FOR DEVICE                                                                                           |\n");
        else if (strncmp(driver_name, "crypto_openssl", strlen("crypto_openssl")) == 0)
            printf("| NO PACKETS DEQUEUED FOR DEVICE (crypto_openssl)                                                                          |\n");
        else if (strncmp(driver_name, "crypto_aesni_mb", strlen("crypto_aesni_mb")) == 0)
            printf("| NO PACKETS DEQUEUED FOR DEVICE (crypto_aesni_mb)                                                                         |\n");
        else
            printf("| NO PACKETS DEQUEUED FOR DEVICE (unknown)                                                                                 |\n");
        printf("+--------------------------------------------------------------------------------------------------------------------------+\n");
    } else {
        if (strncmp(driver_name, "crypto_openssl", strlen("crypto_openssl")) == 0)
            printf("| DEQUEUE (PACKETS) DEVICE (crypto_openssl)                                                                                |\n");
        else if (strncmp(driver_name, "crypto_aesni_mb", strlen("crypto_aesni_mb")) == 0)
            printf("| DEQUEUE (PACKETS) DEVICE (crypto_aesni_mb)                                                                               |\n");
        else
            printf("| DEQUEUE (PACKETS) DEVICE (unknown)                                                                                       |\n");

        printf("+--------------------------------------------------------------------------------------------------------------------------+\n"
               "|    Dequeue calls    |    Packets dequeued    |    Dequeue errors    | Average number of packets dequeued per crypto call |\n"
               "+--------------------------------------------------------------------------------------------------------------------------+\n"
               "|%20lu |%23lu |%21lu |%51f |\n"
               "+--------------------------------------------------------------------------------------------------------------------------+\n",
               p->total_dequeue_calls,
               p->total_packets_dequeued,
               p->total_dequeue_errors,
               p->avg_packets_dequeued_per_call);
    }

    if (p->total_dequeue_calls) {
        printf("| DEQUEUE (CYCLES)                                                                                                         |\n"
               "+--------------------------------------------------------------------------------------------------------------------------+\n"
               "| Total dequeue calls | Total dequeue cycles | Average cycles per crypto dequeue call | Average cycles per dequeued packet |\n"
               "+--------------------------------------------------------------------------------------------------------------------------+\n"
               "|%20lu |%21lu |%39f |%35f |\n"
               "+--------------------------------------------------------------------------------------------------------------------------+\n",
               p->total_dequeue_calls,
               p->total_dequeue_cycles,
               p->avg_cycles_per_dequeue_call,
               p->avg_cycles_per_dequeued_packet);
    }
}

void
sts_hdlr_crypto_init(__attribute__((unused)) struct app_params *app)
{
    init_shadow_mem_crypto();
    init_parsed_stats_mem();
}

void
sts_hdlr_crypto_free(void)
{
    if (NULL != shadow_crypto_sts) {
        rte_free(shadow_crypto_sts);
    }

    if (NULL != parsed_crypto_sts) {
        rte_free(parsed_crypto_sts);
    }
}

void
sts_hdlr_crypto_update_shadow_stats(void)
{
    unsigned i;

    /* simple struct copy - no underlying pointers, just plain data */
    rte_memcpy(shadow_crypto_sts, original_crypto_sts, shadow_crypto_sts_sz);
    for (i = 0; i < STATS_CRYPTO_TYPE_U_DELIM; i++) {
        shadow_crypto_sts[i].total_enqueue_cycles =
            CYCLE_CAPTURE_GET_TOTAL_CYCLES(stats_capture_crypto_get_enqueue_cycle_id(i));
        shadow_crypto_sts[i].total_dequeue_cycles =
            CYCLE_CAPTURE_GET_TOTAL_CYCLES(stats_capture_crypto_get_dequeue_cycle_id(i));
    }
}

void
sts_hdlr_crypto_update_parsed_stats(void)
{
    unsigned i;

    for (i = 0; i < STATS_CRYPTO_TYPE_U_DELIM; i++)
        calculate_parsed_stats_crypto(i);
}

void
sts_hdlr_crypto_clear_stats(void)
{
    memset(original_crypto_sts, 0, shadow_crypto_sts_sz);
    memset(parsed_crypto_sts,
           0,
           sizeof(parsed_crypto_sts[0]) * STATS_CRYPTO_TYPE_U_DELIM);
}

void
sts_hdlr_crypto_print(enum rwpa_stats_lvl sts_lvl)
{
    unsigned i;

    printf("+--------------------------------------------------------------------------------------------------------------------------+\n"
           "| CRYPTO                                                                                                                   |\n"
           "+--------------------------------------------------------------------------------------------------------------------------+\n");

    switch (sts_lvl) {
    case RWPA_STS_LVL_APP:
    case RWPA_STS_LVL_DETAILED:
        for (i = 0; i < STATS_CRYPTO_TYPE_U_DELIM; i++)
            print_parsed_stats_crypto(i);
        break;
    case RWPA_STS_LVL_OFF:
    case RWPA_STS_LVL_PORTS_ONLY:
    default:
        break;
    }

    printf("\n");
}

struct parsed_stats_crypto *
sts_hdlr_crypto_get_mem_info_parsed(void)
{
    return parsed_crypto_sts;
}
