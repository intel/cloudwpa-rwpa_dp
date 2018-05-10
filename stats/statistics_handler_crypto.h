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

#ifndef __INCLUDE_STATISTICS_HANDLER_CRYPTO_H__
#define __INCLUDE_STATISTICS_HANDLER_CRYPTO_H__

#include <rte_common.h>
#include <rte_malloc.h>

struct parsed_stats_crypto {
    uint64_t total_calls;
    uint64_t total_enqueue_calls;
    uint64_t total_dequeue_calls;

    uint64_t total_packets_enqueued;
    uint64_t total_packets_dequeued;

    uint64_t total_enqueue_errors;
    uint64_t total_dequeue_errors;

    float avg_packets_enqueued_per_call;
    float avg_packets_dequeued_per_call;

    uint64_t total_cycles;
    uint64_t total_enqueue_cycles;
    uint64_t total_dequeue_cycles;

    float avg_cycles_per_enqueue_call;
    float avg_cycles_per_dequeue_call;

    float avg_cycles_per_enqueued_packet;
    float avg_cycles_per_dequeued_packet;
};

void
sts_hdlr_crypto_init(struct app_params *app);

void
sts_hdlr_crypto_free(void);

void
sts_hdlr_crypto_update_shadow_stats(void);

void
sts_hdlr_crypto_update_parsed_stats(void);

void
sts_hdlr_crypto_clear_stats(void);

void
sts_hdlr_crypto_print(enum rwpa_stats_lvl);

struct parsed_stats_crypto *
sts_hdlr_crypto_get_mem_info_parsed(void);

#endif // __INCLUDE_STATISTICS_HANDLER_CRYPTO_H__
