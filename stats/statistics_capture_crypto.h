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

#ifndef __INCLUDE_STATISTICS_CAPTURE_CRYPTO_H__
#define __INCLUDE_STATISTICS_CAPTURE_CRYPTO_H__

enum stats_crypto_type {
    /* add new types after this one */
    STATS_CRYPTO_TYPE_L_DELIM = -1,

    STATS_CRYPTO_TYPE_UL,
    STATS_CRYPTO_TYPE_DL,

    /* add new types before this one */
    STATS_CRYPTO_TYPE_U_DELIM
};

struct stats_crypto {
    uint8_t driver_id;

    uint64_t call_num;

    uint64_t total_enqueue_calls;
    uint64_t total_dequeue_calls;

    uint64_t total_packets_enqueued;
    uint64_t total_packets_dequeued;

    uint64_t total_enqueue_errors;
    uint64_t total_dequeue_errors;

    uint64_t cycles_num;
    uint64_t total_enqueue_cycles;
    uint64_t total_dequeue_cycles;
};

void
stats_capture_crypto_init(struct app_params *app);

void
stats_capture_crypto_free(void);

uint8_t
stats_capture_crypto_is_inited(void);

struct stats_crypto *
stats_capture_crypto_get_mem_info(enum stats_crypto_type type);

size_t
stats_capture_crypto_get_mem_info_size(void);

const char *
stats_capture_crypto_get_type_str(enum stats_crypto_type type);

enum e_capture_funcs
stats_capture_crypto_get_enqueue_cycle_id(enum stats_crypto_type type);

enum e_capture_funcs
stats_capture_crypto_get_dequeue_cycle_id(enum stats_crypto_type type);

enum e_capture_funcs
stats_capture_crypto_get_cycle_id(enum stats_crypto_type type);

#endif // __INCLUDE_STATISTICS_CAPTURE_CRYPTO_H__
