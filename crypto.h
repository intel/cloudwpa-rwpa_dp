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

#ifndef __INCLUDE_CRYPTO_H__
#define __INCLUDE_CRYPTO_H__

#include <rte_cryptodev.h>

#define CDEV_QUEUE_DESC  (2048)
#define CDEV_MP_NB_OBJS  (2048)
#define POOL_CACHE_SIZE  (128)

#define MAX_IV_LENGTH    (18) /* actually 13, but 18 for crypto API */
#define MAX_AAD_LENGTH   (32) /* actually 30, but rounded up */
#define IV_OFFSET        (sizeof(struct rte_crypto_op) + \
                          sizeof(struct rte_crypto_sym_op))
#define AAD_OFFSET       (IV_OFFSET + MAX_IV_LENGTH)

void
crypto_init(struct app_crypto_params *options, uint32_t max_sessions);

void
crypto_destroy(void);

struct rte_cryptodev_sym_session *
crypto_session_alloc(struct rte_crypto_sym_xform *xform, uint16_t qp);

void
crypto_session_free(struct rte_cryptodev_sym_session *sess);

enum rwpa_status
crypto_ops_alloc(uint32_t num_ops_alloc, struct rte_crypto_op **ops);

uint16_t
crypto_burst_enqueue(struct rte_crypto_op **ops, uint16_t nb_ops, uint16_t qp);

uint16_t
crypto_burst_dequeue(struct rte_crypto_op **ops, uint16_t nb_ops, uint16_t qp);

uint8_t
crypto_driver_id_get(void);

#endif // __INCLUDE_CRYPTO_H__
