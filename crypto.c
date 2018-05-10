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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_cryptodev.h>
#include <rte_malloc.h>
#include <rte_hexdump.h>

#include "app.h"
#include "r-wpa_global_vars.h"
#include "crypto.h"

#define CRYPTO_OP_PRIV_DATA_SIZE (sizeof(struct rte_crypto_sym_xform) + \
                                  MAX_IV_LENGTH + \
                                  MAX_AAD_LENGTH)
                                   
static struct rte_mempool *crypto_op_pool;
static struct rte_mempool *session_pool;

static uint8_t cdev_id = 0;
static uint8_t driver_id = 0xFF;

static int
cryptodev_init(struct app_crypto_params *params, uint32_t max_sessions);

static int
cryptodev_mask_check(struct app_crypto_params *params, uint8_t cdev_id);

static int
device_type_check(struct app_crypto_params *params,
                  struct rte_cryptodev_info *dev_info);

void
crypto_init(struct app_crypto_params *params, uint32_t max_sessions)
{
    int ret_val;

    /* create crypto operations pool */
    crypto_op_pool = rte_crypto_op_pool_create("crypto_op_pool",
                                               RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                                               CDEV_MP_NB_OBJS,
                                               POOL_CACHE_SIZE,
                                               CRYPTO_OP_PRIV_DATA_SIZE,
                                               rte_socket_id());

    if (crypto_op_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create crypto op pool\n");

    /* init crypto device */
    if ((ret_val = cryptodev_init(params, max_sessions)) < 0)
        rte_exit(EXIT_FAILURE, "Failed to initialize crypto devices\n");
    else
        cdev_id = (uint8_t)ret_val;
}

void
crypto_destroy(void)
{
    rte_cryptodev_stop(cdev_id);
}

struct rte_cryptodev_sym_session *
crypto_session_alloc(struct rte_crypto_sym_xform *xform, uint16_t qp)
{
    struct rte_cryptodev_sym_session *session;

    session = rte_cryptodev_sym_session_create(session_pool);
    if (unlikely(session == NULL)) {
        RTE_LOG(CRIT, RWPA_CRYPTO,
                "Failed to create crypto session\n");
    } else if (unlikely(rte_cryptodev_sym_session_init(
                            cdev_id, session, xform, session_pool) < 0)) {
        RTE_LOG(CRIT, RWPA_CRYPTO,
                "Failed to init crypto session\n");
        rte_cryptodev_sym_session_free(session);
        session = NULL;
    } else if (unlikely(rte_cryptodev_queue_pair_attach_sym_session(
                            cdev_id, qp, session) < 0)) {
        RTE_LOG(CRIT, RWPA_CRYPTO,
                "Session cannot be attached to qp %u\n",
                qp);
        rte_cryptodev_sym_session_free(session);
        session = NULL;
    }

    return session;
}

void
crypto_session_free(struct rte_cryptodev_sym_session *sess)
{
    if (sess != NULL) {
        rte_cryptodev_sym_session_clear(cdev_id, sess);
        rte_cryptodev_sym_session_free(sess);
    }
}

enum rwpa_status
crypto_ops_alloc(uint32_t num_ops_alloc, struct rte_crypto_op **ops)
{
    unsigned alloced, i;

    /*
     * allocate a bulk of crypto ops
     */
    alloced = rte_crypto_op_bulk_alloc(crypto_op_pool,
                                       RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                                       ops,
                                       num_ops_alloc);

    /*
     * log an error and free any ops that were alloc'ed if
     * all were not alloc'ed
     */
    if (alloced != num_ops_alloc) {
        RTE_LOG(CRIT, RWPA_CRYPTO,
                "Unable to allocate %d crypto ops\n", num_ops_alloc);

        for (i = 0; i < alloced; i++)
           rte_crypto_op_free(ops[i]);

        return RWPA_STS_ERR;
    }

    return RWPA_STS_OK;
}

uint16_t
crypto_burst_enqueue(struct rte_crypto_op **ops, uint16_t nb_ops, uint16_t qp)
{
    uint16_t nb_enq;

    if (unlikely(!nb_ops))
        return 0;

    /*
     * the rte_cryptodev_enqueue_burst() function returns the number
     * of operations enqueued for processing. A return value equal
     * to nb_ops means that all the packets have been enqueued
     */
    nb_enq = rte_cryptodev_enqueue_burst(cdev_id, qp, ops, nb_ops);

    RTE_LOG(DEBUG, RWPA_CRYPTO,
            "Enqueued %d crypto operations from %d requested "
            "to cryptodev %u queue %u,\n",
            nb_enq, nb_ops, cdev_id, qp);

    return nb_enq;
}

uint16_t
crypto_burst_dequeue(struct rte_crypto_op **ops, uint16_t nb_ops, uint16_t qp)
{
    uint16_t nb_deq;

    if (unlikely(!nb_ops))
        return 0;

    /*
     * dequeue from crypto device
     * - the max number of dequeued packets is nb_ops
     */
    nb_deq = rte_cryptodev_dequeue_burst(cdev_id, qp, ops, nb_ops);

    RTE_LOG(DEBUG, RWPA_CRYPTO,
            "Dequeued %d crypto operations from %d requested "
            "from cryptodev %u queue %u\n",
            nb_deq, nb_ops, cdev_id, qp);

    return nb_deq;
}

uint8_t
crypto_driver_id_get(void)
{
    return driver_id;
}

static int
cryptodev_init(struct app_crypto_params *params, uint32_t max_sessions)
{
    const struct rte_cryptodev_capabilities *cap;
    struct rte_cryptodev_config dev_conf;
    struct rte_cryptodev_qp_conf qp_conf;
    uint32_t i, cdev_id, cdev_count, sess_sz;
    uint16_t qp;
    int ret_val;

    cdev_count = rte_cryptodev_count();
    if (cdev_count == 0) {
        RTE_LOG(CRIT, RWPA_CRYPTO, "No crypto devices available\n");
        return -1;
    }

    for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
        struct rte_cryptodev_info dev_info;

        if (cryptodev_mask_check(params, (uint8_t)cdev_id))
            continue;

        rte_cryptodev_info_get(cdev_id, &dev_info);

        /*
         * check if device supports AES-CCM algo and is of
         * the preferred type
         */
        i = 0;
        cap = &dev_info.capabilities[i];
        while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
            if (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD) {
                if (cap->sym.aead.algo == RTE_CRYPTO_AEAD_AES_CCM) {
                    if (device_type_check(params, &dev_info) == 0)
                        break;
                }
            }
            cap = &dev_info.capabilities[++i];
        }

        if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED) {
            RTE_LOG(ERR, RWPA_CRYPTO,
                    "Algorithm %s not supported by cryptodev %u "
                    "or device not of preferred type (%s)\n",
                    rte_crypto_aead_algorithm_strings[RTE_CRYPTO_AEAD_AES_CCM],
                    cdev_id,
                    params->cdev_type_string);
        } else {
            /* suitable cryptodev has been found */
            driver_id = dev_info.driver_id;
            break;
        }
    }
    
    if (cdev_id == cdev_count) {
        RTE_LOG(CRIT, RWPA_CRYPTO,
                "No suitable %s cryptodev found to support %s algorithm\n",
                params->cdev_type_string,
                rte_crypto_aead_algorithm_strings[RTE_CRYPTO_AEAD_AES_CCM]);
        return -1;
    }

    sess_sz = rte_cryptodev_get_private_session_size(cdev_id);

    /*
     * Create enough objects for session headers and
     * device private data
     */
    session_pool = rte_mempool_create("session_pool",
                                      max_sessions * 2,
                                      sess_sz,
                                      POOL_CACHE_SIZE,
                                      0, NULL, NULL, NULL,
                                      NULL, rte_socket_id(),
                                      0);

    if (session_pool == NULL) {
        RTE_LOG(CRIT, RWPA_CRYPTO,
                "Cannot create session pool on socket %d\n",
                rte_socket_id());
        return -1;
    }

    dev_conf.socket_id = rte_cryptodev_socket_id(cdev_id);
    dev_conf.nb_queue_pairs = params->n_qp;

    ret_val = rte_cryptodev_configure(cdev_id, &dev_conf);
    if (ret_val < 0) {
        RTE_LOG(CRIT, RWPA_CRYPTO,
                "Failed to configure cryptodev %u\n",
                cdev_id);
        return -1;
    }

    qp_conf.nb_descriptors = CDEV_QUEUE_DESC;
    for (qp = 0; qp < dev_conf.nb_queue_pairs; qp++) {
        ret_val = rte_cryptodev_queue_pair_setup(cdev_id,
                                                 qp,
                                                 &qp_conf,
                                                 rte_socket_id(),
                                                 session_pool);
        if (ret_val < 0) {
            RTE_LOG(CRIT, RWPA_CRYPTO,
                    "Failed to setup queue pair %u on cryptodev %u\n",
                    qp,
                    cdev_id);
            return -1;
        }
    }

    ret_val = rte_cryptodev_start(cdev_id);
    if (ret_val < 0) {
        RTE_LOG(CRIT, RWPA_CRYPTO,
                "Failed to start device %u: error %d\n",
                cdev_id,
                ret_val);
        return -1;
    }

    return cdev_id;
}

/* check if the device is enabled by cryptodev_mask */
static int
cryptodev_mask_check(struct app_crypto_params *params, uint8_t cdev_id)
{
    if (params->cryptodev_mask & (1 << cdev_id))
        return 0;

    return -1;
}

/* check if device has to be HW/SW or any */
static int
device_type_check(struct app_crypto_params *params,
                  struct rte_cryptodev_info *dev_info)
{
    if (params->type == CDEV_TYPE_HW &&
        (dev_info->feature_flags & RTE_CRYPTODEV_FF_HW_ACCELERATED))
        return 0;
    if (params->type == CDEV_TYPE_SW &&
        !(dev_info->feature_flags & RTE_CRYPTODEV_FF_HW_ACCELERATED))
        return 0;
    if (params->type == CDEV_TYPE_ANY)
        return 0;

    return -1;
}
