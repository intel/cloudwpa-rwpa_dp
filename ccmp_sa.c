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

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cryptodev.h>

#include "app.h"
#include "r-wpa_global_vars.h"
#include "key.h"
#include "ccmp_sa.h"
#include "crypto.h"

/*
 * AAD Lengths
 */
#define AAD_LEN_22           22
#define AAD_LEN_24           24
#define AAD_LEN_28           28
#define AAD_LEN_30           30

/*
 * Number of CCMP ops and aad lengths
 */
#define OPS_NUM_MAX          2
#define AAD_LENGTHS_NUM_MAX  4

static enum rwpa_status
xform_init(enum ccmp_op                 op,
           uint8_t                     *tk,
           uint8_t                      tk_len,
           uint8_t                      aad_len,
           struct rte_crypto_sym_xform *xform);

static enum ccmp_sa_session_type
session_select(enum ccmp_op op,
               uint8_t      aad_len);

enum rwpa_status
ccmp_sa_init(const uint8_t  *tk,
             const uint8_t   tk_len,
             struct ccmp_sa *sa)
{
    enum ccmp_op ops[OPS_NUM_MAX] = {
                            CCMP_OP_ENCRYPT,
                            CCMP_OP_DECRYPT};
    uint8_t aad_lens[AAD_LENGTHS_NUM_MAX] = {
                            AAD_LEN_22,
                            AAD_LEN_24,
                            AAD_LEN_28,
                            AAD_LEN_30};
    enum ccmp_sa_session_type sess_type;
    unsigned i, j;

    /* check parameters */
    if (unlikely(tk == NULL ||
                 sa == NULL))
        return RWPA_STS_ERR;

    /* check the key length is valid */
    if (unlikely(!(tk_len == CCMP_128_KEY_LEN ||
                   tk_len == CCMP_256_KEY_LEN))) {
        RTE_LOG(DEBUG, RWPA_CCMP,
                "Invalid key length %d for CCMP\n",
                tk_len);
        return RWPA_STS_ERR;
    }

    /* store the key */
    rte_memcpy(sa->tk, tk, tk_len);
    sa->tk_len = tk_len;

    /* setup each of the crypto xforms and sessions */
    for (i = 0; i < OPS_NUM_MAX; i++) {
        for (j = 0; j < AAD_LENGTHS_NUM_MAX; j++) {
            sess_type = session_select(ops[i], aad_lens[j]);
            xform_init(ops[i], sa->tk, sa->tk_len, aad_lens[j], &(sa->xform[sess_type]));
            sa->session[sess_type] = crypto_session_alloc(&(sa->xform[sess_type]), ops[i]);
        }
    }

    return RWPA_STS_OK;
}

void
ccmp_sa_reset(struct ccmp_sa *sa)
{
    unsigned i;

    /* check parameters */
    if (unlikely(sa == NULL))
        return;

    /* free each of the crypto sessions */
    for (i = 0; i < CCMP_SESSION_TYPE_MAX; i++) {
        crypto_session_free(sa->session[i]);
    }

    memset(sa, 0, sizeof(struct ccmp_sa));
}

struct rte_cryptodev_sym_session *
ccmp_sa_session_select(struct ccmp_sa *sa,
                       enum ccmp_op    op,
                       uint8_t         aad_len)
{
    struct rte_cryptodev_sym_session *session;
    enum ccmp_sa_session_type type;

    if (unlikely(sa == NULL))
        return NULL;

    type  = session_select(op, aad_len);

    if (likely(type != CCMP_SESSION_TYPE_MAX))
        session = sa->session[type];
    else
        session = NULL;

    return session;
}

static enum rwpa_status
xform_init(enum ccmp_op                 op,
           uint8_t                     *tk,
           uint8_t                      tk_len,
           uint8_t                      aad_len,
           struct rte_crypto_sym_xform *xform)
{
    /* check parameters */
    if (unlikely(tk == NULL ||
                 xform == NULL))
        return RWPA_STS_ERR;

    xform->aead.op = (op == CCMP_OP_ENCRYPT ?
                           RTE_CRYPTO_AEAD_OP_ENCRYPT :
                           RTE_CRYPTO_AEAD_OP_DECRYPT);
    xform->aead.algo = RTE_CRYPTO_AEAD_AES_CCM;
    xform->aead.digest_length = tk_len >> 1;
    xform->aead.aad_length = aad_len;
    xform->aead.key.length = tk_len;
    xform->aead.key.data = tk;
    xform->aead.iv.offset = IV_OFFSET;
    xform->aead.iv.length = CCMP_NONCE_LEN;
    xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;
    xform->next = NULL;

    return RWPA_STS_OK;
}

static enum ccmp_sa_session_type
session_select(enum ccmp_op op,
               uint8_t      aad_len)
{
    enum ccmp_sa_session_type sess_type = CCMP_SESSION_TYPE_MAX;

    switch (op) {
    case CCMP_OP_ENCRYPT:
        switch (aad_len) {
        case AAD_LEN_22:
            sess_type = CCMP_SESSION_TYPE_E_AAD22;
            break;

        case AAD_LEN_24:
            sess_type = CCMP_SESSION_TYPE_E_AAD24;
            break;

        case AAD_LEN_28:
            sess_type = CCMP_SESSION_TYPE_E_AAD28;
            break;

        case AAD_LEN_30:
            sess_type = CCMP_SESSION_TYPE_E_AAD30;
            break;

        default:
            break;
        }
        break;

    case CCMP_OP_DECRYPT:
        switch (aad_len) {
        case AAD_LEN_22:
            sess_type = CCMP_SESSION_TYPE_D_AAD22;
            break;

        case AAD_LEN_24:
            sess_type = CCMP_SESSION_TYPE_D_AAD24;
            break;

        case AAD_LEN_28:
            sess_type = CCMP_SESSION_TYPE_D_AAD28;
            break;

        case AAD_LEN_30:
            sess_type = CCMP_SESSION_TYPE_D_AAD30;
            break;

        default:
            break;
        }
        break;

    default:
        break;
    }

    return sess_type;
}
