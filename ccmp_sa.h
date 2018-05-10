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

#ifndef __INCLUDE_CCMP_SA_H__
#define __INCLUDE_CCMP_SA_H__

#include <rte_cryptodev.h>

#include "ccmp_defns.h"

/*
 * Session Types
 */
enum ccmp_sa_session_type {
    /* encrypt, with various AAD lengths */
    CCMP_SESSION_TYPE_E_AAD22 = 0,
    CCMP_SESSION_TYPE_E_AAD24,
    CCMP_SESSION_TYPE_E_AAD28,
    CCMP_SESSION_TYPE_E_AAD30,

    /* decrypt, with various AAD lengths */
    CCMP_SESSION_TYPE_D_AAD22,
    CCMP_SESSION_TYPE_D_AAD24,
    CCMP_SESSION_TYPE_D_AAD28,
    CCMP_SESSION_TYPE_D_AAD30,

    /* delimit */
    CCMP_SESSION_TYPE_MAX,
};

#define CCMP_MAX_SESSIONS (NUM_STA_MAX * CCMP_SESSION_TYPE_MAX) +   \
                          (NUM_VAP_MAX * CCMP_SESSION_TYPE_MAX * 2)

/*
 * CCMP SA
 */
struct ccmp_sa {
    uint8_t tk[KEY_LEN_MAX];
    uint8_t tk_len;

    struct rte_crypto_sym_xform xform[CCMP_SESSION_TYPE_MAX];

    struct rte_cryptodev_sym_session *session[CCMP_SESSION_TYPE_MAX];
};

enum rwpa_status
ccmp_sa_init(const uint8_t  *tk,
             const uint8_t   tk_len,
             struct ccmp_sa *sa);

void
ccmp_sa_reset(struct ccmp_sa *sa);

struct rte_cryptodev_sym_session *
ccmp_sa_session_select(struct ccmp_sa *sa,
                       enum ccmp_op    op,
                       uint8_t         aad_len);

#endif // __INCLUDE_CCMP_SA_H__
