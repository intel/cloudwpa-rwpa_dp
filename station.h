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

#ifndef __INCLUDE_STATION_H__
#define __INCLUDE_STATION_H__

#include <rte_branch_prediction.h>
#include <rte_memcpy.h>
#include <rte_rwlock.h>

#include "key.h"
#include "counter.h"
#include "vap.h"

#define TID_NUM  9

#define _STA_LOCK_T             rte_rwlock_t
#define _STA_LOCK_INIT(lock)    rte_rwlock_init(&(lock))
#define _STA_READ_LOCK(lock)    rte_rwlock_read_lock(&(lock))
#define _STA_READ_UNLOCK(lock)  rte_rwlock_read_unlock(&(lock))
#define _STA_WRITE_LOCK(lock)   rte_rwlock_write_lock(&(lock))
#define _STA_WRITE_UNLOCK(lock) rte_rwlock_write_unlock(&(lock))

/*
 * Station
 */
struct sta_elem {
    struct ccmp_sa ptk_sa;

    counter_t ptk_encrypt_ctr;
    counter_t ptk_decrypt_ctr[TID_NUM];

    struct vap_elem *parent_vap;

    _STA_LOCK_T lock;
} __rte_cache_aligned;

/*
 * Init STA
 */
static inline void
sta_init(struct sta_elem *sta)
{
    unsigned int i;

    if (likely(sta != NULL)) {
        memset(&(sta->ptk_sa), 0, sizeof(struct ccmp_sa));
        counter_set(&(sta->ptk_encrypt_ctr), ENCRYPT_CTR_DEFAULT_VAL);
        for (i = 0; i < TID_NUM; i++)
            counter_set(&(sta->ptk_decrypt_ctr[i]), DECRYPT_CTR_DEFAULT_VAL);
        sta->parent_vap = NULL;
        _STA_LOCK_INIT(sta->lock);
    }
}

/*
 * Lock Station for Reads
 */
static inline void
sta_read_lock(struct sta_elem *sta)
{
    if (likely(sta != NULL))
        _STA_READ_LOCK(sta->lock);
}

/*
 * Unlock Station for Reads
 */
static inline void
sta_read_unlock(struct sta_elem *sta)
{
    if (likely(sta != NULL))
        _STA_READ_UNLOCK(sta->lock);
}

/*
 * Lock Station for Writes
 */
static inline void
sta_write_lock(struct sta_elem *sta)
{
    if (likely(sta != NULL))
        _STA_WRITE_LOCK(sta->lock);
}

/*
 * Unlock Station for Writes
 */
static inline void
sta_write_unlock(struct sta_elem *sta)
{
    if (likely(sta != NULL))
        _STA_WRITE_UNLOCK(sta->lock);
}

/*
 * Reset Station
 */
static inline void
sta_reset(struct sta_elem *sta)
{
    unsigned i;

    if (likely(sta != NULL)) {
        _STA_WRITE_LOCK(sta->lock);
        ccmp_sa_reset(&(sta->ptk_sa));
        counter_set(&(sta->ptk_encrypt_ctr), ENCRYPT_CTR_DEFAULT_VAL);
        for (i = 0; i < TID_NUM; i++)
            counter_set(&(sta->ptk_decrypt_ctr[i]), DECRYPT_CTR_DEFAULT_VAL);
        sta->parent_vap = NULL;
        _STA_WRITE_UNLOCK(sta->lock);
    }
}

/*
 * Set PTK
 */
static inline void
sta_ptk_set(struct sta_elem *sta, const uint8_t *ptk, const uint8_t ptk_len)
{
    unsigned int i;

    if (likely(sta != NULL && ptk != NULL)) {
        _STA_WRITE_LOCK(sta->lock);
        ccmp_sa_reset(&(sta->ptk_sa));
        ccmp_sa_init(ptk, ptk_len, &(sta->ptk_sa));
        counter_set(&(sta->ptk_encrypt_ctr), ENCRYPT_CTR_DEFAULT_VAL);
        for (i = 0; i < TID_NUM; i++)
            counter_set(&(sta->ptk_decrypt_ctr[i]), DECRYPT_CTR_DEFAULT_VAL);
        _STA_WRITE_UNLOCK(sta->lock);
    }
}

/*
 * Set PTK Decrypt Counter
 */
static inline void
sta_ptk_decrypt_counter_set(struct sta_elem *sta, uint8_t tid, counter_val_t value)
{
    UNUSED(value);
    if (likely(sta != NULL && tid < TID_NUM)) {
        counter_set(&(sta->ptk_decrypt_ctr[tid]), value);
    }
}

/*
 * Get Encrypt Data
 * - read lock must be taken before calling this function
 */
static inline void
sta_encrypt_data_get(struct sta_elem *sta,
                     struct ccmp_sa **sa,
                     counter_val_t *ctr,
                     struct vap_elem **vap)
{
    if (likely(sta != NULL && sa != NULL &&
               ctr != NULL && vap != NULL)) {
        *sa = &(sta->ptk_sa);
        *ctr = counter_increment(&(sta->ptk_encrypt_ctr));
        *vap = sta->parent_vap;
    }
}

/*
 * Get Decrypt Data
 * - read lock must be taken before calling this function
 */
static inline void
sta_decrypt_data_get(struct sta_elem *sta,
                     uint8_t tid,
                     struct ccmp_sa **sa,
                     counter_val_t *ctr,
                     struct vap_elem **vap)
{
    if (likely(sta != NULL && sa != NULL && ctr != NULL &&
               vap != NULL && tid < TID_NUM)) {
        *sa = &(sta->ptk_sa);
        *ctr = counter_get(&(sta->ptk_decrypt_ctr[tid]));
        *vap = sta->parent_vap;
    }
}

#endif // __INCLUDE_STATION_H__
