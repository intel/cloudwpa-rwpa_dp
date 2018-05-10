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

#ifndef __INCLUDE_VAP_H__
#define __INCLUDE_VAP_H__


#include <rte_branch_prediction.h>
#include <rte_memcpy.h>
#include <rte_rwlock.h>
#include <rte_ip.h>

#include "key.h"
#include "counter.h"
#include "seq_num.h"
#include "ap_config.h"

#define _VAP_LOCK_T             rte_rwlock_t
#define _VAP_LOCK_INIT(lock)    rte_rwlock_init(&(lock))
#define _VAP_READ_LOCK(lock)    rte_rwlock_read_lock(&(lock))
#define _VAP_READ_UNLOCK(lock)  rte_rwlock_read_unlock(&(lock))
#define _VAP_WRITE_LOCK(lock)   rte_rwlock_write_lock(&(lock))
#define _VAP_WRITE_UNLOCK(lock) rte_rwlock_write_unlock(&(lock))

/*
 * vAP
 */
struct vap_elem {
    struct ether_addr address;

    struct ccmp_sa gtk1_sa;
    struct ccmp_sa gtk2_sa;

    counter_t gtk1_encrypt_ctr;
    counter_t gtk2_encrypt_ctr;

    uint8_t current_gtk_index;

    seq_num_t frag_seq_num;

    uint8_t tun_mac_set;
    struct ether_addr tun_mac;
    uint32_t tun_ip;
    uint16_t tun_port;

    _VAP_LOCK_T lock;
} __rte_cache_aligned;

/*
 * Init vAP
 */
static inline void
vap_init(struct vap_elem *vap)
{
    if (likely(vap != NULL)) {
        memset(&(vap->gtk1_sa), 0, sizeof(struct ccmp_sa));
        memset(&(vap->gtk2_sa), 0, sizeof(struct ccmp_sa));
        counter_set(&(vap->gtk1_encrypt_ctr), ENCRYPT_CTR_DEFAULT_VAL);
        counter_set(&(vap->gtk2_encrypt_ctr), ENCRYPT_CTR_DEFAULT_VAL);
        vap->current_gtk_index = 0;
        seq_num_set(&(vap->frag_seq_num), SEQ_NUM_DEFAULT_VAL);
        memset(&(vap->tun_mac), 0, sizeof(struct ether_addr));
        vap->tun_ip = IPv4(0,0,0,0);
        vap->tun_port = 0;
        vap->tun_mac_set = FALSE;
        _VAP_LOCK_INIT(vap->lock);
    }
}

/*
 * Lock vAP for Reads
 */
static inline void
vap_read_lock(struct vap_elem *vap)
{
    if (likely(vap != NULL))
        _VAP_READ_LOCK(vap->lock);
}

/*
 * Unlock vAP for Reads
 */
static inline void
vap_read_unlock(struct vap_elem *vap)
{
    if (likely(vap != NULL))
        _VAP_READ_UNLOCK(vap->lock);
}

/*
 * Lock vAP for Writes
 */
static inline void
vap_write_lock(struct vap_elem *vap)
{
    if (likely(vap != NULL))
        _VAP_WRITE_LOCK(vap->lock);
}

/*
 * Unlock vAP for Writes
 */
static inline void
vap_write_unlock(struct vap_elem *vap)
{
    if (likely(vap != NULL))
        _VAP_WRITE_UNLOCK(vap->lock);
}

/*
 * Reset vAP
 */
static inline void
vap_reset(struct vap_elem *vap)
{
    if (likely(vap != NULL)) {
        _VAP_WRITE_LOCK(vap->lock);
        ccmp_sa_reset(&(vap->gtk1_sa));
        ccmp_sa_reset(&(vap->gtk2_sa));
        counter_set(&(vap->gtk1_encrypt_ctr), ENCRYPT_CTR_DEFAULT_VAL);
        counter_set(&(vap->gtk2_encrypt_ctr), ENCRYPT_CTR_DEFAULT_VAL);
        vap->current_gtk_index = 0;
        seq_num_set(&(vap->frag_seq_num), SEQ_NUM_DEFAULT_VAL);
        memset(&(vap->tun_mac), 0, sizeof(struct ether_addr));
        vap->tun_ip = IPv4(0,0,0,0);
        vap->tun_port = 0;
        vap->tun_mac_set = FALSE;
        _VAP_WRITE_UNLOCK(vap->lock);
    }
}

/*
 * Set Tunnel MAC Address
 */
static inline void
vap_tun_mac_set(struct vap_elem *vap,
                const struct ether_addr *tun_mac)
{
    if (likely(vap != NULL)) {
        if (unlikely(vap->tun_mac_set == FALSE)) {
            ether_addr_copy(tun_mac, &(vap->tun_mac));
            vap->tun_mac_set = TRUE;
        }
    }
}

/*
 * Set Tunnel IP Address
 */
static inline void
vap_tun_ip_set(struct vap_elem *vap,
               const uint32_t tun_ip)
{
    if (likely(vap != NULL)) {
        if (unlikely(vap->tun_ip != tun_ip)) {
            vap->tun_ip = tun_ip;
        }
    }
}

/*
 * Set Tunnel Port
 */
static inline void
vap_tun_port_set(struct vap_elem *vap,
                 const uint16_t tun_port)
{
    if (likely(vap != NULL)) {
        if (unlikely(vap->tun_port != tun_port)) {
            vap->tun_port = tun_port;
        }
    }
}

/*
 * Set Address
 */
static inline void
vap_address_set(struct vap_elem *vap,
                const struct ether_addr *addr,
                const struct ether_addr *def_tun_mac,
                const uint32_t def_tun_ip,
                const uint16_t def_tun_port)
{
    struct ether_addr tun_mac = { .addr_bytes={0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
    uint32_t tun_ip = def_tun_ip;
    uint16_t tun_port = def_tun_port;

    if (likely(def_tun_mac != NULL)) {
        ether_addr_copy(def_tun_mac, &tun_mac);
    }

    if (likely(vap != NULL && addr != NULL)) {
        if (ap_config_get(*addr, &tun_mac, &tun_ip, &tun_port))
            RTE_LOG(WARNING, RWPA_STORE,
                    "vAP %02x:%02x:%02x:%02x:%02x:%02x is not preconfigured in AP config file, "
                    "using default AP tunnel addresses\n",
                    addr->addr_bytes[0],
                    addr->addr_bytes[1],
                    addr->addr_bytes[2],
                    addr->addr_bytes[3],
                    addr->addr_bytes[4],
                    addr->addr_bytes[5]);

        _VAP_WRITE_LOCK(vap->lock);
        ether_addr_copy(addr, &(vap->address));
        vap_tun_mac_set(vap, &tun_mac);
        vap_tun_ip_set(vap, tun_ip);
        vap_tun_port_set(vap, tun_port);
#ifndef RWPA_DYNAMIC_AP_CONF_UPDATE_OFF
        /* set flag to false to allow dynamic update happen */
        vap->tun_mac_set = FALSE;
#endif
        _VAP_WRITE_UNLOCK(vap->lock);
    }
}

/*
 * Set GTK
 */
static inline void
vap_gtk_set(struct vap_elem *vap,
            uint8_t gtk_index,
            const uint8_t *gtk,
            const uint8_t gtk_len,
            uint8_t set_current_idx)
{
    struct ccmp_sa *set_gtk_sa = NULL;

    if (likely(vap != NULL && gtk != NULL)) {
        if (gtk_index == GTK1) {
            set_gtk_sa = &(vap->gtk1_sa);
        } else if (gtk_index == GTK2) {
            set_gtk_sa = &(vap->gtk2_sa);
        }

        if (likely(set_gtk_sa != NULL)) {
            _VAP_WRITE_LOCK(vap->lock);
            ccmp_sa_reset(set_gtk_sa);
            ccmp_sa_init(gtk, gtk_len, set_gtk_sa);
            counter_set(&(vap->gtk1_encrypt_ctr), ENCRYPT_CTR_DEFAULT_VAL);
            counter_set(&(vap->gtk2_encrypt_ctr), ENCRYPT_CTR_DEFAULT_VAL);
            if (set_current_idx)
                vap->current_gtk_index = gtk_index;
            _VAP_WRITE_UNLOCK(vap->lock);
        }
    }
}

/*
 * Select GTK Counter
 */
static inline counter_t *
vap_gtk_counter_select(struct vap_elem *vap, uint8_t gtk_idx)
{
    counter_t *ctr;

    switch(gtk_idx) {
        case GTK1:
            ctr = &(vap->gtk1_encrypt_ctr);
            break;
        case GTK2:
            ctr = &(vap->gtk2_encrypt_ctr);
            break;
        default:
            ctr = NULL;
            break;
    }

    return ctr;
}

/*
 * Get Current GTK Counter
 */
static inline counter_val_t
vap_current_gtk_counter_get(struct vap_elem *vap)
{
    counter_t *ctr;
    counter_val_t val = 0;

    if (likely(vap != NULL)) {
        ctr = vap_gtk_counter_select(vap, vap->current_gtk_index);
        if (likely(ctr != NULL))
            val = counter_get(ctr);
    }

    return val;
}

/*
 * Get GTK1 Encrypt Data
 * - read lock must be taken before calling this function
 */
static inline void
vap_gtk1_encrypt_data_get(struct vap_elem *vap,
                          struct ccmp_sa **sa,
                          counter_val_t *ctr)
{
    if (likely(vap != NULL && sa != NULL && ctr != NULL)) {
        *sa = &(vap->gtk1_sa);
        *ctr = counter_increment(&(vap->gtk1_encrypt_ctr));
    }
}

/*
 * Get GTK2 Encrypt Data
 * - read lock must be taken before calling this function
 */
static inline void
vap_gtk2_encrypt_data_get(struct vap_elem *vap,
                          struct ccmp_sa **sa,
                          counter_val_t *ctr)
{
    if (likely(vap != NULL && sa != NULL && ctr != NULL)) {
        *sa = &(vap->gtk2_sa);
        *ctr = counter_increment(&(vap->gtk2_encrypt_ctr));
    }
}

/*
 * Get Next Frag Sequence Number
 */
static inline seq_num_val_t
vap_next_frag_seq_num_get(struct vap_elem *vap)
{
    if (likely(vap != NULL))
        return (seq_num_val_t)seq_num_increment(&(vap->frag_seq_num));

    return (seq_num_val_t)0;
}

#endif // __INCLUDE_VAP_H__
