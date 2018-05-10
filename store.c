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
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_rwlock.h>

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC rte_jhash
#endif

#include "r-wpa_global_vars.h"
#include "app.h"
#include "key.h"
#include "ccmp_sa.h"
#include "vap.h"
#include "station.h"
#include "store.h"

static struct app_addr_params *addr_params;

static struct rte_hash *vap_store = NULL;
static struct rte_hash *sta_store = NULL;

static struct vap_elem vaps[NUM_VAP_MAX];
static struct sta_elem stas[NUM_STA_MAX];

#ifndef RWPA_STORE_NO_LOCKS
static rte_rwlock_t vap_store_lock = RTE_RWLOCK_INITIALIZER;
static rte_rwlock_t sta_store_lock = RTE_RWLOCK_INITIALIZER;

#define STORE_READ_LOCK(lock)    rte_rwlock_read_lock(&(lock))
#define STORE_READ_UNLOCK(lock)  rte_rwlock_read_unlock(&(lock))
#define STORE_WRITE_LOCK(lock)   rte_rwlock_write_lock(&(lock))
#define STORE_WRITE_UNLOCK(lock) rte_rwlock_write_unlock(&(lock))
#else
#define STORE_READ_LOCK(lock)
#define STORE_READ_UNLOCK(lock)
#define STORE_WRITE_LOCK(lock)
#define STORE_WRITE_UNLOCK(lock)
#endif

void
store_init(int socket_id, struct app_addr_params *app_addr_params)
{
    char name[RTE_HASH_NAMESIZE];
    int i;

    snprintf(name, sizeof(name), "vap_store_%d", socket_id);
    struct rte_hash_parameters vap_store_hash_params = {
            .name = name,
            .entries = NUM_VAP_MAX,
            .socket_id = socket_id,
            .key_len = sizeof(struct ether_addr)
    };

    vap_store = rte_hash_create(&vap_store_hash_params);
    if (vap_store == NULL)
        rte_exit(EXIT_FAILURE, "Error creating vAP store, exiting\n");

    snprintf(name, sizeof(name), "sta_store_%d", socket_id);
    struct rte_hash_parameters sta_store_hash_params = {
            .name = name,
            .entries = NUM_STA_MAX,
            .socket_id = socket_id,
            .key_len = sizeof(struct ether_addr)
    };

    sta_store = rte_hash_create(&sta_store_hash_params);
    if (sta_store == NULL)
        rte_exit(EXIT_FAILURE, "Error creating Station store, exiting\n");

    memset(&vaps, 0x0, sizeof(vaps));
    memset(&stas, 0x0, sizeof(stas));

    for (i = 0; i < NUM_VAP_MAX; i++)
       vap_init(&vaps[i]);

    for (i = 0; i < NUM_STA_MAX; i++)
       sta_init(&stas[i]);

    addr_params = app_addr_params;
}

void
store_cleanup(void)
{
    rte_hash_free(vap_store);
    rte_hash_free(sta_store);
}

struct vap_elem *
store_vap_add(struct ether_addr *vap_addr)
{
    int32_t index;

    /* check params */
    if (vap_addr == NULL) {
        RTE_LOG(ERR, RWPA_STORE, "Invalid parameters to %s\n", __FUNCTION__);
        return NULL;
    }

    STORE_WRITE_LOCK(vap_store_lock);
    if ((index = rte_hash_add_key(vap_store, vap_addr)) < 0) {
        STORE_WRITE_UNLOCK(vap_store_lock);
        RTE_LOG(ERR, RWPA_STORE, "Error adding entry to vAP store\n");
        return NULL;
    }
    STORE_WRITE_UNLOCK(vap_store_lock);

    vap_address_set(&(vaps[index]), vap_addr,
                    &(addr_params->vap_tun_def_mac),
                    addr_params->vap_tun_def_ip,
                    addr_params->vap_tun_def_port);

    return &(vaps[index]);
}

struct vap_elem *
store_vap_lookup(struct ether_addr *vap_addr)
{
    int32_t index;

    STORE_READ_LOCK(vap_store_lock);
    index = rte_hash_lookup(vap_store, vap_addr);
    STORE_READ_UNLOCK(vap_store_lock);

    if (likely(index >= 0))
        return &(vaps[index]);

    return NULL;
}

struct vap_elem *
store_vap_get(int32_t index)
{
    if (likely(index < NUM_VAP_MAX))
        return &(vaps[index]);

    return NULL;
}

void
store_vap_bulk_lookup(struct ether_addr **vap_addr, uint32_t num_keys, int32_t *found)
{
    STORE_READ_LOCK(vap_store_lock);
    rte_hash_lookup_bulk(vap_store, (const void **)vap_addr, num_keys, found);
    STORE_READ_UNLOCK(vap_store_lock);
}

enum rwpa_status
store_vap_del(struct ether_addr *vap_addr)
{
    int32_t index;

    STORE_WRITE_LOCK(vap_store_lock);
    index = rte_hash_del_key(vap_store, vap_addr);
    STORE_WRITE_UNLOCK(vap_store_lock);

    if (likely(index >= 0)) {
       vap_reset(&(vaps[index]));
       return RWPA_STS_OK;
    }

    return RWPA_STS_ERR;
}

struct sta_elem *
store_sta_add(struct ether_addr *sta_addr, struct ether_addr *vap_addr)
{
    struct vap_elem *vap;
    int32_t index = 0;

    /* check params */
    if (sta_addr == NULL || vap_addr == NULL) {
        RTE_LOG(ERR, RWPA_STORE, "Invalid parameters to %s\n", __FUNCTION__);
        return NULL;
    }

    /* lookup parent vap */
    vap = store_vap_lookup(vap_addr);
    if (likely(vap != NULL)) {
        /* add the station to the store */
        STORE_WRITE_LOCK(sta_store_lock);
        if ((index = rte_hash_add_key(sta_store, sta_addr)) < 0) {
            STORE_WRITE_UNLOCK(sta_store_lock);
            RTE_LOG(ERR, RWPA_STORE, "Error adding entry to Station store\n");
            return NULL;
        }
        STORE_WRITE_UNLOCK(sta_store_lock);

        /* assign parent vap */
        stas[index].parent_vap = vap;
    } else {
        RTE_LOG(ERR, RWPA_STORE, "vAP not found when adding station to store\n");
        return NULL;
    }

    return &(stas[index]);
}

struct sta_elem *
store_sta_lookup(struct ether_addr *sta_addr)
{
    int32_t index;

    STORE_READ_LOCK(sta_store_lock);
    index = rte_hash_lookup(sta_store, sta_addr);
    STORE_READ_UNLOCK(sta_store_lock);

    if (likely(index >= 0))
        return &(stas[index]);

    return NULL;
}

struct sta_elem *
store_sta_get(int32_t index)
{
    if (likely(index < NUM_STA_MAX))
        return &(stas[index]);

    return NULL;
}

void
store_sta_bulk_lookup(struct ether_addr **sta_addr, uint32_t num_keys, int32_t *found)
{
    STORE_READ_LOCK(sta_store_lock);
    rte_hash_lookup_bulk(sta_store, (const void **)sta_addr, num_keys, found);
    STORE_READ_UNLOCK(sta_store_lock);
}

enum rwpa_status
store_sta_del(struct ether_addr *sta_addr)
{
    int32_t index;

    STORE_WRITE_LOCK(sta_store_lock);
    index = rte_hash_del_key(sta_store, sta_addr);
    STORE_WRITE_UNLOCK(sta_store_lock);

    if (likely(index >= 0)) {
       sta_reset(&(stas[index]));
       return RWPA_STS_OK;
    }

    return RWPA_STS_ERR;
}
