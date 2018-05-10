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

#ifndef __INCLUDE_STORE_H__
#define __INCLUDE_STORE_H__

#include <rte_ether.h>

/**********************************************************
 * Init/cleanup
 */

/**
 * @brief Initialises the vAP and station store
 *
 * @param [in] socket_id ID of socket for memory allocation
 * @param [in] app_addr_params Address params from config
 */
void
store_init(int socket_id, struct app_addr_params *app_addr_params);

/**
 * @brief Cleans up the store
 */
void
store_cleanup(void);

/**********************************************************
 * vAP Store
 */

/**
 * @brief Adds a vAP to the store
 *
 * @param [in] vap_addr MAC address of the vAP
 *
 * @return Pointer to the new vAP entry, NULL if error occurred
 */
struct vap_elem *
store_vap_add(struct ether_addr *vap_addr);

/**
 * @brief Checks the store for the specified vAP
 *
 * @param [in] vap_addr MAC address of the vAP
 *
 * @return Pointer to the vAP entry if found, NULL otherwise
 */
struct vap_elem *
store_vap_lookup(struct ether_addr *vap_addr);

/**
 * @brief Gets a particular vAP from the store based on index
 *
 * @param [in] index Store index for the vAP
 *
 * @return Pointer to the vAP entry, NULL if error occurred
 */
struct vap_elem *
store_vap_get(int32_t index);

/**
 * @brief Does a bulk lookup of the vAP store
 *
 * @param [in]  vap_addr Array of vAP MAC addresses
 * @param [in]  num_keys Number of keys in the array
 * @param [out] found Array of found vAP indexes. Values can be passed
 *                    to store_vap_get() to get the actual station. Value
 *                    -ENOENT means vAP was not found.
 */
void
store_vap_bulk_lookup(struct ether_addr **vap_addr, uint32_t num_keys, int32_t *found);

/**
 * @brief Deletes a vAP entry from the store
 *
 * @param [in] vap_addr MAC address of vAP
 *
 * @return STORE_STS_OK if deleted successfully, STORE_STS_FAIL otherwise
 *
 * @note
 *   All stations associated with this vAP must be deleted
 *   from the store before deleting the vAP itself
 */
enum rwpa_status
store_vap_del(struct ether_addr *vap_addr);

/**********************************************************
 * Station Store
 */

/**
 * @brief Adds a Station to the store
 *
 * @param [in] sta_addr MAC address of the Station
 * @param [in] vap_addr MAC address of the Station's vAP
 *
 * @return Pointer to the new Station entry, NULL if error occurred
 */
struct sta_elem *
store_sta_add(struct ether_addr *sta_addr, struct ether_addr *vap_addr);

/**
 * @brief Checks the store for the specified Station
 *
 * @param [in] sta_addr MAC address of the Station
 *
 * @return Pointer to the Station entry if found, NULL otherwise
 */
struct sta_elem *
store_sta_lookup(struct ether_addr *sta_addr);

/**
 * @brief Gets a particular Station from the store based on index
 *
 * @param [in] index Store index for the Station
 *
 * @return Pointer to the Station entry, NULL if error occurred
 */
struct sta_elem *
store_sta_get(int32_t index);

/**
 * @brief Does a bulk lookup of the Station store
 *
 * @param [in]  sta_addr MAC address of the Station
 * @param [in]  num_keys Number of keys in the array
 * @param [out] found Array of found Station indexes. Values can be passed
 *                    to store_sta_get() to get the actual station. Value
 *                    -ENOENT means station was not found.
 */
void
store_sta_bulk_lookup(struct ether_addr **sta_addr, uint32_t num_keys, int32_t *found);

/**
 * @brief Deletes a Station from the store
 *
 * @param [in] sta_addr MAC address of the Station
 *
 * @return STORE_STS_OK if deleted successfully, STORE_STS_FAIL otherwise
 */
enum rwpa_status
store_sta_del(struct ether_addr *sta_addr);

#endif // __INCLUDE_STORE_H__
