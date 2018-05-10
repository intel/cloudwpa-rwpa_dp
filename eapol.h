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

#ifndef __INCLUDE_EAPOL_H__
#define __INCLUDE_EAPOL_H__

#define WPA_REPLAY_COUNTER_LEN 8
#define WPA_NONCE_LEN 32
#define WPA_KEY_RSC_LEN 8
#define WPA_KEY_MIC_LEN 16

struct wpa_eapol_key {
	uint8_t version;
	uint8_t pkt_type;
	uint8_t length[2];
	uint8_t type;
	/* Note: key_info, key_length, and key_data_length are unaligned */
	uint8_t key_info[2]; /* big endian */
	uint8_t key_length[2]; /* big endian */
	uint8_t replay_counter[WPA_REPLAY_COUNTER_LEN];
	uint8_t key_nonce[WPA_NONCE_LEN];
	uint8_t key_iv[16];
	uint64_t key_rsc;//[WPA_KEY_RSC_LEN];
	uint8_t key_id[8]; /* Reserved in IEEE 802.11i/RSN */
	uint8_t key_mic[WPA_KEY_MIC_LEN];
	uint8_t key_data_length[2]; /* big endian */
	/* followed by key_data_length bytes of key_data */
	uint8_t key_data[0]; /* big endian */
} __attribute__((__packed__));

int vnf_wpa_eapol_key_mic(const uint8_t *key, size_t key_len, int ver,
			  const uint8_t *buf, size_t len, uint8_t *mic);

#endif // __INCLUDE_EAPOL_H__
