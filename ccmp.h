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

#ifndef __INCLUDE_CCMP_H__
#define __INCLUDE_CCMP_H__

/*
 * CCMP Header
 */
struct ccmp_hdr {
    uint8_t         pn0;
    uint8_t         pn1;
    uint8_t         rsvd1;

    union {
        struct {
            uint8_t rsvd2:5;
            uint8_t ext_iv:1;
            uint8_t key_id:2;
        } __attribute__((__packed__))le;
        uint8_t     u8;
    } key_id;

    uint8_t         pn2;
    uint8_t         pn3;
    uint8_t         pn4;
    uint8_t         pn5;
} __attribute__((__packed__));

/*
 * CCMP AAD
 */
struct ccmp_aad {
    union frame_ctrl  frame_ctrl;

    struct ether_addr addr1;
    struct ether_addr addr2;
    struct ether_addr addr3;

    union seq_ctrl    seq_ctrl;

    // addr4 not always present
    // struct ether_addr addr4;

    // qos_ctrl not always present
    // union qos_ctrl    qos_ctrl;
} __attribute__((__packed__));

/*
 * CCMP Nonce
 */
struct ccmp_nonce {
    union {
        struct {
            uint8_t   priority:4;
            uint8_t   mgmt:1;
            uint8_t   zeros:3;
        } __attribute__((__packed__))le;
        uint8_t       u8;
    } flags;

    struct ether_addr addr2;
    uint8_t           pn[CCMP_PN_LEN];
} __attribute__((__packed__));

enum rwpa_status
ccmp_aad_generate(struct ieee80211_hdr *wifi_hdr,
                  struct rwpa_meta     *meta,
                  uint8_t              *aad,
                  uint8_t              *aad_len);

enum rwpa_status
ccmp_nonce_generate(struct ieee80211_hdr *wifi_hdr,
                    struct rwpa_meta     *meta,
                    counter_val_t         ctr_val,
                    uint8_t              *nonce);

enum rwpa_status
ccmp_hdr_generate(counter_val_t  ctr_val,
                  enum key_id    key_id,
                  uint8_t       *ccmp_hdr);

uint16_t
ccmp_burst_enqueue(struct rte_mbuf  *pkts_in[],
                   uint16_t          pkts_in_sz,
                   struct rwpa_meta *meta[],
                   enum ccmp_op      op,
                   uint16_t          qp,
                   uint8_t           success[]);

uint16_t
ccmp_burst_dequeue(struct rte_mbuf *pkts_out[],
                   uint16_t         pkts_out_sz,
                   uint16_t         qp,
                   uint16_t        *nb_deq_success,
                   uint8_t          success[]);

enum rwpa_status
ccmp_replay_detect(struct ccmp_hdr *hdr,
                   counter_val_t   *ctr_check);

enum rwpa_status
ccmp_encap(struct rte_mbuf  *mbuf,
           struct rwpa_meta *meta);

enum rwpa_status
ccmp_decap(struct rte_mbuf  *mbuf,
           struct rwpa_meta *meta);

#endif // __INCLUDE_CCMP_H__
