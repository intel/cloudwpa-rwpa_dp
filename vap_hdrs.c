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
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include "r-wpa_global_vars.h"
#include "counter.h"
#include "seq_num.h"
#include "ether.h"
#include "meta.h"
#include "vap_hdrs.h"

static inline void
vap_hdr_fill(struct vap_hdr *hdr,
             uint8_t fragment,
             uint8_t last_fragment,
             seq_num_val_t seq_num);

static inline void
vap_tlv_fill(struct vap_tlv *hdr, uint16_t frame_len);

enum rwpa_status
vap_hdr_parse(struct rte_mbuf *mbuf, struct rwpa_meta *meta)
{
    struct ether_hdr *eth_hdr;
    struct vap_hdr *vap_hdr;

    /* check parameters */
    if (unlikely(mbuf == NULL || meta == NULL))
        return RWPA_STS_ERR;

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    vap_hdr = (struct vap_hdr *)&eth_hdr[1];

    /* sanity check headers */
    if (eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_TIPC) ||
        vap_hdr->proto_ver != VAP_PROTO_VERSION_0)
        return RWPA_STS_ERR;

    /* get some info from the vAP header */
    meta->p_sta_addr = &(eth_hdr->s_addr);
    meta->fragment = vap_is_fragment(vap_hdr);
    meta->last_fragment = vap_is_last_fragment(vap_hdr);
    meta->frag_seq_num = vap_hdr->seq_num;

    return RWPA_STS_OK;
}

enum rwpa_status
vap_hdr_decap(struct rte_mbuf *mbuf)
{
    /* check parameters */
    if (unlikely(mbuf == NULL))
        return RWPA_STS_ERR;

    uint8_t decap_sz = 0;

    /* calculate amount to decap */
    decap_sz = sizeof(struct ether_hdr) +
               sizeof(struct vap_hdr);

    /* decap */
    if (unlikely(rte_pktmbuf_adj(mbuf, decap_sz) == NULL)) {
        return RWPA_STS_ERR;
    }

    return RWPA_STS_OK;
}

enum rwpa_status
vap_hdr_encap(struct rte_mbuf *mbuf,
              uint8_t fragment,
              uint8_t last_fragment,
              seq_num_val_t seq_num,
              struct ether_addr *inner_src_mac,
              struct ether_addr *inner_dst_mac)
{
    struct ether_hdr *eth_hdr;
    struct vap_hdr *vap_hdr;

    /* check parameters */
    if (unlikely(mbuf == NULL ||
                 inner_src_mac == NULL ||
                 inner_dst_mac == NULL))
        return RWPA_STS_ERR;

    /*
     * calculate how much to prepend for the inner Ethernet II
     * and vAP headers
     */
    uint8_t prepend_sz = sizeof(struct ether_hdr) +
                         sizeof(struct vap_hdr);

    /* prepend space for these headers */
    eth_hdr = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, prepend_sz);
    if (unlikely(eth_hdr == NULL))
        return RWPA_STS_ERR;

    /* fill in the Ethernet II header */
    eth_hdr_fill(eth_hdr, inner_src_mac, inner_dst_mac, ETHER_TYPE_TIPC);

    /* fill in the vAP header */
    vap_hdr = (struct vap_hdr *)&eth_hdr[1];
    vap_hdr_fill(vap_hdr, fragment, last_fragment, seq_num);

    return RWPA_STS_OK;
}

enum rwpa_status
vap_tlv_decap(struct rte_mbuf *mbuf)
{
    struct vap_tlv *vap_tlv;

    /* check parameters */
    if (unlikely(mbuf == NULL))
        return RWPA_STS_ERR;

    vap_tlv = rte_pktmbuf_mtod(mbuf, struct vap_tlv *);

    /* sanity check headers */
    if (vap_tlv->t != rte_cpu_to_be_16(VAP_TLV_TYPE_80211))
        return RWPA_STS_ERR;

    /* decap */
    if (unlikely(rte_pktmbuf_adj(mbuf, sizeof(struct vap_tlv)) == NULL))
        return RWPA_STS_ERR;

    return RWPA_STS_OK;
}

enum rwpa_status
vap_tlv_encap(struct rte_mbuf *mbuf)
{
    struct vap_tlv *vap_tlv;

    /* check parameters */
    if (unlikely(mbuf == NULL))
        return RWPA_STS_ERR;

    /* save the current frame length */
    uint16_t frame_len = mbuf->data_len;

    /* prepend space for the vAP TLV headers */
    vap_tlv = (struct vap_tlv *)rte_pktmbuf_prepend(mbuf, sizeof(struct vap_tlv));
    if (unlikely(vap_tlv == NULL))
        return RWPA_STS_ERR;

    /* fill in the vAP TLV */
    vap_tlv_fill(vap_tlv, frame_len);

    return RWPA_STS_OK;
}

static inline void
vap_hdr_fill(struct vap_hdr *hdr,
             uint8_t fragment,
             uint8_t last_fragment,
             seq_num_val_t seq_num)
{
    hdr->proto_ver = VAP_PROTO_VERSION_0;
    hdr->wifi_tid = 0;
    hdr->reserved = 0;
    hdr->seq_num = seq_num;
    hdr->ctrl.be.fragment = fragment;
    hdr->ctrl.be.last_fragment = last_fragment;
    hdr->ctrl.be.reserved = 0;
}

static inline void
vap_tlv_fill(struct vap_tlv *hdr, uint16_t frame_len)
{
    hdr->t = rte_cpu_to_be_16(VAP_TLV_TYPE_80211);
    hdr->l = rte_cpu_to_be_16(frame_len);
}
