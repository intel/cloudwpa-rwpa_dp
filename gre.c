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
#include <rte_gre.h>

#include "r-wpa_global_vars.h"
#include "ip.h"
#include "ether.h"
#include "counter.h"
#include "seq_num.h"
#include "meta.h"
#include "gre.h"

static inline void
gre_hdr_fill(struct gre_hdr *hdr, uint8_t key_present, uint32_t key);

enum rwpa_status
gre_decap(struct rte_mbuf *mbuf, struct rwpa_meta *meta)
{
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)&eth_hdr[1];
    struct gre_hdr *gre_hdr = (struct gre_hdr *)&ip_hdr[1];
 
    uint8_t gre_hdr_sz = sizeof(struct gre_hdr);
    uint8_t decap_sz = 0;

    /*
     * sanity check headers
     * - outer eth header and ipv4 header have been checked in
     *   initial classifier stage
     */
    if (rte_be_to_cpu_16(gre_hdr->proto) != ETHER_TYPE_TEB)
        return RWPA_STS_ERR;

    /* calculate gre header size */
    if (gre_hdr->c) gre_hdr_sz += GRE_CKSUM_SZ; /* checksum */
    if (gre_hdr->k) gre_hdr_sz += GRE_KEY_SZ;   /* key */
    if (gre_hdr->s) gre_hdr_sz += GRE_SEQ_SZ;   /* sequence number */

#ifndef RWPA_DYNAMIC_AP_CONF_UPDATE_OFF
    /* save the source MAC and IP addresses */
    if (likely(meta != NULL)) {
        ether_addr_copy(&(eth_hdr->s_addr), &(meta->vap_tun_mac));
        meta->vap_tun_ip = ip_hdr->src_addr;
    }
#else
    UNUSED(meta);
#endif

    /* calculate amount to decap */
    decap_sz = sizeof(struct ether_hdr) +
               sizeof(struct ipv4_hdr) +
               gre_hdr_sz;

    /* decap */
    if (unlikely(rte_pktmbuf_adj(mbuf, decap_sz) == NULL))
        return RWPA_STS_ERR;

    return RWPA_STS_OK;
}

enum rwpa_status
gre_encap(struct rte_mbuf *mbuf,
          uint32_t tun_src_ip, struct ether_addr *tun_src_mac,
          uint32_t tun_dest_ip, struct ether_addr *tun_dest_mac,
          uint8_t key_present, uint32_t key)
{
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    struct gre_hdr *gre_hdr;

    /* calculate the IPv4 frame length (including IPv4 header) */
    uint16_t ip_frame_len = mbuf->pkt_len +
                            sizeof(struct ipv4_hdr) +
                            sizeof(struct gre_hdr) +
                            (key_present ? GRE_KEY_SZ : 0);

    /*
     * calculate how much to prepend for the inner Ethernet II,
     * IPv4 and GRE headers
     */
    uint8_t prepend_sz = sizeof(struct ether_hdr) +
                         sizeof(struct ipv4_hdr) +
                         sizeof(struct gre_hdr) +
                         (key_present ? GRE_KEY_SZ : 0);

    /* prepend space for these headers */
    eth_hdr = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, prepend_sz);
    if (unlikely(eth_hdr == NULL))
        return RWPA_STS_ERR;

    /* fill in the Ethernet II header */
    eth_hdr_fill(eth_hdr, tun_src_mac, tun_dest_mac, ETHER_TYPE_IPv4);

    /* fill in the IP header */
    ip_hdr = (struct ipv4_hdr *)&eth_hdr[1];
    ip_hdr_fill(ip_hdr, tun_src_ip, tun_dest_ip, ip_frame_len, IPPROTO_GRE);
#ifdef RWPA_HW_CKSUM_OFFLOAD_OFF
    mbuf->ol_flags &= ~PKT_TX_IP_CKSUM;
#else
    mbuf->ol_flags |= PKT_TX_IP_CKSUM;
    mbuf->l2_len = sizeof(struct ether_hdr);
    mbuf->l3_len = sizeof(struct ipv4_hdr);
#endif

    /* fill in the GRE header */
    gre_hdr = (struct gre_hdr *)&ip_hdr[1];
    gre_hdr_fill(gre_hdr, key_present, key);

    return RWPA_STS_OK;
}

static inline void
gre_hdr_fill(struct gre_hdr *hdr, uint8_t key_present, uint32_t key)
{
    hdr->proto = rte_cpu_to_be_16(ETHER_TYPE_TEB);
    hdr->k = key_present;
    hdr->ver = 0;
    hdr->c = 0;
    hdr->s = 0;
    hdr->res1 = 0;
    hdr->res2 = 0;
    hdr->res3 = 0;

    uint8_t *key_p = (uint8_t *)hdr + GRE_KEY_SZ;

    if (key_present)
        rte_memcpy(key_p, &key, GRE_KEY_SZ);
}
