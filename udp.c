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
#include <rte_udp.h>

#include "r-wpa_global_vars.h"
#include "ip.h"
#include "ether.h"
#include "counter.h"
#include "seq_num.h"
#include "meta.h"
#include "udp.h"

static inline void
udp_hdr_fill(struct udp_hdr *hdr, uint16_t src_port,
             uint16_t dest_port, uint16_t length);

enum rwpa_status
udp_decap(struct rte_mbuf *mbuf, struct rwpa_meta *meta)
{
#ifndef RWPA_DYNAMIC_AP_CONF_UPDATE_OFF
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)&eth_hdr[1];
    struct udp_hdr *udp_hdr = (struct udp_hdr *)&ip_hdr[1];

    /* save the source MAC, IP and UDP port addresses */
    if (likely(meta != NULL)) {
        ether_addr_copy(&(eth_hdr->s_addr), &(meta->vap_tun_mac));
        meta->vap_tun_ip = ip_hdr->src_addr;
        meta->vap_tun_port = rte_be_to_cpu_16(udp_hdr->src_port);
    }
#else
    UNUSED(meta);
#endif

    /* calculate amount to decap */
    uint8_t decap_sz = sizeof(struct ether_hdr) +
                       sizeof(struct ipv4_hdr) +
                       sizeof(struct udp_hdr);

    /* decap */
    if (unlikely(rte_pktmbuf_adj(mbuf, decap_sz) == NULL))
        return RWPA_STS_ERR;

    return RWPA_STS_OK;
}

enum rwpa_status
udp_encap(struct rte_mbuf *mbuf,
          uint16_t tun_src_port, uint32_t tun_src_ip, struct ether_addr *tun_src_mac,
          uint16_t tun_dest_port, uint32_t tun_dest_ip, struct ether_addr *tun_dest_mac)
{
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    struct udp_hdr *udp_hdr;

    /* calculate the IPv4 frame length (including IPv4 header) */
    uint16_t ip_frame_len = sizeof(struct ipv4_hdr) +
                            sizeof(struct udp_hdr) +
                            mbuf->pkt_len;

    /*
     * calculate how much to prepend for the inner Ethernet II,
     * IPv4 and UDP headers
     */
    uint8_t prepend_sz = sizeof(struct ether_hdr) +
                         sizeof(struct ipv4_hdr) +
                         sizeof(struct udp_hdr);

    /* prepend space for these headers */
    eth_hdr = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, prepend_sz);
    if (unlikely(eth_hdr == NULL))
        return RWPA_STS_ERR;

    /* fill in the Ethernet II header */
    eth_hdr_fill(eth_hdr, tun_src_mac, tun_dest_mac, ETHER_TYPE_IPv4);

    /* fill in the IP header */
    ip_hdr = (struct ipv4_hdr *)&eth_hdr[1];
    ip_hdr_fill(ip_hdr, tun_src_ip, tun_dest_ip, ip_frame_len, IPPROTO_UDP);
#ifdef RWPA_HW_CKSUM_OFFLOAD_OFF
    mbuf->ol_flags &= ~PKT_TX_IP_CKSUM;
#else
    mbuf->ol_flags |= PKT_TX_IP_CKSUM;
    mbuf->l2_len = sizeof(struct ether_hdr);
    mbuf->l3_len = sizeof(struct ipv4_hdr);
#endif

    /* fill in the UDP header */
    udp_hdr = (struct udp_hdr *)&ip_hdr[1];
    udp_hdr_fill(udp_hdr, tun_src_port, tun_dest_port,
                 ip_frame_len - sizeof(struct ipv4_hdr));

    return RWPA_STS_OK;
}

static inline void
udp_hdr_fill(struct udp_hdr *hdr, uint16_t src_port,
             uint16_t dest_port, uint16_t length)
{
    hdr->src_port = rte_cpu_to_be_16(src_port);
    hdr->dst_port = rte_cpu_to_be_16(dest_port);
    hdr->dgram_len = rte_cpu_to_be_16(length);
    hdr->dgram_cksum = 0;
}
