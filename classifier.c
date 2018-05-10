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

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include "key.h"
#include "ether.h"
#include "ieee80211.h"
#include "ieee8022.h"
#include "classifier.h"

enum outer_pkt_type
initial_packet_classify(struct rte_mbuf *mbuf)
{
    enum outer_pkt_type pkt_type = OUTER_PKT_TYPE_DELIM;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;

    /* check parameters */
    if (unlikely(mbuf == NULL))
        return pkt_type;

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    ipv4_hdr = (struct ipv4_hdr *)&eth_hdr[1];

    uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    if (likely(ether_type == ETHER_TYPE_IPv4)) {
        if (ipv4_hdr->next_proto_id == IPPROTO_GRE)
            pkt_type = OUTER_PKT_TYPE_GRE;
        else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
            pkt_type = OUTER_PKT_TYPE_UDP;
        else if (ipv4_hdr->next_proto_id == IPPROTO_ICMP)
            pkt_type = OUTER_PKT_TYPE_ICMP;
        else
            pkt_type = OUTER_PKT_TYPE_OTHER_IP;
    } else if (ether_type == ETHER_TYPE_ARP)
        pkt_type = OUTER_PKT_TYPE_ARP;

    return pkt_type;
}
