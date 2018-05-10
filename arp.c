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

#include "arp.h"

#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_ip.h>

void
arp_request(struct rte_mbuf *mbuf, uint32_t dst_ipaddr, uint32_t src_ipaddr, uint8_t port)
{
    size_t pkt_size = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
    mbuf->data_len = pkt_size;
    mbuf->pkt_len = pkt_size;
    struct ether_hdr *eth_h = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

    rte_eth_macaddr_get(port, &eth_h->s_addr);
    memset(&eth_h->d_addr, 0xFF, ETHER_ADDR_LEN);
    eth_h->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

    struct arp_hdr *arp_h =
            (struct arp_hdr *)((char *)eth_h + sizeof(struct ether_hdr));

    arp_h->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
    arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);
    arp_h->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    arp_h->arp_hln = ETHER_ADDR_LEN;
    arp_h->arp_pln = sizeof(uint32_t);
    arp_h->arp_data.arp_sip = rte_cpu_to_be_32(src_ipaddr);
    arp_h->arp_data.arp_tip = rte_cpu_to_be_32(dst_ipaddr);

    rte_eth_macaddr_get(port, &arp_h->arp_data.arp_sha);
    memset(&arp_h->arp_data.arp_tha, 0, ETHER_ADDR_LEN);
}

int
arp_reply(struct rte_mbuf *mbuf, uint8_t port, uint32_t vnfd_ip_addr)
{
    struct ether_hdr    *eth_h;
    struct arp_hdr      *arp_h;

    eth_h = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

    arp_h = (struct arp_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
    uint16_t arp_op = rte_be_to_cpu_16(arp_h->arp_op);

    if(arp_op == ARP_OP_REQUEST && arp_h->arp_data.arp_tip == vnfd_ip_addr) {

        /*
         * currently we do not do IP Addr lookup for arp
         * we just swap IPs and insert MAC addr of VNFD
         * if destination IP addr matches that of VNFD
         */

        /* Change ARP Op */
        arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);

        /* Swap MACs */
        ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
        rte_eth_macaddr_get(port, &eth_h->s_addr);
        ether_addr_copy(&arp_h->arp_data.arp_sha, &arp_h->arp_data.arp_tha);
        ether_addr_copy(&eth_h->s_addr, &arp_h->arp_data.arp_sha);

        /* Swap IPs */
        uint32_t ipaddr = arp_h->arp_data.arp_sip;
        arp_h->arp_data.arp_sip = arp_h->arp_data.arp_tip;
        arp_h->arp_data.arp_tip = ipaddr;
	return 1;
    } else if(arp_op == ARP_OP_REPLY) {
        /*
         * currently we do not populate an arp table on VNFD
         * - drop the packet
         */
        rte_pktmbuf_free(mbuf);
	return 0;

    } else {
        rte_pktmbuf_free(mbuf);
	return 0;
    }
}
