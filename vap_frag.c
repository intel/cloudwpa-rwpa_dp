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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_ether.h>

#include "r-wpa_global_vars.h"
#include "key.h"
#include "counter.h"
#include "seq_num.h"
#include "meta.h"
#include "vap_hdrs.h"
#include "vap_frag.h"
#include "ieee80211.h"

#define FRAG_TBL_BUCKET_ENTRIES  16
#define FRAG_DR_PREFETCH          3

#define MAX_VAP_FRAG_SZ_MULTIPLE  8

static struct rte_ip_frag_tbl *frag_tbl;
static struct rte_ip_frag_death_row death_row;
static uint32_t vap_frag_sz = 0;

void
vap_frag_init(uint32_t max_stations,
              uint32_t frag_ttl_ms,
              uint32_t max_vap_frag_sz)
{
    uint64_t frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) /
                               MS_PER_S * frag_ttl_ms;

    /*
     * check max vap fragment size is a multiple
     * of 8
     */
    if (max_vap_frag_sz % MAX_VAP_FRAG_SZ_MULTIPLE)
        rte_exit(EXIT_FAILURE, "max_vap_frag_sz must be a multiple "
                 "of %d, exiting\n",
                 MAX_VAP_FRAG_SZ_MULTIPLE);

    /* create the reassembly table */
    frag_tbl = rte_ip_frag_table_create(
                                max_stations, FRAG_TBL_BUCKET_ENTRIES,
                                max_stations, frag_cycles, rte_socket_id());

    if (frag_tbl == NULL)
        rte_exit(EXIT_FAILURE, "Error creating fragment table, exiting\n");

    memset(&death_row, 0x0, sizeof(struct rte_ip_frag_death_row));

    vap_frag_sz = max_vap_frag_sz;
}

void
vap_frag_destroy(void)
{
    rte_ip_frag_table_destroy(frag_tbl);
}

enum rwpa_status
vap_payload_fragment(struct rte_mbuf *m,
                     struct rte_mbuf **frags_out,
                     uint16_t nb_frags_out,
                     struct rte_mempool *hdr_mp,
                     struct rte_mempool *data_mp)
{
    struct ipv4_hdr *ip_hdr;
    int32_t nb_frags, i;

    /*
     * check parameters and prepend a 'dummy' IPv4
     * header to the mbuf
     */
    if (unlikely(m == NULL ||
                 frags_out == NULL ||
                 hdr_mp == NULL ||
                 data_mp == NULL ||
                 (ip_hdr = (struct ipv4_hdr *)
                     rte_pktmbuf_prepend(m, sizeof(struct ipv4_hdr))) == NULL))
        return RWPA_STS_ERR;

    /*
     * fill in some fields into the IP header which are used
     * during fragmentation
     * - fragment_offset is the only one, which contains the
     *   don't fragment flag
     */
    ip_hdr->fragment_offset = 0;

    /* fragment the payload */
    nb_frags = rte_ipv4_fragment_packet(m, frags_out, nb_frags_out,
                                        vap_frag_sz + sizeof(struct ipv4_hdr),
                                        hdr_mp, data_mp);

    if (unlikely(nb_frags != nb_frags_out))
        return RWPA_STS_ERR;

    /* remove the IPv4 header from the start of each mbuf */
    for (i = 0; i < nb_frags; i++)
        rte_pktmbuf_adj(frags_out[i], sizeof(struct ipv4_hdr));

    return RWPA_STS_OK;
}

enum rwpa_status
vap_payload_reassemble(struct rte_mbuf *mi,
                       struct rte_mbuf **mo,
                       uint64_t tms,
                       struct rwpa_meta *meta)
{
    struct ipv4_hdr *ip_hdr;
    uint16_t frag_offs;

    /*
     * check parameters and prepend a 'dummy' IPv4
     * header to the mbuf
     */
    if (unlikely(mi == NULL ||
                 mo == NULL ||
                 meta == NULL ||
                 (ip_hdr = (struct ipv4_hdr *)
                     rte_pktmbuf_prepend(mi, sizeof(struct ipv4_hdr))) == NULL))
        return RWPA_STS_ERR;

    /*
     * fill in some fields into the IP header which are used
     * during reassembly
     * - src and dest IP addresses
     *   - station MAC will be overloaded into these fields
     * - packet id
     *   - vAP header sequence number will be used here
     * - total_length
     * - fragment_offset, if last fragment
     * - MF flag, if not last fragment
     *
     *  NOTE: although the fragmentation sequence number is at
     *  the vAP level, the station MAC is used here to
     *  give some extra "uniqueness" and because the vAP MAC
     *  may not be available at this point as the 802.11
     *  header will only be in the first fragment
     */
    ip_hdr->src_addr = ip_hdr->dst_addr = 0;
    ether_addr_copy(meta->p_sta_addr,
                    (struct ether_addr *)&ip_hdr->src_addr);
    ip_hdr->packet_id = meta->frag_seq_num;
    ip_hdr->total_length = rte_cpu_to_be_16(rte_pktmbuf_data_len(mi));
    if (meta->last_fragment) {
        frag_offs = vap_frag_sz >> 3;
    } else {
        frag_offs = 0 | IPV4_HDR_MF_FLAG;
    }
    ip_hdr->fragment_offset = rte_cpu_to_be_16(frag_offs);

    /* update some fields in the mbuf */
    mi->l2_len = 0;
    mi->l3_len = sizeof(struct ether_hdr) +
                 sizeof(struct vap_hdr) +
                 sizeof(struct ipv4_hdr);

    /* attempt to reassemble the packet */
    *mo = rte_ipv4_frag_reassemble_packet(
                                frag_tbl, &death_row, mi, tms, ip_hdr);

    /*
     * check if the packet is fully reassembled
     * - if it is, remove the IP header from the start
     *   of the packet before returning
     */
    if (*mo)
        rte_pktmbuf_adj(*mo, sizeof(struct ipv4_hdr));

    return RWPA_STS_OK;
}

void
vap_frag_free_death_row(void)
{
     rte_ip_frag_free_death_row(&death_row, FRAG_DR_PREFETCH);
}
