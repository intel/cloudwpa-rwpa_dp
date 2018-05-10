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

#ifndef __INCLUDE_VAP_HDRS_H__
#define __INCLUDE_VAP_HDRS_H__

/*
 * Protocol IDs
 */
#define VAP_PROTO_VERSION_0 (0)

/*
 * TLV Types
 */
#define VAP_TLV_TYPE_80211  (0)

/*
 * vAP Header Control
 */
union vap_ctrl {
    struct {
        uint8_t    fragment:1;
        uint8_t    last_fragment:1;
        uint8_t    reserved:6;
    } __attribute__((__packed__))be;
    uint8_t        u8;
};

/*
 * vAP Header
 */
struct vap_hdr {
    uint8_t        proto_ver;
    uint8_t        wifi_tid:4;
    uint8_t        reserved:4;
    uint8_t        seq_num;
    union vap_ctrl ctrl;
} __attribute__((__packed__));

/*
 * vAP TLV
 */
struct vap_tlv {
    uint16_t       t;
    uint16_t       l;
    uint8_t        v[0];
}__attribute__((__packed__));

/*
 * Is Fragment
 */
static inline int
vap_is_fragment(struct vap_hdr *hdr)
{
    return (hdr &&
            hdr->ctrl.be.fragment == 1);
}

/*
 * Is Last Fragmented
 */
static inline int
vap_is_last_fragment(struct vap_hdr *hdr)
{
    return (hdr &&
            hdr->ctrl.be.last_fragment == 1);
}

/*
 * vAP Header Parse
 */
enum rwpa_status
vap_hdr_parse(struct rte_mbuf *mbuf, struct rwpa_meta *meta);

/*
 * vAP Header Decap
 */
enum rwpa_status
vap_hdr_decap(struct rte_mbuf *mbuf);

/*
 * vAP Header Encap
 */
enum rwpa_status
vap_hdr_encap(struct rte_mbuf *mbuf,
              uint8_t fragment,
              uint8_t last_fragment,
              seq_num_val_t seq_num,
              struct ether_addr *inner_src_mac,
              struct ether_addr *inner_dst_mac);

/*
 * vAP TLV Decap
 */
enum rwpa_status
vap_tlv_decap(struct rte_mbuf *mbuf);

/*
 * vAP TLV Encap
 */
enum rwpa_status
vap_tlv_encap(struct rte_mbuf *mbuf);

#endif // __INCLUDE_VAP_HDRS_H__
