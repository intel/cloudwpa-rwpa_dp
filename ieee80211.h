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

#ifndef __INCLUDE_IEEE80211_H__
#define __INCLUDE_IEEE80211_H__

#define IEEE80211_HDR_SZ_MAX (32)

/*
 * IEEE 802.11 Frame Control
 */
union frame_ctrl {
    struct {
        uint8_t proto_ver:2;
        uint8_t type:2;
        uint8_t sub_type:4;

        uint8_t to_ds:1;
        uint8_t from_ds:1;
        uint8_t more_frag:1;
        uint8_t retry:1;
        uint8_t pwr_mgmt:1;
        uint8_t more_data:1;
        uint8_t wep:1;
        uint8_t order:1;
    } __attribute__((__packed__))le;
    uint16_t    u16;
};

/*
 * IEEE 802.11 Sequence Control
 */
union seq_ctrl {
    struct {
        uint8_t frag_num:4;
        uint8_t seq_num_0:4; /* LSB */
        uint8_t seq_num_1;   /* MSB */
    } __attribute__((__packed__))le;
    uint16_t    u16;
};

/*
 * IEEE 802.11 QoS Control
*/
union qos_ctrl {
    struct {
        uint8_t tid:4;
        uint8_t eosp:1;
        uint8_t ack_policy:2;
        uint8_t payload_type:1;

        uint8_t qap_ps_buffer_state;
    } __attribute__((__packed__))le;
    uint16_t    u16;
};

/*
 * IEEE 802.11 Header
 */
struct ieee80211_hdr {
    union frame_ctrl  frame_ctrl;
    uint16_t          duration_id;

    struct ether_addr addr1;
    struct ether_addr addr2;
    struct ether_addr addr3;

    union seq_ctrl    seq_ctrl;

    // addr4 not always present
    // struct ether_addr addr4;

    // qos_ctrl not always present
    // union qos_ctrl    qos_ctrl;
} __attribute__((__packed__));

#define IEEE80211_TYPE_MGMT                          0

#define IEEE80211_MGMT_SUBTYPE_ASSOC_REQ             0
#define IEEE80211_MGMT_SUBTYPE_ASSOC_RES             1
#define IEEE80211_MGMT_SUBTYPE_REASSOC_REQ           2
#define IEEE80211_MGMT_SUBTYPE_REASSOC_RES           3
#define IEEE80211_MGMT_SUBTYPE_PROBE_REQ             4
#define IEEE80211_MGMT_SUBTYPE_PROBE_RES             5
#define IEEE80211_MGMT_SUBTYPE_BEACON                8
#define IEEE80211_MGMT_SUBTYPE_ATIM                  9
#define IEEE80211_MGMT_SUBTYPE DISASSOC             10
#define IEEE80211_MGMT_SUBTYPE_AUTH                 11
#define IEEE80211_MGMT_SUBTYPE_DEAUTH               12
#define IEEE80211_MGMT_SUBTYPE_ACTION               13

#define IEEE80211_TYPE_CTRL                          1

#define IEEE80211_CTRL_SUBTYPE_BLK_ACK_REQ           8
#define IEEE80211_CTRL_SUBTYPE_BLK_ACK               9
#define IEEE80211_CTRL_SUBTYPE_PS_POLL              10
#define IEEE80211_CTRL_SUBTYPE_RTS                  11
#define IEEE80211_CTRL_SUBTYPE_CTS                  12
#define IEEE80211_CTRL_SUBTYPE_ACK                  13
#define IEEE80211_CTRL_SUBTYPE_CF_END               14
#define IEEE80211_CTRL_SUBTYPE_CF_END_ACK           15

#define IEEE80211_TYPE_DATA                          2

#define IEEE80211_DATA_SUBTYPE_DATA                  0
#define IEEE80211_DATA_SUBTYPE_DATA_CF_ACK           1
#define IEEE80211_DATA_SUBTYPE_DATA_CF_POLL          2
#define IEEE80211_DATA_SUBTYPE_DATA_CF_ACK_POLL      3
#define IEEE80211_DATA_SUBTYPE_NULL                  4
#define IEEE80211_DATA_SUBTYPE_CK_ACK                5
#define IEEE80211_DATA_SUBTYPE_CF_POLL               6
#define IEEE80211_DATA_SUBTYPE_CF_ACK_POLL           7
#define IEEE80211_DATA_SUBTYPE_QOS_DATA              8
#define IEEE80211_DATA_SUBTYPE_QOS_DATA_CF_ACK       9
#define IEEE80211_DATA_SUBTYPE_QOS_DATA_CF_POLL     10
#define IEEE80211_DATA_SUBTYPE_QOS_DATA_CF_ACK_POLL 11
#define IEEE80211_DATA_SUBTYPE_QOS_NULL             12
#define IEEE80211_DATA_SUBTYPE_RSVD                 13
#define IEEE80211_DATA_SUBTYPE_QOS_CF_POLL          14
#define IEEE80211_DATA_SUBTYPE_QOS_CF_ACK           15

#define IEEE80211_DATA_QOS_MASK                     0x8

static inline int
ieee80211_has_a4(struct ieee80211_hdr *hdr)
{
    return (hdr &&
            hdr->frame_ctrl.le.to_ds &&
            hdr->frame_ctrl.le.from_ds);
}

static inline int
ieee80211_has_qos_ctrl(struct ieee80211_hdr *hdr)
{
    return (hdr &&
            hdr->frame_ctrl.le.type == IEEE80211_TYPE_DATA &&
            hdr->frame_ctrl.le.sub_type & IEEE80211_DATA_QOS_MASK);
}

static inline int
ieee80211_is_protected(struct ieee80211_hdr *hdr)
{
    return (hdr &&
            hdr->frame_ctrl.le.wep == 1);
}

static inline void
ieee80211_addrs_get(struct ieee80211_hdr *hdr,
                    struct ether_addr **sta_addr,
                    struct ether_addr **bssid)
{
    /* check parameters */
    if (likely(hdr && sta_addr && bssid)) {
        /*
         * in 802.11 header, there are 4 possible combinations
         * of addresses, based on the To DS and From DS control
         * flags
         * - only 2 of these options should happen in this POC
         *   though
         *   - To DS = 1 and From DS = 0
         *   - To DS = 0 and From DS = 1
         *
         * going to just check the To DS flag here to determine
         * the station and bssid MAC addresses
         * - if one of the other 2 options is somehow hit, then
         *   incorrect addresses could be returned here but it's
         *   not too big a deal - the packet will simply get dropped
         *   later anyways
         */
        if (hdr->frame_ctrl.le.to_ds) {
            *sta_addr = &(hdr->addr2);
            *bssid = &(hdr->addr1);
        } else {
            *sta_addr = &(hdr->addr1);
            *bssid = &(hdr->addr2);
        }
    }
}

#endif // __INCLUDE_IEEE80211_H__
