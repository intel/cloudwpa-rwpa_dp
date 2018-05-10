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
#include "counter.h"
#include "seq_num.h"
#include "meta.h"
#include "ether.h"
#include "ieee80211.h"
#include "ieee8022.h"
#include "ccmp_defns.h"
#include "ccmp.h"
#include "ieee80211_utils.h"

void
ieee80211_packet_parse(struct rte_mbuf *mbuf, struct rwpa_meta *meta)
{
    /* check parameters */
    if (unlikely(mbuf == NULL || meta == NULL))
        return;

    struct ieee80211_hdr *wifi_hdr =
        rte_pktmbuf_mtod(mbuf, struct ieee80211_hdr *);

    /* check if the wifi header has addr4 and qos_ctrl */
    meta->has_a4 = ieee80211_has_a4(wifi_hdr);
    meta->has_qc = ieee80211_has_qos_ctrl(wifi_hdr);

    meta->wifi_hdr_sz = sizeof(struct ieee80211_hdr);

    meta->p_qc = (union qos_ctrl *)&wifi_hdr[1];

    if (meta->has_a4) {
        meta->p_a4 = (struct ether_addr *)meta->p_qc;
        meta->p_qc = (union qos_ctrl *)&meta->p_a4[1];
        meta->wifi_hdr_sz += sizeof(struct ether_addr);
    }

    if (meta->has_qc) {
        meta->wifi_hdr_sz += sizeof(union qos_ctrl);
    }

    meta->wep = ieee80211_is_protected(wifi_hdr);

    /* get pointers to the station and bssid MAC addresses*/
    ieee80211_addrs_get(wifi_hdr, &(meta->p_sta_addr), &(meta->p_bssid));
}

enum ieee80211_pkt_type
ieee80211_packet_classify(struct rte_mbuf *mbuf, struct rwpa_meta *meta)
{
    enum ieee80211_pkt_type pkt_type = IEEE80211_PKT_TYPE_DELIM;
    struct ieee80211_hdr *wifi_hdr;
    struct ieee8022_snap_hdr *snap_hdr;
    uint16_t ether_type;

    /* check parameters */
    if (unlikely(mbuf == NULL || meta == NULL))
        return pkt_type;

    wifi_hdr = rte_pktmbuf_mtod(mbuf, struct ieee80211_hdr *);

    /*
     * sanity check headers
     * - currently only DATA frames supported
     * - sanity checks are spread across classify and decap functions
     */
    if (wifi_hdr->frame_ctrl.le.type != IEEE80211_TYPE_DATA)
        return pkt_type;

    /* find the start of the 802.2 header */
    snap_hdr = (struct ieee8022_snap_hdr *)
                   (((uint8_t *)wifi_hdr) + 
                    meta->wifi_hdr_sz +
                    (meta->wep ? sizeof(struct ccmp_hdr) : 0));

    /* check snap fields are present in 802.2 header */
    if (snap_hdr->dsap == DSAP_SNAP &&
        snap_hdr->ssap == SSAP_SNAP) {

        /* snap fields are present */
        ether_type = rte_be_to_cpu_16(snap_hdr->ether_type);

        /* check ether_type field for EAPOL or data */
        pkt_type = (ether_type == ETHER_TYPE_EAPOL ?
                    IEEE80211_PKT_TYPE_EAPOL :
                    IEEE80211_PKT_TYPE_DATA);
    }

    return pkt_type;
}
