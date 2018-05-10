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

#include "r-wpa_global_vars.h"
#include "app.h"
#include "key.h"
#include "counter.h"
#include "seq_num.h"
#include "meta.h"
#include "ieee80211.h"
#include "ieee8022.h"
#include "ccmp_defns.h"
#include "ccmp_sa.h"
#include "ccmp.h"
#include "vap.h"
#include "convert.h"

/*
 * Default Downlink Frame Control settings
 * - Type = DATA (b'10)
 * - SubType = QOS_DATA (b'1000)
 * - ToDS = 0
 * - FromDS = 1
 * - wep = 1
 */
#define FRAME_CTRL_DL_DEFAULT 0x4288

/*
 * Ethernet II -> 802.11 Conversion
 *
 * Convert Ethernet II header to 802.11 & 802.2-SNAP headers
 *
 * 802.11
 * - FrameCtrl::Type = DATA
 * - FrameCtrl::SubType =
 *                        QOS_DATA if unicast
 *                        DATA if broadcast/multicast
 * - FrameCtrl::ToDS = 0
 * - FrameCtrl::FromDS = 1
 * - FrameCtrl::wep = 0/1
 * - Addr1 (DA) = Ethernet::Dest
 * - Addr2 (BSSID) = vAP MAC
 * - Addr3 (SA) = Ethernet::Src
 * - Addr4 = not present
 * - QosCtrl::TID = 0*
 *
 * 802.2-SNAP
 * - SSAP = 0xAA
 * - DSAP = 0xAA
 * - Control = 0
 * - SNAP ID
 *   - OUI = 0x000000
 *   - EtherType = Ethernet::EtherType
 *
 * *802.11::QosCtrl only present if unicast
 */
enum rwpa_status
ether_to_ieee80211_convert(struct rte_mbuf  *mbuf,
                           struct rwpa_meta *meta)
{
    struct ether_hdr *eth_hdr;
    struct ieee80211_hdr *wifi_hdr;
    struct ccmp_hdr *ccmp_hdr;
    struct ieee8022_snap_hdr *snap_hdr;
    struct ether_addr dest_mac, src_mac;
    uint16_t ether_type;

    if (unlikely(mbuf == NULL ||
                 meta == NULL ||
                 meta->sa == NULL ||
                 meta->vap == NULL ||
                 (eth_hdr =
                      rte_pktmbuf_mtod(mbuf, struct ether_hdr *)) == NULL))
        return RWPA_STS_ERR;

    /* save src and dest MACs and etherType */
    ether_addr_copy(&(eth_hdr->d_addr), &dest_mac);
    ether_addr_copy(&(eth_hdr->s_addr), &src_mac);
    ether_type = eth_hdr->ether_type;

    int unicast = is_unicast_ether_addr(&dest_mac);

    meta->wifi_hdr_sz = sizeof(struct ieee80211_hdr) +
                        (unicast ? sizeof(union qos_ctrl) : 0);

    /*
     * calculate how much extra space is required to hold the
     * 802.11, CCMP and 802.2 headers
     */
    uint8_t prepend_sz = meta->wifi_hdr_sz +
                         sizeof(struct ccmp_hdr) +
                         sizeof(struct ieee8022_snap_hdr) -
                         sizeof(struct ether_hdr);

    /* prepend space to the front of the packet mbuf */
    if (likely((wifi_hdr = (struct ieee80211_hdr *)
                                    rte_pktmbuf_prepend(mbuf, prepend_sz)) != NULL)) {
        /*
         * fill in 802.11 header
         * - NOTE: not locking the vap element before accessing the
         *   address, as the address should hardly ever change
         *   - even if the vap element is being/has been reset and
         *     a garbage address is used, it's not a big deal as
         *     that vap is no longer live and the packet won't be
         *     delivered through it anyways
         */
        wifi_hdr->frame_ctrl.u16 = FRAME_CTRL_DL_DEFAULT;
        ether_addr_copy(&dest_mac, &(wifi_hdr->addr1));
        ether_addr_copy(&(meta->vap->address), &(wifi_hdr->addr2));
        ether_addr_copy(&src_mac, &(wifi_hdr->addr3));
        wifi_hdr->seq_ctrl.u16 = 0;
        wifi_hdr->duration_id = 0;

        /*
         * if unicast, fill in QoS Control field
         * if broadcast/multicast, set 802.11::FrameCtrl::SubType to DATA
         */
        if (likely(unicast)) {
            meta->p_qc = (union qos_ctrl *)&wifi_hdr[1];
            meta->p_qc->u16 = 0; /* TID = 0; all other fields = 0 */
            ccmp_hdr = (struct ccmp_hdr *)&meta->p_qc[1];
            meta->has_qc = 1;
        } else {
            wifi_hdr->frame_ctrl.le.sub_type = IEEE80211_DATA_SUBTYPE_DATA;
            ccmp_hdr = (struct ccmp_hdr *)&wifi_hdr[1];
        }

        /* fill in 802.2-SNAP header */
        snap_hdr = (struct ieee8022_snap_hdr *)&ccmp_hdr[1];
        snap_hdr->ssap = SSAP_SNAP;
        snap_hdr->dsap = DSAP_SNAP;
        snap_hdr->control = CTRL_UNNUMBERED;
        RESET_VENDOR_ID(snap_hdr->vendor_id);
        snap_hdr->ether_type = ether_type;

        /*
         * append space to the end of the packet mbuf for
         * CCMP MIC
         * - MIC is half the length of the key
         */
        if (unlikely(rte_pktmbuf_append(mbuf, (meta->sa->tk_len >> 1)) == NULL))
            return RWPA_STS_ERR;

        /* get pointers to the station and bssid MAC addresses*/
        ieee80211_addrs_get(wifi_hdr, &(meta->p_sta_addr), &(meta->p_bssid));

    } else /* wifi_hdr == NULL */
        return RWPA_STS_ERR;

    return RWPA_STS_OK;
}

/*
 * 802.11 -> Ethernet II Conversion
 */
enum rwpa_status
ieee80211_to_ether_convert(struct rte_mbuf  *mbuf,
                           struct rwpa_meta *meta)
{
    struct ieee80211_hdr *wifi_hdr;
    struct ieee8022_snap_hdr *snap_hdr;
    struct ether_hdr *eth_hdr;
    struct ether_addr dest_mac, src_mac;
    uint16_t ether_type;

    wifi_hdr = rte_pktmbuf_mtod(mbuf, struct ieee80211_hdr *);

    if (unlikely(wifi_hdr == NULL ||
                 meta == NULL))
        return RWPA_STS_ERR;

    /* save src and dest MACs and etherType*/
    ether_addr_copy(&(wifi_hdr->addr3), &dest_mac);
    ether_addr_copy(&(wifi_hdr->addr2), &src_mac);

    /* find the start of the snap header */
    snap_hdr = (struct ieee8022_snap_hdr *)
                       (((uint8_t *)wifi_hdr) +
                        meta->wifi_hdr_sz +
                        (meta->wep ? sizeof(struct ccmp_hdr) : 0));

    ether_type = snap_hdr->ether_type;

    uint8_t adj_sz = sizeof(struct ieee80211_hdr) +
                     (meta->has_a4 ? sizeof(struct ether_addr) : 0) +
                     (meta->has_qc ? sizeof(union qos_ctrl) : 0) +
                     (meta->wep ? sizeof(struct ccmp_hdr) : 0) +
                     sizeof(struct ieee8022_snap_hdr) -
                     sizeof(struct ether_hdr);

    /* remove space from the front of the packet mbuf */
    if (likely((eth_hdr = (struct ether_hdr *)
                                    rte_pktmbuf_adj(mbuf, adj_sz)) != NULL)) {
        /* fill in the ethernet header */
        ether_addr_copy(&dest_mac, &(eth_hdr->d_addr));
        ether_addr_copy(&src_mac, &(eth_hdr->s_addr));
        eth_hdr->ether_type = ether_type;
    } else
        return RWPA_STS_ERR;

    if (meta->wep) {
        /*
         * remove space from the end of the packet mbuf where
         * the CCMP MIC is
         * - MIC is half the length of the key
         */
        if (unlikely(meta->sa == NULL || 
                     rte_pktmbuf_trim(mbuf, (meta->sa->tk_len >> 1)) == -1))
            return RWPA_STS_ERR;
    }

    return RWPA_STS_OK;
}
