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

#include <stdint.h>
#include <stdio.h>

#include <rte_common.h>
#include <rte_mbuf.h>

#include "r-wpa_global_vars.h"
#include "app.h"
#include "key.h"
#include "ccmp_sa.h"
#include "store.h"
#include "vap.h"
#include "station.h"
#include "meta.h"
#include "wpapt_cdi.h"
#include "wpapt_cdi_helper.h"
#include "tls_msg_handler.h"
#include "ieee80211.h"
#include "ieee80211_utils.h"
#include "ieee8022.h"
#include "eapol.h"

int init(struct rte_mbuf *data);
int status(struct rte_mbuf *data);
int bss_add(struct rte_mbuf *data);
int bss_del(struct rte_mbuf *data);
int sta_add(struct rte_mbuf *data);
int sta_del(struct rte_mbuf *data);
int key_set(struct rte_mbuf *data);
int frame(struct rte_mbuf *data);
int eapol_mic(struct rte_mbuf *data);

const struct ether_addr gtk_addr = { .addr_bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

tls_handler_ctx_t tls_handlers[] = {
    { SOCKET, (uint16_t)WPAPT_CDI_MSG_INIT,       init      },
    { SOCKET, (uint16_t)WPAPT_CDI_MSG_STATUS,     status    },
    { SOCKET, (uint16_t)WPAPT_CDI_MSG_BSS_ADD,    bss_add   },
    { SOCKET, (uint16_t)WPAPT_CDI_MSG_BSS_REMOVE, bss_del   },
    { SOCKET, (uint16_t)WPAPT_CDI_MSG_STA_ADD,    sta_add   },
    { SOCKET, (uint16_t)WPAPT_CDI_MSG_STA_REMOVE, sta_del   },
    { SOCKET, (uint16_t)WPAPT_CDI_MSG_SET_KEY,    key_set   },
    { SOCKET, (uint16_t)WPAPT_CDI_MSG_FRAME,      frame     },
    { SOCKET, (uint16_t)WPAPT_CDI_MSG_EAPOL_MIC,  eapol_mic },
    { EOL }
};

int init(struct rte_mbuf *data)
{
    struct wpapt_cdi_msg_init *init =
            rte_pktmbuf_mtod(data, struct wpapt_cdi_msg_init *);

    init->peer_version = R_WPA_PEER_VERISON;

    /* rewrite DVNF Peer_id and trim remaining bytes if shorter */
    if (R_WPA_PEER_ID_LEN < init->peer_id_len) {
        unsigned diff = init->peer_id_len - R_WPA_PEER_ID_LEN;
        if (rte_pktmbuf_trim(data, diff) == -1) {
            RTE_LOG(ERR, RWPA_TLS,
                    "Error trimming %d bytes from init message peer id\n", diff);
        }
    } else {
        unsigned diff = R_WPA_PEER_ID_LEN - init->peer_id_len;
        if (rte_pktmbuf_append(data, diff) == NULL) {
            RTE_LOG(ERR, RWPA_TLS,
                    "Error appending %d bytes to init message peer id\n", diff);
        }
    }
    snprintf(init->peer_id, R_WPA_PEER_ID_LEN, R_WPA_PEER_ID);
    init->peer_id_len = R_WPA_PEER_ID_LEN;

    if (unlikely(wpapt_cdi_hdr_encap(data, WPAPT_CDI_MSG_INIT,
                                     (sizeof(struct wpapt_cdi_msg_init) +
                                     init->peer_id_len)) == RWPA_STS_ERR)) {
        RTE_LOG(ERR, RWPA_TLS,
                "Error adding TLS message header\n");
        return TLS_HANDLER_ACTION_ERROR;
    }

    return TLS_HANDLER_ACTION_TLS_TX;
}

int status(struct rte_mbuf *data)
{
    struct wpapt_cdi_msg_status *status =
            rte_pktmbuf_mtod(data, struct wpapt_cdi_msg_status *);

    if (!status) return TLS_HANDLER_ACTION_ERROR;

    return TLS_HANDLER_ACTION_NONE;
}

int bss_add(struct rte_mbuf *data)
{
    struct wpapt_cdi_msg_bss_add *bss_add =
            rte_pktmbuf_mtod(data, struct wpapt_cdi_msg_bss_add *);

    struct ether_addr vap_addr;

    memcpy(vap_addr.addr_bytes, bss_add->bssid, 6);

    if (store_vap_add(&vap_addr) == NULL) {
        RTE_LOG(ERR, RWPA_TLS,
                "Could not add bss (%02x:%02x:%02x:%02x:%02x:%02x)"
                " to store\n",
                bss_add->bssid[0],
                bss_add->bssid[1],
                bss_add->bssid[2],
                bss_add->bssid[3],
                bss_add->bssid[4],
                bss_add->bssid[5]);
    }

    return TLS_HANDLER_ACTION_NONE;
}

int bss_del(struct rte_mbuf *data)
{
    struct wpapt_cdi_msg_bss_remove *bss_remove =
            rte_pktmbuf_mtod(data, struct wpapt_cdi_msg_bss_remove *);

    struct ether_addr vap_addr;

    memcpy(vap_addr.addr_bytes, bss_remove->bssid, 6);

    if (store_vap_del(&vap_addr) != RWPA_STS_OK) {
        RTE_LOG(ERR, RWPA_TLS,
                "Could not delete bss (%02x:%02x:%02x:%02x:%02x:%02x)"
                " from store\n",
                bss_remove->bssid[0],
                bss_remove->bssid[1],
                bss_remove->bssid[2],
                bss_remove->bssid[3],
                bss_remove->bssid[4],
                bss_remove->bssid[5]);
    }

    return TLS_HANDLER_ACTION_NONE;
}

int sta_add(struct rte_mbuf *data)
{
    struct wpapt_cdi_msg_sta_add *msg_sta_add =
            rte_pktmbuf_mtod(data, struct wpapt_cdi_msg_sta_add *);

    struct ether_addr vap_addr;
    memcpy(vap_addr.addr_bytes, msg_sta_add->bssid, 6);

    struct ether_addr sta_addr;
    memcpy(sta_addr.addr_bytes, msg_sta_add->sta_addr, 6);

    if (store_sta_add(&sta_addr, &vap_addr) == NULL) {
        RTE_LOG(ERR, RWPA_TLS,
                "Could not add sta (%02x:%02x:%02x:%02x:%02x:%02x) to "
                "bss (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                msg_sta_add->sta_addr[0],
                msg_sta_add->sta_addr[1],
                msg_sta_add->sta_addr[2],
                msg_sta_add->sta_addr[3],
                msg_sta_add->sta_addr[4],
                msg_sta_add->sta_addr[5],
                msg_sta_add->bssid[0],
                msg_sta_add->bssid[1],
                msg_sta_add->bssid[2],
                msg_sta_add->bssid[3],
                msg_sta_add->bssid[4],
                msg_sta_add->bssid[5]);
    }

    return TLS_HANDLER_ACTION_NONE;
}

int sta_del(struct rte_mbuf *data)
{
    struct wpapt_cdi_msg_sta_remove *msg_sta_del =
            rte_pktmbuf_mtod(data, struct wpapt_cdi_msg_sta_remove *);

    struct ether_addr sta_addr;
    memcpy(sta_addr.addr_bytes, msg_sta_del->sta_addr, 6);

    if (store_sta_del(&sta_addr) != RWPA_STS_OK) {
        RTE_LOG(ERR, RWPA_TLS,
                "Could not delete sta (%02x:%02x:%02x:%02x:%02x:%02x)"
                " from store\n",
                msg_sta_del->sta_addr[0],
                msg_sta_del->sta_addr[1],
                msg_sta_del->sta_addr[2],
                msg_sta_del->sta_addr[3],
                msg_sta_del->sta_addr[4],
                msg_sta_del->sta_addr[5]);
    }

    return TLS_HANDLER_ACTION_NONE;
}

int key_set(struct rte_mbuf *data)
{
    struct wpapt_cdi_msg_set_key *set_key =
            rte_pktmbuf_mtod(data, struct wpapt_cdi_msg_set_key *);

    unsigned key_id = set_key->key_idx;
    /* 0: PTK; 1,2: GTK; 3,4: IGTK */

    if (key_id == 0) {
        struct sta_elem *sta;
        sta = store_sta_lookup((struct ether_addr *)set_key->sta_addr);
        if (sta == NULL) {
            RTE_LOG(ERR, RWPA_TLS,
                    "Could not lookup sta (%02x:%02x:%02x:%02x:%02x:%02x) "
                    "from store for key set\n",
                    set_key->sta_addr[0],
                    set_key->sta_addr[1],
                    set_key->sta_addr[2],
                    set_key->sta_addr[3],
                    set_key->sta_addr[4],
                    set_key->sta_addr[5]);
            return TLS_HANDLER_ACTION_ERROR;
        }
        sta_ptk_set(sta, (const uint8_t *)&(set_key->key), set_key->key_len);

    } else if (key_id == GTK1 || key_id == GTK2) {
        if (is_same_ether_addr((struct ether_addr *)set_key->sta_addr, &gtk_addr)) {
            /* Set GTK */
            struct vap_elem* vap = store_vap_lookup((struct ether_addr *)set_key->bssid);
            if (vap) {
                vap_gtk_set(vap, key_id,
                            (const uint8_t *)&(set_key->key),
                            set_key->key_len, TRUE);
            }
        }
    }

    return TLS_HANDLER_ACTION_NONE;
}

int frame(struct rte_mbuf *data)
{
    struct wpapt_cdi_msg_frame *frame =
            rte_pktmbuf_mtod(data, struct wpapt_cdi_msg_frame *);

    if (frame->frame_type == WPAPT_FRAME_EAPOL) {
        /*
         * EAPOL frame
         * - remove the wpapt_cdi_msg_frame
         */
        if (unlikely(wpapt_cdi_frame_decap(data) == RWPA_STS_ERR)) {
            RTE_LOG(ERR, RWPA_TLS,
                    "Error removing message frame encapsulation\n");
            return TLS_HANDLER_ACTION_ERROR;
        }

        return TLS_HANDLER_ACTION_PROCESS;

    } else if (frame->frame_type == WPAPT_FRAME_MGMT) {
        /*
         * MGMT frame
         * - not supported now
         */
        return TLS_HANDLER_ACTION_NONE;
    }

    return TLS_HANDLER_ACTION_NONE;
}

/* This form of message is currently not supported by CVNF hostapd-auth */
int eapol_mic(struct rte_mbuf *data)
{
    struct wpapt_cdi_msg_eapol_mic *eapol_mic =
            rte_pktmbuf_mtod(data, struct wpapt_cdi_msg_eapol_mic *);

    if (eapol_mic->frame_type == WPAPT_FRAME_EAPOL) {
        /*
         * EAPOL frame
         * - remove the wpapt_cdi_msg_eapol_mic
         */
        if (unlikely(wpapt_cdi_eapol_mic_decap(data) == RWPA_STS_ERR)) {
            RTE_LOG(ERR, RWPA_TLS,
                    "Error removing message eapol mic encapsulation\n");
            return TLS_HANDLER_ACTION_ERROR;
        }

        struct vap_elem *vap = store_vap_lookup((struct ether_addr *)&eapol_mic->bssid);
	if (vap == NULL) {
            RTE_LOG(ERR, RWPA_TLS,
                    "vAP (%02x:%02x:%02x:%02x:%02x:%02x) is not in store\n",
                    eapol_mic->bssid[0],
                    eapol_mic->bssid[1],
                    eapol_mic->bssid[2],
                    eapol_mic->bssid[3],
                    eapol_mic->bssid[4],
                    eapol_mic->bssid[5]);
            return TLS_HANDLER_ACTION_NONE;
        }

        /*
         * Set Key RSC to gtk1_ctr_encrypt or gtk2_ctr_encrypt
         * Correct value returned by below function.
         */
        uint64_t key_rsc = vap_current_gtk_counter_get(vap);

        struct ieee80211_hdr *hdr = rte_pktmbuf_mtod(data, struct ieee80211_hdr *);
        struct rwpa_meta meta;
        ieee80211_packet_parse(data, &meta);
        struct wpa_eapol_key *eapol_key = (struct wpa_eapol_key *)((uint8_t *)hdr +
                                                                   meta.wifi_hdr_sz +
                                                                   sizeof(struct ieee8022_snap_hdr) );
        /* Update RSC with GTK. */
        eapol_key->key_rsc = key_rsc;

        /* Regenerate MIC. */
        vnf_wpa_eapol_key_mic((const uint8_t *)eapol_mic->key,
                              eapol_mic->key_len,
                              eapol_mic->akm,
                              (const uint8_t *)eapol_key,
                              sizeof(struct wpa_eapol_key) +
                                  (eapol_key->key_data_length[0] << 8) +
                                  eapol_key->key_data_length[1],
                              eapol_key->key_mic);

        return TLS_HANDLER_ACTION_PROCESS;

    } else if (eapol_mic->frame_type == WPAPT_FRAME_MGMT) {
        /*
         * MGMT frame
         * - not supported now
         */
        return TLS_HANDLER_ACTION_NONE;
    }

    return TLS_HANDLER_ACTION_NONE;
}

