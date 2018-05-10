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

#include <rte_common.h>
#include <rte_malloc.h>

#include "r-wpa_global_vars.h"
#include "app.h"
#include "statistics_handler_cycles.h"
#include "statistics_capture_ports.h"
#include "statistics_handler_ports.h"
#include "statistics_capture_sta_lookup.h"
#include "statistics_handler_sta_lookup.h"
#include "statistics_capture_crypto.h"
#include "statistics_handler_crypto.h"
#include "cycle_capture.h"
#include "uplink_thread.h"
#include "downlink_thread.h"

/* reference to original mem locations of cycle stats */
static struct cycle_stats *original_cycle_sts = NULL;

/* 
 * mem where shadow copy of original data is kept.
 * - memcpy is performed between original and shadow copy regions, as
 *   original stat counters change continuously as application runs
 */
static struct cycle_stats *shadow_cycle_sts = NULL;
static size_t shadow_cycle_sts_sz = 0;
static uint32_t shadow_cycle_sts_num = 0;

static struct parsed_statistics_cycle *parsed_cycle_sts = NULL;

static struct stats_ports *parsed_sts_ports = NULL;
static struct stats_sta_lookup *parsed_sts_sta_lookup = NULL;
static struct parsed_stats_crypto *parsed_sts_crypto = NULL;

static void
calculate_parsed_stats_cycle(void)
{
    struct parsed_statistics_cycle *p = parsed_cycle_sts;
    struct cycle_stats *o = shadow_cycle_sts;

    uint8_t ul_src_port = uplink_thread_src_port_get();
    uint8_t dl_src_port = downlink_thread_src_port_get();

    uint64_t ul_ipackets;
    struct rte_eth_dev_info dev_info;

    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(ul_src_port, &dev_info);
    if (strcmp(dev_info.driver_name, "net_i40e_vf") == 0) {
        ul_ipackets =
            parsed_sts_ports->stats[ul_src_port].ipackets -
            parsed_sts_ports->stats[ul_src_port].imissed;
    } else {
        ul_ipackets = parsed_sts_ports->stats[ul_src_port].ipackets;
    }

    /* UL_PMD_RX */
    if (o[CYCLE_CAPTURE_UL_PMD_RX].reset == FALSE) {
        p->ul_pmd_rx_cycles_total = o[CYCLE_CAPTURE_UL_PMD_RX].total_cycles;
        p->ul_pmd_rx_calls_total  = o[CYCLE_CAPTURE_UL_PMD_RX].call_count;
    } else {
        p->ul_pmd_rx_cycles_total = 0;
        p->ul_pmd_rx_calls_total = 0;
    }
    if (p->ul_pmd_rx_calls_total) {
        p->ul_pmd_rx_cycles_per_call =
            p->ul_pmd_rx_cycles_total / p->ul_pmd_rx_calls_total;
    }
    if (parsed_sts_ports->stats[ul_src_port].ipackets) {
        p->ul_pmd_rx_cycles_per_mbuf =
            p->ul_pmd_rx_cycles_total / ul_ipackets;
    }

    /* UL_PMD_RX_EXCL_EMPTIES */
    if (o[CYCLE_CAPTURE_UL_PMD_RX_EXCL_EMPTIES].reset == FALSE) {
        p->ul_pmd_rx_excl_empties_cycles_total =
            o[CYCLE_CAPTURE_UL_PMD_RX_EXCL_EMPTIES].total_cycles;
        p->ul_pmd_rx_excl_empties_calls_total  =
            o[CYCLE_CAPTURE_UL_PMD_RX_EXCL_EMPTIES].call_count;
    } else {
        p->ul_pmd_rx_excl_empties_cycles_total = 0;
        p->ul_pmd_rx_excl_empties_calls_total = 0;
    }
    if (p->ul_pmd_rx_excl_empties_calls_total) {
        p->ul_pmd_rx_excl_empties_cycles_per_call =
            p->ul_pmd_rx_excl_empties_cycles_total /
            p->ul_pmd_rx_excl_empties_calls_total;
    }
    if (ul_ipackets) {
        p->ul_pmd_rx_excl_empties_cycles_per_mbuf =
            p->ul_pmd_rx_excl_empties_cycles_total /
            ul_ipackets;
    }

    /* UL_PROCESS_FULL */
    if (o[CYCLE_CAPTURE_UL_PROCESS_FULL].reset == FALSE) {
        p->ul_process_full_cycles_total =
            o[CYCLE_CAPTURE_UL_PROCESS_FULL].total_cycles;
        p->ul_process_full_calls_total =
            o[CYCLE_CAPTURE_UL_PROCESS_FULL].call_count;
    } else {
        p->ul_process_full_cycles_total = 0;
        p->ul_process_full_calls_total = 0;
    }
    if (p->ul_process_full_calls_total) {
        p->ul_process_full_cycles_per_call =
            p->ul_process_full_cycles_total /
            p->ul_process_full_calls_total;
    }
    if (ul_ipackets) {
        p->ul_process_full_cycles_per_mbuf =
            p->ul_process_full_cycles_total /
            ul_ipackets;
    }

    /* UL_PKT_CLASSIFY */
    if (o[CYCLE_CAPTURE_UL_INITIAL_PKT_CLASSIFY].reset == FALSE) {
        p->ul_initial_pkt_classify_cycles_total =
            o[CYCLE_CAPTURE_UL_INITIAL_PKT_CLASSIFY].total_cycles;
        p->ul_initial_pkt_classify_calls_total =
             o[CYCLE_CAPTURE_UL_INITIAL_PKT_CLASSIFY].call_count;
    } else {
        p->ul_initial_pkt_classify_cycles_total = 0;
        p->ul_initial_pkt_classify_calls_total = 0;
    }
    if (p->ul_initial_pkt_classify_calls_total) {
        p->ul_initial_pkt_classify_cycles_per_call =
            p->ul_initial_pkt_classify_cycles_total /
            p->ul_initial_pkt_classify_calls_total;
        p->ul_initial_pkt_classify_cycles_per_mbuf =
            p->ul_initial_pkt_classify_cycles_total /
            p->ul_initial_pkt_classify_calls_total;
    }

    /* UL_AP_TUNNEL_DECAP */
    if (o[CYCLE_CAPTURE_UL_AP_TUNNEL_DECAP].reset == FALSE) {
        p->ul_ap_tunnel_decap_cycles_total =
            o[CYCLE_CAPTURE_UL_AP_TUNNEL_DECAP].total_cycles;
        p->ul_ap_tunnel_decap_calls_total =
            o[CYCLE_CAPTURE_UL_AP_TUNNEL_DECAP].call_count;
    } else {
        p->ul_ap_tunnel_decap_cycles_total = 0;
        p->ul_ap_tunnel_decap_calls_total = 0;
    }
    if (p->ul_ap_tunnel_decap_calls_total) {
        p->ul_ap_tunnel_decap_cycles_per_call =
            p->ul_ap_tunnel_decap_cycles_total /
            p->ul_ap_tunnel_decap_calls_total;
        p->ul_ap_tunnel_decap_cycles_per_mbuf =
            p->ul_ap_tunnel_decap_cycles_total /
            p->ul_ap_tunnel_decap_calls_total;
    }

    /* UL_VAP_HDR_PARSE */
    if (o[CYCLE_CAPTURE_UL_VAP_HDR_PARSE].reset == FALSE) {
        p->ul_vap_hdr_parse_cycles_total =
            o[CYCLE_CAPTURE_UL_VAP_HDR_PARSE].total_cycles;
        p->ul_vap_hdr_parse_calls_total =
            o[CYCLE_CAPTURE_UL_VAP_HDR_PARSE].call_count;
    } else {
        p->ul_vap_hdr_parse_cycles_total = 0;
        p->ul_vap_hdr_parse_calls_total = 0;
    }
    if (p->ul_vap_hdr_parse_calls_total) {
        p->ul_vap_hdr_parse_cycles_per_call =
            p->ul_vap_hdr_parse_cycles_total /
            p->ul_vap_hdr_parse_calls_total;
        p->ul_vap_hdr_parse_cycles_per_mbuf =
            p->ul_vap_hdr_parse_cycles_total /
            p->ul_vap_hdr_parse_calls_total;
    }

    /* UL_VAP_PAYLOAD_REASSEMBLE */
    if (o[CYCLE_CAPTURE_UL_VAP_PAYLOAD_REASSEMBLE].reset == FALSE) {
        p->ul_vap_payload_reassemble_cycles_total =
            o[CYCLE_CAPTURE_UL_VAP_PAYLOAD_REASSEMBLE].total_cycles;
        p->ul_vap_payload_reassemble_calls_total =
            o[CYCLE_CAPTURE_UL_VAP_PAYLOAD_REASSEMBLE].call_count;
    } else {
        p->ul_vap_payload_reassemble_cycles_total = 0;
        p->ul_vap_payload_reassemble_calls_total = 0;
    }
    if (p->ul_vap_payload_reassemble_calls_total) {
        p->ul_vap_payload_reassemble_cycles_per_call =
            p->ul_vap_payload_reassemble_cycles_total /
            p->ul_vap_payload_reassemble_calls_total;
        p->ul_vap_payload_reassemble_cycles_per_mbuf =
            p->ul_vap_payload_reassemble_cycles_total /
            p->ul_vap_payload_reassemble_calls_total;
    }

    /* UL_VAP_HDR_DECAP */
    if (o[CYCLE_CAPTURE_UL_VAP_HDR_DECAP].reset == FALSE) {
        p->ul_vap_hdr_decap_cycles_total =
            o[CYCLE_CAPTURE_UL_VAP_HDR_DECAP].total_cycles;
        p->ul_vap_hdr_decap_calls_total =
            o[CYCLE_CAPTURE_UL_VAP_HDR_DECAP].call_count;
    } else {
        p->ul_vap_hdr_decap_cycles_total = 0;
        p->ul_vap_hdr_decap_calls_total = 0;
    }
    if (p->ul_vap_hdr_decap_calls_total) {
        p->ul_vap_hdr_decap_cycles_per_call =
            p->ul_vap_hdr_decap_cycles_total /
            p->ul_vap_hdr_decap_calls_total;
        p->ul_vap_hdr_decap_cycles_per_mbuf =
            p->ul_vap_hdr_decap_cycles_total /
            p->ul_vap_hdr_decap_calls_total;
    }

    /* UL_VAP_TLV_DECAP */
    if (o[CYCLE_CAPTURE_UL_VAP_TLV_DECAP].reset == FALSE) {
        p->ul_vap_tlv_decap_cycles_total =
            o[CYCLE_CAPTURE_UL_VAP_TLV_DECAP].total_cycles;
        p->ul_vap_tlv_decap_calls_total =
            o[CYCLE_CAPTURE_UL_VAP_TLV_DECAP].call_count;
    } else {
        p->ul_vap_tlv_decap_cycles_total = 0;
        p->ul_vap_tlv_decap_calls_total = 0;
    }
    if (p->ul_vap_tlv_decap_calls_total) {
        p->ul_vap_tlv_decap_cycles_per_call =
            p->ul_vap_tlv_decap_cycles_total /
            p->ul_vap_tlv_decap_calls_total;
        p->ul_vap_tlv_decap_cycles_per_mbuf =
            p->ul_vap_tlv_decap_cycles_total /
            p->ul_vap_tlv_decap_calls_total;
    }

    /* UL_IEEE80211_PKT_PARSE */
    if (o[CYCLE_CAPTURE_UL_IEEE80211_PKT_PARSE].reset == FALSE) {
        p->ul_ieee80211_pkt_parse_cycles_total =
            o[CYCLE_CAPTURE_UL_IEEE80211_PKT_PARSE].total_cycles;
        p->ul_ieee80211_pkt_parse_calls_total =
            o[CYCLE_CAPTURE_UL_IEEE80211_PKT_PARSE].call_count;
    } else {
        p->ul_ieee80211_pkt_parse_cycles_total = 0;
        p->ul_ieee80211_pkt_parse_calls_total = 0;
    }
    if (p->ul_ieee80211_pkt_parse_calls_total) {
        p->ul_ieee80211_pkt_parse_cycles_per_call =
            p->ul_ieee80211_pkt_parse_cycles_total /
            p->ul_ieee80211_pkt_parse_calls_total;
        p->ul_ieee80211_pkt_parse_cycles_per_mbuf =
            p->ul_ieee80211_pkt_parse_cycles_total /
            p->ul_ieee80211_pkt_parse_calls_total;
    }

    /* UL_STA_LOOKUP */
    if (o[CYCLE_CAPTURE_UL_STA_LOOKUP].reset == FALSE) {
        p->ul_sta_lookup_cycles_total =
            o[CYCLE_CAPTURE_UL_STA_LOOKUP].total_cycles;
        p->ul_sta_lookup_calls_total =
            o[CYCLE_CAPTURE_UL_STA_LOOKUP].call_count;
    } else {
        p->ul_sta_lookup_cycles_total = 0;
        p->ul_sta_lookup_calls_total = 0;
    }
    if (p->ul_sta_lookup_calls_total) {
        p->ul_sta_lookup_cycles_per_call =
            p->ul_sta_lookup_cycles_total /
            p->ul_sta_lookup_calls_total;
    }
    if (parsed_sts_sta_lookup[STATS_STA_LOOKUP_TYPE_UL].num_pkts) {
        p->ul_sta_lookup_cycles_per_mbuf =
            p->ul_sta_lookup_cycles_total /
            parsed_sts_sta_lookup[STATS_STA_LOOKUP_TYPE_UL].num_pkts;
    }

    /* UL_STA_LOCK */
    if (o[CYCLE_CAPTURE_UL_STA_LOCK].reset == FALSE) {
        p->ul_sta_lock_cycles_total =
            o[CYCLE_CAPTURE_UL_STA_LOCK].total_cycles;
        p->ul_sta_lock_calls_total =
            o[CYCLE_CAPTURE_UL_STA_LOCK].call_count;
    } else {
        p->ul_sta_lock_cycles_total = 0;
        p->ul_sta_lock_calls_total = 0;
    }
    if (p->ul_sta_lock_calls_total) {
        p->ul_sta_lock_cycles_per_call =
            p->ul_sta_lock_cycles_total /
            p->ul_sta_lock_calls_total;
        p->ul_sta_lock_cycles_per_mbuf =
            p->ul_sta_lock_cycles_total /
            p->ul_sta_lock_calls_total;
    }

    /* UL_STA_DECRYPT_DATA_GET */
    if (o[CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_GET].reset == FALSE) {
        p->ul_sta_decrypt_data_get_cycles_total =
            o[CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_GET].total_cycles;
        p->ul_sta_decrypt_data_get_calls_total =
            o[CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_GET].call_count;
    } else {
        p->ul_sta_decrypt_data_get_cycles_total = 0;
        p->ul_sta_decrypt_data_get_calls_total = 0;
    }
    if (p->ul_sta_decrypt_data_get_calls_total) {
        p->ul_sta_decrypt_data_get_cycles_per_call =
            p->ul_sta_decrypt_data_get_cycles_total /
            p->ul_sta_decrypt_data_get_calls_total;
        p->ul_sta_decrypt_data_get_cycles_per_mbuf =
            p->ul_sta_decrypt_data_get_cycles_total /
            p->ul_sta_decrypt_data_get_calls_total;
    }

    /* UL_CCMP_REPLAY_DETECT */
    if (o[CYCLE_CAPTURE_UL_CCMP_REPLAY_DETECT].reset == FALSE) {
        p->ul_ccmp_replay_detect_cycles_total =
            o[CYCLE_CAPTURE_UL_CCMP_REPLAY_DETECT].total_cycles;
        p->ul_ccmp_replay_detect_calls_total =
            o[CYCLE_CAPTURE_UL_CCMP_REPLAY_DETECT].call_count;
    } else {
        p->ul_ccmp_replay_detect_cycles_total = 0;
        p->ul_ccmp_replay_detect_calls_total = 0;
    }
    if (p->ul_ccmp_replay_detect_calls_total) {
        p->ul_ccmp_replay_detect_cycles_per_call =
            p->ul_ccmp_replay_detect_cycles_total /
            p->ul_ccmp_replay_detect_calls_total;
        p->ul_ccmp_replay_detect_cycles_per_mbuf =
            p->ul_ccmp_replay_detect_cycles_total /
            p->ul_ccmp_replay_detect_calls_total;
    }

    /* UL_STA_DECRYPT_DATA_UPDATE */
    if (o[CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_UPDATE].reset == FALSE) {
        p->ul_sta_decrypt_data_update_cycles_total =
            o[CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_UPDATE].total_cycles;
        p->ul_sta_decrypt_data_update_calls_total =
            o[CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_UPDATE].call_count;
    } else {
        p->ul_sta_decrypt_data_update_cycles_total = 0;
        p->ul_sta_decrypt_data_update_calls_total = 0;
    }
    if (p->ul_sta_decrypt_data_update_calls_total) {
        p->ul_sta_decrypt_data_update_cycles_per_call =
            p->ul_sta_decrypt_data_update_cycles_total /
            p->ul_sta_decrypt_data_update_calls_total;
        p->ul_sta_decrypt_data_update_cycles_per_mbuf =
            p->ul_sta_decrypt_data_update_cycles_total /
            p->ul_sta_decrypt_data_update_calls_total;
    }

    /* UL_CRYPTO_ENQUEUE */
    if (o[CYCLE_CAPTURE_UL_CRYPTO_ENQUEUE].reset == FALSE) {
        p->ul_crypto_enq_cycles_total =
            o[CYCLE_CAPTURE_UL_CRYPTO_ENQUEUE].total_cycles;
        p->ul_crypto_enq_calls_total =
            o[CYCLE_CAPTURE_UL_CRYPTO_ENQUEUE].call_count;
    } else {
        p->ul_crypto_enq_cycles_total = 0;
        p->ul_crypto_enq_calls_total = 0;
    }
    if (p->ul_crypto_enq_calls_total) {
        p->ul_crypto_enq_cycles_per_call =
            p->ul_crypto_enq_cycles_total /
            p->ul_crypto_enq_calls_total;
    }
    p->ul_crypto_enq_cycles_per_mbuf =
        parsed_sts_crypto[STATS_CRYPTO_TYPE_UL].avg_cycles_per_enqueued_packet;

    /* UL_CRYPTO_DEQUEUE */
    if (o[CYCLE_CAPTURE_UL_CRYPTO_DEQUEUE].reset == FALSE) {
        p->ul_crypto_deq_cycles_total =
            o[CYCLE_CAPTURE_UL_CRYPTO_DEQUEUE].total_cycles;
        p->ul_crypto_deq_calls_total =
            o[CYCLE_CAPTURE_UL_CRYPTO_DEQUEUE].call_count;
    } else {
        p->ul_crypto_deq_cycles_total = 0;
        p->ul_crypto_deq_calls_total = 0;
    }
    if (p->ul_crypto_deq_calls_total) {
        p->ul_crypto_deq_cycles_per_call =
            p->ul_crypto_deq_cycles_total /
            p->ul_crypto_deq_calls_total;
    }
    p->ul_crypto_deq_cycles_per_mbuf =
        parsed_sts_crypto[STATS_CRYPTO_TYPE_UL].avg_cycles_per_dequeued_packet;

    /* UL_STA_UNLOCK */
    if (o[CYCLE_CAPTURE_UL_STA_UNLOCK].reset == FALSE) {
        p->ul_sta_unlock_cycles_total =
            o[CYCLE_CAPTURE_UL_STA_UNLOCK].total_cycles;
        p->ul_sta_unlock_calls_total =
            o[CYCLE_CAPTURE_UL_STA_UNLOCK].call_count;
    } else {
        p->ul_sta_unlock_cycles_total = 0;
        p->ul_sta_unlock_calls_total = 0;
    }
    if (p->ul_sta_unlock_calls_total) {
        p->ul_sta_unlock_cycles_per_call =
            p->ul_sta_unlock_cycles_total /
            p->ul_sta_unlock_calls_total;
        p->ul_sta_unlock_cycles_per_mbuf =
            p->ul_sta_unlock_cycles_total /
            p->ul_sta_unlock_calls_total;
    }

    /* UL_IEEE80211_PKT_CLASSIFY */
    if (o[CYCLE_CAPTURE_UL_IEEE80211_PKT_CLASSIFY].reset == FALSE) {
        p->ul_ieee80211_pkt_classify_cycles_total =
            o[CYCLE_CAPTURE_UL_IEEE80211_PKT_CLASSIFY].total_cycles;
        p->ul_ieee80211_pkt_classify_calls_total =
            o[CYCLE_CAPTURE_UL_IEEE80211_PKT_CLASSIFY].call_count;
    } else {
        p->ul_ieee80211_pkt_classify_cycles_total = 0;
        p->ul_ieee80211_pkt_classify_calls_total = 0;
    }
    if (p->ul_ieee80211_pkt_classify_calls_total) {
        p->ul_ieee80211_pkt_classify_cycles_per_call =
            p->ul_ieee80211_pkt_classify_cycles_total /
            p->ul_ieee80211_pkt_classify_calls_total;
        p->ul_ieee80211_pkt_classify_cycles_per_mbuf =
            p->ul_ieee80211_pkt_classify_cycles_total /
            p->ul_ieee80211_pkt_classify_calls_total;
    }

    /* UL_IEEE80211_TO_ETHER_CONV */
    if (o[CYCLE_CAPTURE_UL_IEEE80211_TO_ETHER_CONV].reset == FALSE) {
        p->ul_ieee80211_to_ether_conv_cycles_total =
            o[CYCLE_CAPTURE_UL_IEEE80211_TO_ETHER_CONV].total_cycles;
        p->ul_ieee80211_to_ether_conv_calls_total =
            o[CYCLE_CAPTURE_UL_IEEE80211_TO_ETHER_CONV].call_count;
    } else {
        p->ul_ieee80211_to_ether_conv_cycles_total = 0;
        p->ul_ieee80211_to_ether_conv_calls_total = 0;
    }
    if (p->ul_ieee80211_to_ether_conv_calls_total) {
        p->ul_ieee80211_to_ether_conv_cycles_per_call =
            p->ul_ieee80211_to_ether_conv_cycles_total /
            p->ul_ieee80211_to_ether_conv_calls_total;
        p->ul_ieee80211_to_ether_conv_cycles_per_mbuf =
            p->ul_ieee80211_to_ether_conv_cycles_total /
            p->ul_ieee80211_to_ether_conv_calls_total;
    }

    /* UL_GRE_ENCAP */
    if (o[CYCLE_CAPTURE_UL_GRE_ENCAP].reset == FALSE) {
        p->ul_gre_encap_cycles_total =
            o[CYCLE_CAPTURE_UL_GRE_ENCAP].total_cycles;
        p->ul_gre_encap_calls_total =
            o[CYCLE_CAPTURE_UL_GRE_ENCAP].call_count;
    } else {
        p->ul_gre_encap_cycles_total = 0;
        p->ul_gre_encap_calls_total = 0;
    }
    if (p->ul_gre_encap_calls_total) {
        p->ul_gre_encap_cycles_per_call =
            p->ul_gre_encap_cycles_total /
            p->ul_gre_encap_calls_total;
        p->ul_gre_encap_cycles_per_mbuf =
            p->ul_gre_encap_cycles_total /
            p->ul_gre_encap_calls_total;
    }

    /* UL_PMD_TX */
    if (o[CYCLE_CAPTURE_UL_PMD_TX].reset == FALSE) {
        p->ul_pmd_tx_cycles_total =
            o[CYCLE_CAPTURE_UL_PMD_TX].total_cycles;
        p->ul_pmd_tx_calls_total =
            o[CYCLE_CAPTURE_UL_PMD_TX].call_count;
    } else {
        p->ul_pmd_tx_cycles_total = 0;
        p->ul_pmd_tx_calls_total = 0;
    }
    if (p->ul_pmd_tx_calls_total) {
        p->ul_pmd_tx_cycles_per_call =
            p->ul_pmd_tx_cycles_total / p->ul_pmd_tx_calls_total;
        p->ul_pmd_tx_cycles_per_mbuf =
            p->ul_pmd_tx_cycles_total / p->ul_pmd_tx_calls_total;
    }

    /* UL_CCMP_DECAP */
    if (o[CYCLE_CAPTURE_UL_CCMP_DECAP].reset == FALSE) {
        p->ul_ccmp_decap_cycles_total =
            o[CYCLE_CAPTURE_UL_CCMP_DECAP].total_cycles;
        p->ul_ccmp_decap_calls_total =
            o[CYCLE_CAPTURE_UL_CCMP_DECAP].call_count;
    } else {
        p->ul_ccmp_decap_cycles_total = 0;
        p->ul_ccmp_decap_calls_total = 0;
    }
    if (p->ul_ccmp_decap_calls_total) {
        p->ul_ccmp_decap_cycles_per_call =
            p->ul_ccmp_decap_cycles_total /
            p->ul_ccmp_decap_calls_total;
        p->ul_ccmp_decap_cycles_per_mbuf =
            p->ul_ccmp_decap_cycles_total /
            p->ul_ccmp_decap_calls_total;
    }

    /* UL_WPAPT_CDI_FRAME_ENCAP */
    if (o[CYCLE_CAPTURE_UL_WPAPT_CDI_FRAME_ENCAP].reset == FALSE) {
        p->ul_wpapt_cdi_frame_encap_cycles_total =
            o[CYCLE_CAPTURE_UL_WPAPT_CDI_FRAME_ENCAP].total_cycles;
        p->ul_wpapt_cdi_frame_encap_calls_total =
            o[CYCLE_CAPTURE_UL_WPAPT_CDI_FRAME_ENCAP].call_count;
    } else {
        p->ul_wpapt_cdi_frame_encap_cycles_total = 0;
        p->ul_wpapt_cdi_frame_encap_calls_total = 0;
    }
    if (p->ul_wpapt_cdi_frame_encap_calls_total) {
        p->ul_wpapt_cdi_frame_encap_cycles_per_call =
            p->ul_wpapt_cdi_frame_encap_cycles_total /
            p->ul_wpapt_cdi_frame_encap_calls_total;
        p->ul_wpapt_cdi_frame_encap_cycles_per_mbuf =
            p->ul_wpapt_cdi_frame_encap_cycles_total /
            p->ul_wpapt_cdi_frame_encap_calls_total;
    }

    /* UL_WPAPT_CDI_HDR_ENCAP */
    if (o[CYCLE_CAPTURE_UL_WPAPT_CDI_HDR_ENCAP].reset == FALSE) {
        p->ul_wpapt_cdi_hdr_encap_cycles_total =
            o[CYCLE_CAPTURE_UL_WPAPT_CDI_HDR_ENCAP].total_cycles;
        p->ul_wpapt_cdi_hdr_encap_calls_total =
            o[CYCLE_CAPTURE_UL_WPAPT_CDI_HDR_ENCAP].call_count;
    } else {
        p->ul_wpapt_cdi_hdr_encap_cycles_total = 0;
        p->ul_wpapt_cdi_hdr_encap_calls_total = 0;
    }
    if (p->ul_wpapt_cdi_hdr_encap_calls_total) {
        p->ul_wpapt_cdi_hdr_encap_cycles_per_call =
            p->ul_wpapt_cdi_hdr_encap_cycles_total /
            p->ul_wpapt_cdi_hdr_encap_calls_total;
        p->ul_wpapt_cdi_hdr_encap_cycles_per_mbuf =
            p->ul_wpapt_cdi_hdr_encap_cycles_total /
            p->ul_wpapt_cdi_hdr_encap_calls_total;
    }

    /* UL_TLS_TX */
    if (o[CYCLE_CAPTURE_UL_TLS_TX].reset == FALSE) {
        p->ul_tls_tx_cycles_total =
            o[CYCLE_CAPTURE_UL_TLS_TX].total_cycles;
        p->ul_tls_tx_calls_total =
            o[CYCLE_CAPTURE_UL_TLS_TX].call_count;
    } else {
        p->ul_tls_tx_cycles_total = 0;
        p->ul_tls_tx_calls_total = 0;
    }
    if (p->ul_tls_tx_calls_total) {
        p->ul_tls_tx_cycles_per_call =
            p->ul_tls_tx_cycles_total /
            p->ul_tls_tx_calls_total;
        p->ul_tls_tx_cycles_per_mbuf =
            p->ul_tls_tx_cycles_total /
            p->ul_tls_tx_calls_total;
    }

    /* DL_PMD_RX */
    if (o[CYCLE_CAPTURE_DL_PMD_RX].reset == FALSE) {
        p->dl_pmd_rx_cycles_total =
            o[CYCLE_CAPTURE_DL_PMD_RX].total_cycles;
        p->dl_pmd_rx_calls_total =
            o[CYCLE_CAPTURE_DL_PMD_RX].call_count;
    } else {
        p->dl_pmd_rx_cycles_total = 0;
        p->dl_pmd_rx_calls_total = 0;
    }
    if (p->dl_pmd_rx_calls_total) {
        p->dl_pmd_rx_cycles_per_call =
            p->dl_pmd_rx_cycles_total / p->dl_pmd_rx_calls_total;
    }
    if (parsed_sts_ports->stats[dl_src_port].ipackets) {
        p->dl_pmd_rx_cycles_per_mbuf =
            p->dl_pmd_rx_cycles_total / parsed_sts_ports->stats[dl_src_port].ipackets;
    }

    /* DL_PMD_RX_EXCL_EMPTIES */
    if (o[CYCLE_CAPTURE_DL_PMD_RX_EXCL_EMPTIES].reset == FALSE) {
        p->dl_pmd_rx_excl_empties_cycles_total =
            o[CYCLE_CAPTURE_DL_PMD_RX_EXCL_EMPTIES].total_cycles;
        p->dl_pmd_rx_excl_empties_calls_total  =
            o[CYCLE_CAPTURE_DL_PMD_RX_EXCL_EMPTIES].call_count;
    } else {
        p->dl_pmd_rx_excl_empties_cycles_total = 0;
        p->dl_pmd_rx_excl_empties_calls_total = 0;
    }
    if (p->dl_pmd_rx_excl_empties_calls_total) {
        p->dl_pmd_rx_excl_empties_cycles_per_call =
            p->dl_pmd_rx_excl_empties_cycles_total /
            p->dl_pmd_rx_excl_empties_calls_total;
    }
    if (parsed_sts_ports->stats[dl_src_port].ipackets) {
        p->dl_pmd_rx_excl_empties_cycles_per_mbuf =
            p->dl_pmd_rx_excl_empties_cycles_total /
            parsed_sts_ports->stats[dl_src_port].ipackets;
    }

    /* DL_PROCESS_FULL */
    if (o[CYCLE_CAPTURE_DL_PROCESS_FULL].reset == FALSE) {
        p->dl_process_full_cycles_total =
            o[CYCLE_CAPTURE_DL_PROCESS_FULL].total_cycles;
        p->dl_process_full_calls_total =
            o[CYCLE_CAPTURE_DL_PROCESS_FULL].call_count;
    } else {
        p->dl_process_full_cycles_total = 0;
        p->dl_process_full_calls_total = 0;
    }
    if (p->dl_process_full_calls_total) {
        p->dl_process_full_cycles_per_call =
            p->dl_process_full_cycles_total /
            p->dl_process_full_calls_total;
    }
    if (parsed_sts_ports->stats[dl_src_port].ipackets) {
        p->dl_process_full_cycles_per_mbuf =
            p->dl_process_full_cycles_total /
            parsed_sts_ports->stats[dl_src_port].ipackets;
    }

    /* DL_PKT_CLASSIFY */
    if (o[CYCLE_CAPTURE_DL_INITIAL_PKT_CLASSIFY].reset == FALSE) {
        p->dl_initial_pkt_classify_cycles_total =
            o[CYCLE_CAPTURE_DL_INITIAL_PKT_CLASSIFY].total_cycles;
        p->dl_initial_pkt_classify_calls_total =
            o[CYCLE_CAPTURE_DL_INITIAL_PKT_CLASSIFY].call_count;
    } else {
        p->dl_initial_pkt_classify_cycles_total = 0;
        p->dl_initial_pkt_classify_calls_total = 0;
    }
    if (p->dl_initial_pkt_classify_calls_total) {
        p->dl_initial_pkt_classify_cycles_per_call =
            p->dl_initial_pkt_classify_cycles_total /
            p->dl_initial_pkt_classify_calls_total;
        p->dl_initial_pkt_classify_cycles_per_mbuf =
            p->dl_initial_pkt_classify_cycles_total /
            p->dl_initial_pkt_classify_calls_total;
    }

    /* DL_GRE_DECAP */
    if (o[CYCLE_CAPTURE_DL_GRE_DECAP].reset == FALSE) {
        p->dl_gre_decap_cycles_total =
            o[CYCLE_CAPTURE_DL_GRE_DECAP].total_cycles;
        p->dl_gre_decap_calls_total =
            o[CYCLE_CAPTURE_DL_GRE_DECAP].call_count;
    } else {
        p->dl_gre_decap_cycles_total = 0;
        p->dl_gre_decap_calls_total = 0;
    }
    if (p->dl_gre_decap_calls_total) {
        p->dl_gre_decap_cycles_per_call =
            p->dl_gre_decap_cycles_total /
            p->dl_gre_decap_calls_total;
        p->dl_gre_decap_cycles_per_mbuf =
            p->dl_gre_decap_cycles_total /
            p->dl_gre_decap_calls_total;
    }

    /* DL_STA_LOOKUP */
    if (o[CYCLE_CAPTURE_DL_STA_LOOKUP].reset == FALSE) {
        p->dl_sta_lookup_cycles_total =
            o[CYCLE_CAPTURE_DL_STA_LOOKUP].total_cycles;
        p->dl_sta_lookup_calls_total =
            o[CYCLE_CAPTURE_DL_STA_LOOKUP].call_count;
    } else {
        p->dl_sta_lookup_cycles_total = 0;
        p->dl_sta_lookup_calls_total = 0;
    }
    if (p->dl_sta_lookup_calls_total) {
        p->dl_sta_lookup_cycles_per_call =
            p->dl_sta_lookup_cycles_total /
            p->dl_sta_lookup_calls_total;
    }
    if (parsed_sts_sta_lookup[STATS_STA_LOOKUP_TYPE_DL].num_pkts) {
        p->dl_sta_lookup_cycles_per_mbuf =
            p->dl_sta_lookup_cycles_total /
            parsed_sts_sta_lookup[STATS_STA_LOOKUP_TYPE_DL].num_pkts;
    }

    /* DL_STA_LOCK */
    if (o[CYCLE_CAPTURE_DL_STA_LOCK].reset == FALSE) {
        p->dl_sta_lock_cycles_total =
            o[CYCLE_CAPTURE_DL_STA_LOCK].total_cycles;
        p->dl_sta_lock_calls_total =
            o[CYCLE_CAPTURE_DL_STA_LOCK].call_count;
    } else {
        p->dl_sta_lock_cycles_total = 0;
        p->dl_sta_lock_calls_total = 0;
    }
    if (p->dl_sta_lock_calls_total) {
        p->dl_sta_lock_cycles_per_call =
            p->dl_sta_lock_cycles_total /
            p->dl_sta_lock_calls_total;
        p->dl_sta_lock_cycles_per_mbuf =
            p->dl_sta_lock_cycles_total /
            p->dl_sta_lock_calls_total;
    }

    /* DL_STA_ENCRYPT_DATA_GET */
    if (o[CYCLE_CAPTURE_DL_STA_ENCRYPT_DATA_GET].reset == FALSE) {
        p->dl_sta_encrypt_data_get_cycles_total =
            o[CYCLE_CAPTURE_DL_STA_ENCRYPT_DATA_GET].total_cycles;
        p->dl_sta_encrypt_data_get_calls_total =
            o[CYCLE_CAPTURE_DL_STA_ENCRYPT_DATA_GET].call_count;
    } else {
        p->dl_sta_encrypt_data_get_cycles_total = 0;
        p->dl_sta_encrypt_data_get_calls_total = 0;
    }
    if (p->dl_sta_encrypt_data_get_calls_total) {
        p->dl_sta_encrypt_data_get_cycles_per_call =
            p->dl_sta_encrypt_data_get_cycles_total /
            p->dl_sta_encrypt_data_get_calls_total;
        p->dl_sta_encrypt_data_get_cycles_per_mbuf =
            p->dl_sta_encrypt_data_get_cycles_total /
            p->dl_sta_encrypt_data_get_calls_total;
    }

    /* DL_ETHER_TO_IEEE80211_CONV */
    if (o[CYCLE_CAPTURE_DL_ETHER_TO_IEEE80211_CONV].reset == FALSE) {
        p->dl_ether_to_ieee80211_conv_cycles_total =
            o[CYCLE_CAPTURE_DL_ETHER_TO_IEEE80211_CONV].total_cycles;
        p->dl_ether_to_ieee80211_conv_calls_total =
            o[CYCLE_CAPTURE_DL_ETHER_TO_IEEE80211_CONV].call_count;
    } else {
        p->dl_ether_to_ieee80211_conv_cycles_total = 0;
        p->dl_ether_to_ieee80211_conv_calls_total = 0;
    }
    if (p->dl_ether_to_ieee80211_conv_calls_total) {
        p->dl_ether_to_ieee80211_conv_cycles_per_call =
            p->dl_ether_to_ieee80211_conv_cycles_total /
            p->dl_ether_to_ieee80211_conv_calls_total;
        p->dl_ether_to_ieee80211_conv_cycles_per_mbuf =
            p->dl_ether_to_ieee80211_conv_cycles_total /
            p->dl_ether_to_ieee80211_conv_calls_total;
    }

    /* DL_CCMP_HDR_GENERATE */
    if (o[CYCLE_CAPTURE_DL_CCMP_HDR_GENERATE].reset == FALSE) {
        p->dl_ccmp_hdr_generate_cycles_total =
            o[CYCLE_CAPTURE_DL_CCMP_HDR_GENERATE].total_cycles;
        p->dl_ccmp_hdr_generate_calls_total =
            o[CYCLE_CAPTURE_DL_CCMP_HDR_GENERATE].call_count;
    } else {
        p->dl_ccmp_hdr_generate_cycles_total = 0;
        p->dl_ccmp_hdr_generate_calls_total = 0;
    }
    if (p->dl_ccmp_hdr_generate_calls_total) {
        p->dl_ccmp_hdr_generate_cycles_per_call =
            p->dl_ccmp_hdr_generate_cycles_total /
            p->dl_ccmp_hdr_generate_calls_total;
        p->dl_ccmp_hdr_generate_cycles_per_mbuf =
            p->dl_ccmp_hdr_generate_cycles_total /
            p->dl_ccmp_hdr_generate_calls_total;
    }

    /* DL_CRYPTO_ENQUEUE */
    if (o[CYCLE_CAPTURE_DL_CRYPTO_ENQUEUE].reset == FALSE) {
        p->dl_crypto_enq_cycles_total =
            o[CYCLE_CAPTURE_DL_CRYPTO_ENQUEUE].total_cycles;
        p->dl_crypto_enq_calls_total =
            o[CYCLE_CAPTURE_DL_CRYPTO_ENQUEUE].call_count;
    } else {
        p->dl_crypto_enq_cycles_total = 0;
        p->dl_crypto_enq_calls_total = 0;
    }
    if (p->dl_crypto_enq_calls_total) {
        p->dl_crypto_enq_cycles_per_call =
            p->dl_crypto_enq_cycles_total /
            p->dl_crypto_enq_calls_total;
    }
    p->dl_crypto_enq_cycles_per_mbuf =
        parsed_sts_crypto[STATS_CRYPTO_TYPE_DL].avg_cycles_per_enqueued_packet;

    /* DL_CRYPTO_DEQUEUE */
    if (o[CYCLE_CAPTURE_DL_CRYPTO_DEQUEUE].reset == FALSE) {
        p->dl_crypto_deq_cycles_total =
            o[CYCLE_CAPTURE_DL_CRYPTO_DEQUEUE].total_cycles;
        p->dl_crypto_deq_calls_total =
            o[CYCLE_CAPTURE_DL_CRYPTO_DEQUEUE].call_count;
    } else {
        p->dl_crypto_deq_cycles_total = 0;
        p->dl_crypto_deq_calls_total = 0;
    }
    if (p->dl_crypto_deq_calls_total) {
        p->dl_crypto_deq_cycles_per_call =
            p->dl_crypto_deq_cycles_total /
            p->dl_crypto_deq_calls_total;
    }
    p->dl_crypto_deq_cycles_per_mbuf =
        parsed_sts_crypto[STATS_CRYPTO_TYPE_DL].avg_cycles_per_dequeued_packet;

    /* DL_STA_UNLOCK */
    if (o[CYCLE_CAPTURE_DL_STA_UNLOCK].reset == FALSE) {
        p->dl_sta_unlock_cycles_total =
            o[CYCLE_CAPTURE_DL_STA_UNLOCK].total_cycles;
        p->dl_sta_unlock_calls_total =
            o[CYCLE_CAPTURE_DL_STA_UNLOCK].call_count;
    } else {
        p->dl_sta_unlock_cycles_total = 0;
        p->dl_sta_unlock_calls_total = 0;
    }
    if (p->dl_sta_unlock_calls_total) {
        p->dl_sta_unlock_cycles_per_call =
            p->dl_sta_unlock_cycles_total /
            p->dl_sta_unlock_calls_total;
        p->dl_sta_unlock_cycles_per_mbuf =
            p->dl_sta_unlock_cycles_total /
            p->dl_sta_unlock_calls_total;
    }

    /* DL_VAP_TLV_ENCAP */
    if (o[CYCLE_CAPTURE_DL_VAP_TLV_ENCAP].reset == FALSE) {
        p->dl_vap_tlv_encap_cycles_total =
            o[CYCLE_CAPTURE_DL_VAP_TLV_ENCAP].total_cycles;
        p->dl_vap_tlv_encap_calls_total =
            o[CYCLE_CAPTURE_DL_VAP_TLV_ENCAP].call_count;
    } else {
        p->dl_vap_tlv_encap_cycles_total = 0;
        p->dl_vap_tlv_encap_calls_total = 0;
    }
    if (p->dl_vap_tlv_encap_calls_total) {
        p->dl_vap_tlv_encap_cycles_per_call =
            p->dl_vap_tlv_encap_cycles_total /
            p->dl_vap_tlv_encap_calls_total;
        p->dl_vap_tlv_encap_cycles_per_mbuf =
            p->dl_vap_tlv_encap_cycles_total /
            p->dl_vap_tlv_encap_calls_total;
    }

    /* DL_VAP_PAYLOAD_FRAGMENT */
    if (o[CYCLE_CAPTURE_DL_VAP_PAYLOAD_FRAGMENT].reset == FALSE) {
        p->dl_vap_payload_fragment_cycles_total =
            o[CYCLE_CAPTURE_DL_VAP_PAYLOAD_FRAGMENT].total_cycles;
        p->dl_vap_payload_fragment_calls_total =
            o[CYCLE_CAPTURE_DL_VAP_PAYLOAD_FRAGMENT].call_count;
    } else {
        p->dl_vap_payload_fragment_cycles_total = 0;
        p->dl_vap_payload_fragment_calls_total = 0;
    }
    if (p->dl_vap_payload_fragment_calls_total) {
        p->dl_vap_payload_fragment_cycles_per_call =
            p->dl_vap_payload_fragment_cycles_total /
            p->dl_vap_payload_fragment_calls_total;
        p->dl_vap_payload_fragment_cycles_per_mbuf =
            p->dl_vap_payload_fragment_cycles_total /
            p->dl_vap_payload_fragment_calls_total;
    }

    /* DL_VAP_HDR_ENCAP */
    if (o[CYCLE_CAPTURE_DL_VAP_HDR_ENCAP].reset == FALSE) {
        p->dl_vap_hdr_encap_cycles_total =
            o[CYCLE_CAPTURE_DL_VAP_HDR_ENCAP].total_cycles;
        p->dl_vap_hdr_encap_calls_total =
            o[CYCLE_CAPTURE_DL_VAP_HDR_ENCAP].call_count;
    } else {
        p->dl_vap_hdr_encap_cycles_total = 0;
        p->dl_vap_hdr_encap_calls_total = 0;
    }
    if (p->dl_vap_hdr_encap_calls_total) {
        p->dl_vap_hdr_encap_cycles_per_call =
            p->dl_vap_hdr_encap_cycles_total /
            p->dl_vap_hdr_encap_calls_total;
        p->dl_vap_hdr_encap_cycles_per_mbuf =
            p->dl_vap_hdr_encap_cycles_total /
            p->dl_vap_hdr_encap_calls_total;
    }

    /* DL_AP_TUNNEL_ENCAP */
    if (o[CYCLE_CAPTURE_DL_AP_TUNNEL_ENCAP].reset == FALSE) {
        p->dl_ap_tunnel_encap_cycles_total =
            o[CYCLE_CAPTURE_DL_AP_TUNNEL_ENCAP].total_cycles;
        p->dl_ap_tunnel_encap_calls_total =
            o[CYCLE_CAPTURE_DL_AP_TUNNEL_ENCAP].call_count;
    } else {
        p->dl_ap_tunnel_encap_cycles_total = 0;
        p->dl_ap_tunnel_encap_calls_total = 0;
    }
    if (p->dl_ap_tunnel_encap_calls_total) {
        p->dl_ap_tunnel_encap_cycles_per_call =
            p->dl_ap_tunnel_encap_cycles_total /
            p->dl_ap_tunnel_encap_calls_total;
        p->dl_ap_tunnel_encap_cycles_per_mbuf =
            p->dl_ap_tunnel_encap_cycles_total /
            p->dl_ap_tunnel_encap_calls_total;
    }

    /* DL_PMD_TX */
    if (o[CYCLE_CAPTURE_DL_PMD_TX].reset == FALSE) {
        p->dl_pmd_tx_cycles_total =
            o[CYCLE_CAPTURE_DL_PMD_TX].total_cycles;
        p->dl_pmd_tx_calls_total =
            o[CYCLE_CAPTURE_DL_PMD_TX].call_count;
    } else {
        p->dl_pmd_tx_cycles_total = 0;
        p->dl_pmd_tx_calls_total = 0;
    }
    if (p->dl_pmd_tx_calls_total) {
        p->dl_pmd_tx_cycles_per_call =
            p->dl_pmd_tx_cycles_total / p->dl_pmd_tx_calls_total;
        p->dl_pmd_tx_cycles_per_mbuf =
            p->dl_pmd_tx_cycles_total / p->dl_pmd_tx_calls_total;
    }

    /* AGGREGATES */

    /* UL_CRYPTO */
    p->ul_crypto_cycles_total =
        p->ul_crypto_enq_cycles_total +
        p->ul_crypto_deq_cycles_total;

    p->ul_crypto_calls_total =
        p->ul_crypto_enq_calls_total +
        p->ul_crypto_deq_calls_total;

    p->ul_crypto_cycles_per_call =
        p->ul_crypto_enq_cycles_per_call +
        p->ul_crypto_deq_cycles_per_call;

    p->ul_crypto_cycles_per_mbuf =
        p->ul_crypto_enq_cycles_per_mbuf +
        p->ul_crypto_deq_cycles_per_mbuf;

    /* UL_IEEE80211_DATA_PKTS_PROCESS */
    p->ul_ieee80211_data_pkts_process_cycles_total =
        p->ul_ieee80211_to_ether_conv_cycles_total +
        p->ul_gre_encap_cycles_total +
        p->ul_pmd_tx_cycles_total;

    p->ul_ieee80211_data_pkts_process_calls_total =
        p->ul_ieee80211_to_ether_conv_calls_total +
        p->ul_gre_encap_calls_total +
        p->ul_pmd_tx_calls_total;

    p->ul_ieee80211_data_pkts_process_cycles_per_call =
        p->ul_ieee80211_to_ether_conv_cycles_per_call +
        p->ul_gre_encap_cycles_per_call +
        p->ul_pmd_tx_cycles_per_call;

    p->ul_ieee80211_data_pkts_process_cycles_per_mbuf =
        p->ul_ieee80211_to_ether_conv_cycles_per_mbuf +
        p->ul_gre_encap_cycles_per_mbuf +
        p->ul_pmd_tx_cycles_per_mbuf;

    /* UL_IEEE80211_EAPOL_PKTS_PROCESS */
    p->ul_ieee80211_eapol_pkts_process_cycles_total =
        p->ul_ccmp_decap_cycles_total +
        p->ul_wpapt_cdi_frame_encap_cycles_total +
        p->ul_wpapt_cdi_hdr_encap_cycles_total +
        p->ul_tls_tx_cycles_total;

    p->ul_ieee80211_eapol_pkts_process_calls_total =
        p->ul_ccmp_decap_calls_total +
        p->ul_wpapt_cdi_frame_encap_calls_total +
        p->ul_wpapt_cdi_hdr_encap_calls_total +
        p->ul_tls_tx_calls_total;

    p->ul_ieee80211_eapol_pkts_process_cycles_per_call =
        p->ul_ccmp_decap_cycles_per_call +
        p->ul_wpapt_cdi_frame_encap_cycles_per_call +
        p->ul_wpapt_cdi_hdr_encap_cycles_per_call +
        p->ul_tls_tx_cycles_per_call;

    p->ul_ieee80211_eapol_pkts_process_cycles_per_mbuf =
        p->ul_ccmp_decap_cycles_per_mbuf +
        p->ul_wpapt_cdi_frame_encap_cycles_per_mbuf +
        p->ul_wpapt_cdi_hdr_encap_cycles_per_mbuf +
        p->ul_tls_tx_cycles_per_mbuf;

    /* UL_POST_IEEE80211_PKT_CLASSIFY */
    p->ul_post_ieee80211_pkt_classify_cycles_total =
        p->ul_ieee80211_data_pkts_process_cycles_total +
        p->ul_ieee80211_eapol_pkts_process_cycles_total;

    p->ul_post_ieee80211_pkt_classify_calls_total =
        p->ul_ieee80211_data_pkts_process_calls_total +
        p->ul_ieee80211_eapol_pkts_process_calls_total;

    p->ul_post_ieee80211_pkt_classify_cycles_per_call =
        p->ul_ieee80211_data_pkts_process_cycles_per_call +
        p->ul_ieee80211_eapol_pkts_process_cycles_per_call;

    p->ul_post_ieee80211_pkt_classify_cycles_per_mbuf =
        p->ul_ieee80211_data_pkts_process_cycles_per_mbuf +
        p->ul_ieee80211_eapol_pkts_process_cycles_per_mbuf;

    /* UL_TOTALS */
#if RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH
    p->ul_cycles_total =
        p->ul_pmd_rx_excl_empties_cycles_total +
        p->ul_initial_pkt_classify_cycles_total +
        p->ul_ap_tunnel_decap_cycles_total +
        p->ul_vap_hdr_parse_cycles_total +
        p->ul_vap_payload_reassemble_cycles_total  +
        p->ul_vap_hdr_decap_cycles_total +
        p->ul_vap_tlv_decap_cycles_total +
        p->ul_ieee80211_pkt_parse_cycles_total +
        p->ul_sta_lookup_cycles_total +
        p->ul_sta_lock_cycles_total +
        p->ul_sta_decrypt_data_get_cycles_total +
        p->ul_ccmp_replay_detect_cycles_total +
        p->ul_sta_decrypt_data_update_cycles_total +
        p->ul_crypto_cycles_total +
        p->ul_sta_unlock_cycles_total +
        p->ul_ieee80211_pkt_classify_cycles_total  +
        p->ul_post_ieee80211_pkt_classify_cycles_total;

    p->ul_cycles_per_call =
        p->ul_pmd_rx_excl_empties_cycles_per_call +
        p->ul_initial_pkt_classify_cycles_per_call +
        p->ul_ap_tunnel_decap_cycles_per_call +
        p->ul_vap_hdr_parse_cycles_per_call +
        p->ul_vap_payload_reassemble_cycles_per_call +
        p->ul_vap_hdr_decap_cycles_per_call +
        p->ul_vap_tlv_decap_cycles_per_call +
        p->ul_ieee80211_pkt_parse_cycles_per_call +
        p->ul_sta_lookup_cycles_per_call +
        p->ul_sta_lock_cycles_per_call +
        p->ul_sta_decrypt_data_get_cycles_per_call +
        p->ul_ccmp_replay_detect_cycles_per_call +
        p->ul_sta_decrypt_data_update_cycles_per_call +
        p->ul_crypto_cycles_per_call +
        p->ul_sta_unlock_cycles_per_call +
        p->ul_ieee80211_pkt_classify_cycles_per_call +
        p->ul_post_ieee80211_pkt_classify_cycles_per_call;

    p->ul_cycles_per_mbuf =
        p->ul_pmd_rx_excl_empties_cycles_per_mbuf +
        p->ul_initial_pkt_classify_cycles_per_mbuf +
        p->ul_ap_tunnel_decap_cycles_per_mbuf +
        p->ul_vap_hdr_parse_cycles_per_mbuf +
        p->ul_vap_payload_reassemble_cycles_per_mbuf  +
        p->ul_vap_hdr_decap_cycles_per_mbuf +
        p->ul_vap_tlv_decap_cycles_per_mbuf +
        p->ul_ieee80211_pkt_parse_cycles_per_mbuf +
        p->ul_sta_lookup_cycles_per_mbuf +
        p->ul_sta_lock_cycles_per_mbuf +
        p->ul_sta_decrypt_data_get_cycles_per_mbuf +
        p->ul_ccmp_replay_detect_cycles_per_mbuf +
        p->ul_sta_decrypt_data_update_cycles_per_mbuf +
        p->ul_crypto_cycles_per_mbuf +
        p->ul_sta_unlock_cycles_per_mbuf +
        p->ul_ieee80211_pkt_classify_cycles_per_mbuf +
        p->ul_post_ieee80211_pkt_classify_cycles_per_mbuf;
#elif RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_LOW
    p->ul_cycles_total =
        p->ul_pmd_rx_excl_empties_cycles_total +
        p->ul_process_full_cycles_total;

    p->ul_cycles_per_call =
        p->ul_pmd_rx_excl_empties_cycles_per_call +
        p->ul_process_full_cycles_per_call;

    p->ul_cycles_per_mbuf =
        p->ul_pmd_rx_excl_empties_cycles_per_mbuf +
        p->ul_process_full_cycles_per_mbuf;
#else
    p->ul_cycles_total =
        p->ul_pmd_rx_excl_empties_cycles_total;
    p->ul_cycles_per_call =
        p->ul_pmd_rx_excl_empties_cycles_per_call;
    p->ul_cycles_per_mbuf =
        p->ul_pmd_rx_excl_empties_cycles_per_mbuf;
#endif

    /* DL_CRYPTO */
    p->dl_crypto_cycles_total =
        p->dl_crypto_enq_cycles_total +
        p->dl_crypto_deq_cycles_total;

    p->dl_crypto_calls_total =
        p->dl_crypto_enq_calls_total +
        p->dl_crypto_deq_calls_total;

    p->dl_crypto_cycles_per_call =
        p->dl_crypto_enq_cycles_per_call +
        p->dl_crypto_deq_cycles_per_call;

    p->dl_crypto_cycles_per_mbuf =
        p->dl_crypto_enq_cycles_per_mbuf +
        p->dl_crypto_deq_cycles_per_mbuf;

    /* DL_TOTALS */
#if RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH
    p->dl_cycles_total =
        p->dl_pmd_rx_excl_empties_cycles_total +
        p->dl_initial_pkt_classify_cycles_total +
        p->dl_gre_decap_cycles_total +
        p->dl_sta_lookup_cycles_total +
        p->dl_sta_lock_cycles_total +
        p->dl_sta_encrypt_data_get_cycles_total +
        p->dl_ether_to_ieee80211_conv_cycles_total +
        p->dl_ccmp_hdr_generate_cycles_total +
        p->dl_crypto_cycles_total +
        p->dl_sta_unlock_cycles_total +
        p->dl_vap_tlv_encap_cycles_total +
        p->dl_vap_payload_fragment_cycles_total +
        p->dl_vap_hdr_encap_cycles_total +
        p->dl_ap_tunnel_encap_cycles_total +
        p->dl_pmd_tx_cycles_total;

    p->dl_cycles_per_call =
        p->dl_pmd_rx_excl_empties_cycles_per_call +
        p->dl_initial_pkt_classify_cycles_per_call +
        p->dl_gre_decap_cycles_per_call +
        p->dl_sta_lookup_cycles_per_call +
        p->dl_sta_lock_cycles_per_call +
        p->dl_sta_encrypt_data_get_cycles_per_call +
        p->dl_ether_to_ieee80211_conv_cycles_per_call +
        p->dl_ccmp_hdr_generate_cycles_per_call +
        p->dl_crypto_cycles_per_call +
        p->dl_sta_unlock_cycles_per_call +
        p->dl_vap_tlv_encap_cycles_per_call +
        p->dl_vap_payload_fragment_cycles_per_call +
        p->dl_vap_hdr_encap_cycles_per_call +
        p->dl_ap_tunnel_encap_cycles_per_call +
        p->dl_pmd_tx_cycles_per_call;

    p->dl_cycles_per_mbuf =
        p->dl_pmd_rx_excl_empties_cycles_per_mbuf +
        p->dl_initial_pkt_classify_cycles_per_mbuf +
        p->dl_gre_decap_cycles_per_mbuf +
        p->dl_sta_lookup_cycles_per_mbuf +
        p->dl_sta_lock_cycles_per_mbuf +
        p->dl_sta_encrypt_data_get_cycles_per_mbuf +
        p->dl_ether_to_ieee80211_conv_cycles_per_mbuf +
        p->dl_ccmp_hdr_generate_cycles_per_mbuf +
        p->dl_crypto_cycles_per_mbuf +
        p->dl_sta_unlock_cycles_per_mbuf +
        p->dl_vap_tlv_encap_cycles_per_mbuf +
        p->dl_vap_payload_fragment_cycles_per_mbuf +
        p->dl_vap_hdr_encap_cycles_per_mbuf +
        p->dl_ap_tunnel_encap_cycles_per_mbuf +
        p->dl_pmd_tx_cycles_per_mbuf;
#elif RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_LOW
    p->dl_cycles_total =
        p->dl_pmd_rx_excl_empties_cycles_total +
        p->dl_process_full_cycles_total;

    p->dl_cycles_per_call =
        p->dl_pmd_rx_excl_empties_cycles_per_call +
        p->dl_process_full_cycles_per_call;

    p->dl_cycles_per_mbuf =
        p->dl_pmd_rx_excl_empties_cycles_per_mbuf +
        p->dl_process_full_cycles_per_mbuf;
#else
    p->dl_cycles_total =
        p->dl_pmd_rx_excl_empties_cycles_total;
    p->dl_cycles_per_call =
        p->dl_pmd_rx_excl_empties_cycles_per_call;
    p->dl_cycles_per_mbuf =
        p->dl_pmd_rx_excl_empties_cycles_per_mbuf;
#endif
}

static void
init_shadow_mem_cycle(void)
{
    /* grab pointers to mem locations of original stats */
    original_cycle_sts =
        cycle_capture_get_mem_info((uint32_t *)(&shadow_cycle_sts_sz));
    shadow_cycle_sts_num = shadow_cycle_sts_sz / sizeof(original_cycle_sts[0]);

    /*
     * allocate memory for shadow stats, during the runtime original stats
     * will be 'memcpy' to this memory in order to process the most current
     * snapshot of stats.
     */
    shadow_cycle_sts = rte_zmalloc("cycle_shadow_stats_capture",
                                   shadow_cycle_sts_sz,
                                   RTE_CACHE_LINE_SIZE);

    if (NULL == shadow_cycle_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate shadow mem for cycle Stats\n");
}

static void
init_parsed_stats_mem(void)
{
    parsed_cycle_sts = rte_zmalloc("cycle_parsed_stats",
                                   sizeof(struct parsed_statistics_cycle),
                                   RTE_CACHE_LINE_SIZE);

    if (NULL == parsed_cycle_sts)
        rte_exit(EXIT_FAILURE,
                 "Failed to allocate parsed mem for cycle Stats\n");

#if !defined(RWPA_STATS_CAPTURE_PORTS_OFF) && defined(RWPA_STATS_CAPTURE)
    parsed_sts_ports = sts_hdlr_ports_get_mem_info_parsed();
#else
    parsed_sts_ports = rte_zmalloc(NULL,
                                   sizeof(parsed_sts_ports[0]),
                                   RTE_CACHE_LINE_SIZE);
#endif

#if !defined(RWPA_STATS_CAPTURE_STA_LOOKUP_OFF) && defined(RWPA_STATS_CAPTURE)
    parsed_sts_sta_lookup = sts_hdlr_sta_lookup_get_mem_info_parsed();
#else
    parsed_sts_sta_lookup = rte_zmalloc(NULL,
                                        STATS_STA_LOOKUP_TYPE_U_DELIM *
                                        sizeof(parsed_sts_sta_lookup[0]),
                                        RTE_CACHE_LINE_SIZE);
#endif

#if !defined(RWPA_STATS_CAPTURE_CRYPTO_OFF) && defined(RWPA_STATS_CAPTURE)
    parsed_sts_crypto = sts_hdlr_crypto_get_mem_info_parsed();
#else
    parsed_sts_crypto = rte_zmalloc(NULL,
                                    STATS_CRYPTO_TYPE_U_DELIM *
                                    sizeof(parsed_sts_crypto[0]),
                                    RTE_CACHE_LINE_SIZE);
#endif
}

static void
print_warining_if_any_stat_is_disabled(void)
{
#if defined(RWPA_STATS_CAPTURE_PORTS_OFF)      || \
    defined(RWPA_STATS_CAPTURE_STA_LOOKUP_OFF) || \
    defined(RWPA_STATS_CAPTURE_CRYPTO_OFF)     || \
    defined(RWPA_STATS_CAPTURE_UPLINK_OFF)     || \
    defined(RWPA_STATS_CAPTURE_DOWNLINK_OFF)
    printf("************************************************************************************************************************************************\n"
           "* WARNING: Not all stats were enabled for capture in this run!                                                                                 *\n"
           "*          Aggregate Cycle Stats will be calculated only on enabled stats!                                                                     *\n");
#endif
}


void
sts_hdlr_cycle_init(__attribute__((unused)) struct app_params *app)
{
    init_shadow_mem_cycle();
    init_parsed_stats_mem();
}

void
sts_hdlr_cycle_free(void)
{
    if (NULL != shadow_cycle_sts) {
        rte_free(shadow_cycle_sts);
    }

    if (NULL != parsed_cycle_sts) {
        rte_free(parsed_cycle_sts);
    }
}

void
sts_hdlr_cycle_update_shadow_stats(void)
{
    /* simple struct copy - no underlying pointers, just plain data */
    rte_memcpy(shadow_cycle_sts, original_cycle_sts, shadow_cycle_sts_sz);
}

void
sts_hdlr_cycle_update_parsed_stats(void)
{
    calculate_parsed_stats_cycle();
}

void
sts_hdlr_cycle_clear_stats(void)
{
    uint32_t i;

    for (i = 0; i < shadow_cycle_sts_num; i++) {
          original_cycle_sts[i].reset = TRUE;
    }

    memset(parsed_cycle_sts, 0, sizeof(parsed_cycle_sts[0]));
}

void
sts_hdlr_cycle_print(__attribute__((unused)) enum rwpa_stats_lvl sts_lvl)
{
    struct parsed_statistics_cycle *p = parsed_cycle_sts;

    char hdr[] =      "+----------------------------------------+----------------------------+----------------------------+---------------------+---------------------+\n"
                      "| Cycle States                           | Total Calls                | Total Cycles               |   Cycles per Call   |   Cycles per Mbuf   |\n";
    char soft_spc[] = "+----------------------------------------+----------------------------+----------------------------+---------------------+---------------------+\n";
    char hard_spc[] = "| |                                      |============================+============================+=====================+=====================+\n";

    UNUSED(p);
    UNUSED(hard_spc);

    print_warining_if_any_stat_is_disabled();

    printf("%s", hdr);
    printf("%s", soft_spc);

#ifndef RWPA_STATS_CAPTURE_UPLINK_OFF
    printf("|%-40s| %26s | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " UPLINK",
           "",
           p->ul_cycles_total,
           p->ul_cycles_per_call,
           p->ul_cycles_per_mbuf);

    printf("%s", hard_spc);

#if !defined RWPA_STATS_CAPTURE_PORTS_OFF
    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_PMD_RX (excl empty reads)",
           p->ul_pmd_rx_excl_empties_calls_total,
           p->ul_pmd_rx_excl_empties_cycles_total,
           p->ul_pmd_rx_excl_empties_cycles_per_call,
           p->ul_pmd_rx_excl_empties_cycles_per_mbuf);

    printf("|%-40s| `--%-23"PRIu64" | `--%-23"PRIu64" | `--%-16"PRIu64" | `--%-16"PRIu64" |\n",
           " |  `--incl empty reads",
           p->ul_pmd_rx_calls_total,
           p->ul_pmd_rx_cycles_total,
           p->ul_pmd_rx_cycles_per_call,
           p->ul_pmd_rx_cycles_per_mbuf);
#endif

#if RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_LOW
    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " `--UL_PROCESS_FULL",
           p->ul_process_full_calls_total,
           p->ul_process_full_cycles_total,
           p->ul_process_full_cycles_per_call,
           p->ul_process_full_cycles_per_mbuf);
#elif RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH
    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_INITIAL_PKT_CLASSIFY",
           p->ul_initial_pkt_classify_calls_total,
           p->ul_initial_pkt_classify_cycles_total,
           p->ul_initial_pkt_classify_cycles_per_call,
           p->ul_initial_pkt_classify_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_AP_TUNNEL_DECAP",
           p->ul_ap_tunnel_decap_calls_total,
           p->ul_ap_tunnel_decap_cycles_total,
           p->ul_ap_tunnel_decap_cycles_per_call,
           p->ul_ap_tunnel_decap_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_VAP_HDR_PARSE",
           p->ul_vap_hdr_parse_calls_total,
           p->ul_vap_hdr_parse_cycles_total,
           p->ul_vap_hdr_parse_cycles_per_call,
           p->ul_vap_hdr_parse_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_VAP_PAYLOAD_REASSEMBLE",
           p->ul_vap_payload_reassemble_calls_total,
           p->ul_vap_payload_reassemble_cycles_total,
           p->ul_vap_payload_reassemble_cycles_per_call,
           p->ul_vap_payload_reassemble_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_VAP_HDR_DECAP",
           p->ul_vap_hdr_decap_calls_total,
           p->ul_vap_hdr_decap_cycles_total,
           p->ul_vap_hdr_decap_cycles_per_call,
           p->ul_vap_hdr_decap_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_VAP_TLV_DECAP",
           p->ul_vap_tlv_decap_calls_total,
           p->ul_vap_tlv_decap_cycles_total,
           p->ul_vap_tlv_decap_cycles_per_call,
           p->ul_vap_tlv_decap_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_IEEE80211_PKT_PARSE",
           p->ul_ieee80211_pkt_parse_calls_total,
           p->ul_ieee80211_pkt_parse_cycles_total,
           p->ul_ieee80211_pkt_parse_cycles_per_call,
           p->ul_ieee80211_pkt_parse_cycles_per_mbuf);

#if !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF
    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_STA_LOOKUP",
           p->ul_sta_lookup_calls_total,
           p->ul_sta_lookup_cycles_total,
           p->ul_sta_lookup_cycles_per_call,
           p->ul_sta_lookup_cycles_per_mbuf);
#endif

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_STA_LOCK",
           p->ul_sta_lock_calls_total,
           p->ul_sta_lock_cycles_total,
           p->ul_sta_lock_cycles_per_call,
           p->ul_sta_lock_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_STA_DECRYPT_DATA_GET",
           p->ul_sta_decrypt_data_get_calls_total,
           p->ul_sta_decrypt_data_get_cycles_total,
           p->ul_sta_decrypt_data_get_cycles_per_call,
           p->ul_sta_decrypt_data_get_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_CCMP_REPLAY_DETECT",
           p->ul_ccmp_replay_detect_calls_total,
           p->ul_ccmp_replay_detect_cycles_total,
           p->ul_ccmp_replay_detect_cycles_per_call,
           p->ul_ccmp_replay_detect_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_STA_DECRYPT_DATA_UPDATE",
           p->ul_sta_decrypt_data_update_calls_total,
           p->ul_sta_decrypt_data_update_cycles_total,
           p->ul_sta_decrypt_data_update_cycles_per_call,
           p->ul_sta_decrypt_data_update_cycles_per_mbuf);

#if !defined RWPA_STATS_CAPTURE_CRYPTO_OFF
    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_CRYPTO",
           p->ul_crypto_calls_total,
           p->ul_crypto_cycles_total,
           p->ul_crypto_cycles_per_call,
           p->ul_crypto_cycles_per_mbuf);

    printf("|%-40s| |--%-23"PRIu64" | |--%-23"PRIu64" | |--%-16"PRIu64" | |--%-16"PRIu64" |\n",
           " |  |--UL_CRYPTO_ENQUEUE",
           p->ul_crypto_enq_calls_total,
           p->ul_crypto_enq_cycles_total,
           p->ul_crypto_enq_cycles_per_call,
           p->ul_crypto_enq_cycles_per_mbuf);

    printf("|%-40s| `--%-23"PRIu64" | `--%-23"PRIu64" | `--%-16"PRIu64" | `--%-16"PRIu64" |\n",
           " |  `--UL_CRYPTO_DEQUEUE",
           p->ul_crypto_deq_calls_total,
           p->ul_crypto_deq_cycles_total,
           p->ul_crypto_deq_cycles_per_call,
           p->ul_crypto_deq_cycles_per_mbuf);
#endif

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_STA_UNLOCK",
           p->ul_sta_unlock_calls_total,
           p->ul_sta_unlock_cycles_total,
           p->ul_sta_unlock_cycles_per_call,
           p->ul_sta_unlock_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--UL_IEEE80211_PKT_CLASSIFY",
           p->ul_ieee80211_pkt_classify_calls_total,
           p->ul_ieee80211_pkt_classify_cycles_total,
           p->ul_ieee80211_pkt_classify_cycles_per_call,
           p->ul_ieee80211_pkt_classify_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " `--UL_POST_IEEE80211_PKT_CLASSIFY",
           p->ul_post_ieee80211_pkt_classify_calls_total,
           p->ul_post_ieee80211_pkt_classify_cycles_total,
           p->ul_post_ieee80211_pkt_classify_cycles_per_call,
           p->ul_post_ieee80211_pkt_classify_cycles_per_mbuf);

    printf("|%-40s| |--%-23"PRIu64" | |--%-23"PRIu64" | |--%-16"PRIu64" | |--%-16"PRIu64" |\n",
           "    |--UL_IEEE80211_DATA_PKTS_PROCESS",
           p->ul_ieee80211_data_pkts_process_calls_total,
           p->ul_ieee80211_data_pkts_process_cycles_total,
           p->ul_ieee80211_data_pkts_process_cycles_per_call,
           p->ul_ieee80211_data_pkts_process_cycles_per_mbuf);

    printf("|%-40s| |  |--%-20"PRIu64" | |  |--%-20"PRIu64" | |  |--%-13"PRIu64" | |  |--%-13"PRIu64" |\n",
           "    |  |--UL_IEEE80211_TO_ETHER_CONV",
           p->ul_ieee80211_to_ether_conv_calls_total,
           p->ul_ieee80211_to_ether_conv_cycles_total,
           p->ul_ieee80211_to_ether_conv_cycles_per_call,
           p->ul_ieee80211_to_ether_conv_cycles_per_mbuf);

#if !defined RWPA_STATS_CAPTURE_PORTS_OFF
    printf("|%-40s| |  |--%-20"PRIu64" | |  |--%-20"PRIu64" | |  |--%-13"PRIu64" | |  |--%-13"PRIu64" |\n",
           "    |  |--UL_GRE_ENCAP",
#else
    printf("|%-40s| |  `--%-20"PRIu64" | |  `--%-20"PRIu64" | |  `--%-13"PRIu64" | |  `--%-13"PRIu64" |\n",
           "    |  `--UL_GRE_ENCAP",
#endif
           p->ul_gre_encap_calls_total,
           p->ul_gre_encap_cycles_total,
           p->ul_gre_encap_cycles_per_call,
           p->ul_gre_encap_cycles_per_mbuf);

#if !defined RWPA_STATS_CAPTURE_PORTS_OFF
    printf("|%-40s| |  `--%-20"PRIu64" | |  `--%-20"PRIu64" | |  `--%-13"PRIu64" | |  `--%-13"PRIu64" |\n",
           "    |  `--UL_PMD_TX",
           p->ul_pmd_tx_calls_total,
           p->ul_pmd_tx_cycles_total,
           p->ul_pmd_tx_cycles_per_call ,
           p->ul_pmd_tx_cycles_per_mbuf);
#endif

    printf("|%-40s| `--%-23"PRIu64" | `--%-23"PRIu64" | `--%-16"PRIu64" | `--%-16"PRIu64" |\n",
           "    `--UL_IEEE80211_EAPOL_PKTS_PROCESS",
           p->ul_ieee80211_eapol_pkts_process_calls_total,
           p->ul_ieee80211_eapol_pkts_process_cycles_total,
           p->ul_ieee80211_eapol_pkts_process_cycles_per_call,
           p->ul_ieee80211_eapol_pkts_process_cycles_per_mbuf);

    printf("|%-40s|    |--%-20"PRIu64" |    |--%-20"PRIu64" |    |--%-13"PRIu64" |    |--%-13"PRIu64" |\n",
           "       |--CCMP_DECAP",
           p->ul_ccmp_decap_calls_total,
           p->ul_ccmp_decap_cycles_total,
           p->ul_ccmp_decap_cycles_per_call,
           p->ul_ccmp_decap_cycles_per_mbuf);

    printf("|%-40s|    |--%-20"PRIu64" |    |--%-20"PRIu64" |    |--%-13"PRIu64" |    |--%-13"PRIu64" |\n",
           "       |--WPAPT_CDI_FRAME_ENCAP",
           p->ul_wpapt_cdi_frame_encap_calls_total,
           p->ul_wpapt_cdi_frame_encap_cycles_total,
           p->ul_wpapt_cdi_frame_encap_cycles_per_call,
           p->ul_wpapt_cdi_frame_encap_cycles_per_mbuf);

    printf("|%-40s|    |--%-20"PRIu64" |    |--%-20"PRIu64" |    |--%-13"PRIu64" |    |--%-13"PRIu64" |\n",
           "       |--WPAPT_CDI_HDR_ENCAP",
           p->ul_wpapt_cdi_hdr_encap_calls_total,
           p->ul_wpapt_cdi_hdr_encap_cycles_total,
           p->ul_wpapt_cdi_hdr_encap_cycles_per_call,
           p->ul_wpapt_cdi_hdr_encap_cycles_per_mbuf);

    printf("|%-40s|    `--%-20"PRIu64" |    `--%-20"PRIu64" |    `--%-13"PRIu64" |    `--%-13"PRIu64" |\n",
           "       `--TLS_TX",
           p->ul_tls_tx_calls_total,
           p->ul_tls_tx_cycles_total,
           p->ul_tls_tx_cycles_per_call,
           p->ul_tls_tx_cycles_per_mbuf);
#endif // RWPA_STATS_CAPTURE == CYCLE_CAPTURE_LEVEL_

    printf("%s", soft_spc);
#endif // ifndef RWPA_STATS_CAPTURE_UPLINK_OFF

#ifndef RWPA_STATS_CAPTURE_DOWNLINK_OFF
    printf("|%-40s| %26s | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " DOWNLINK",
           "",
           p->dl_cycles_total,
           p->dl_cycles_per_call,
           p->dl_cycles_per_mbuf);

    printf("%s", hard_spc);

#if !defined RWPA_STATS_CAPTURE_PORTS_OFF
    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_PMD_RX (excl empty reads)",
           p->dl_pmd_rx_excl_empties_calls_total ,
           p->dl_pmd_rx_excl_empties_cycles_total,
           p->dl_pmd_rx_excl_empties_cycles_per_call,
           p->dl_pmd_rx_excl_empties_cycles_per_mbuf);

    printf("|%-40s| `--%-23"PRIu64" | `--%-23"PRIu64" | `--%-16"PRIu64" | `--%-16"PRIu64" |\n",
           " |  `--incl empty reads",
           p->dl_pmd_rx_calls_total,
           p->dl_pmd_rx_cycles_total,
           p->dl_pmd_rx_cycles_per_call,
           p->dl_pmd_rx_cycles_per_mbuf);
#endif

#if RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_LOW
    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " `--DL_PROCESS_FULL",
           p->dl_process_full_calls_total,
           p->dl_process_full_cycles_total,
           p->dl_process_full_cycles_per_call,
           p->dl_process_full_cycles_per_mbuf);
#elif RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH
    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_INITIAL_PKT_CLASSIFY",
           p->dl_initial_pkt_classify_calls_total,
           p->dl_initial_pkt_classify_cycles_total,
           p->dl_initial_pkt_classify_cycles_per_call,
           p->dl_initial_pkt_classify_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_GRE_DECAP",
           p->dl_gre_decap_calls_total,
           p->dl_gre_decap_cycles_total,
           p->dl_gre_decap_cycles_per_call,
           p->dl_gre_decap_cycles_per_mbuf);

#if !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF
    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_STA_LOOKUP",
           p->dl_sta_lookup_calls_total,
           p->dl_sta_lookup_cycles_total,
           p->dl_sta_lookup_cycles_per_call,
           p->dl_sta_lookup_cycles_per_mbuf);
#endif

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_STA_LOCK",
           p->dl_sta_lock_calls_total,
           p->dl_sta_lock_cycles_total,
           p->dl_sta_lock_cycles_per_call,
           p->dl_sta_lock_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_STA_ENCRYPT_DATA_GET",
           p->dl_sta_encrypt_data_get_calls_total,
           p->dl_sta_encrypt_data_get_cycles_total,
           p->dl_sta_encrypt_data_get_cycles_per_call,
           p->dl_sta_encrypt_data_get_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_ETHER_TO_IEEE80211_CONV",
           p->dl_ether_to_ieee80211_conv_calls_total,
           p->dl_ether_to_ieee80211_conv_cycles_total,
           p->dl_ether_to_ieee80211_conv_cycles_per_call,
           p->dl_ether_to_ieee80211_conv_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_CCMP_HDR_GENERATE",
           p->dl_ccmp_hdr_generate_calls_total,
           p->dl_ccmp_hdr_generate_cycles_total,
           p->dl_ccmp_hdr_generate_cycles_per_call,
           p->dl_ccmp_hdr_generate_cycles_per_mbuf);

#if !defined RWPA_STATS_CAPTURE_CRYPTO_OFF
    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_CRYPTO",
           p->dl_crypto_calls_total,
           p->dl_crypto_cycles_total,
           p->dl_crypto_cycles_per_call,
           p->dl_crypto_cycles_per_mbuf);

    printf("|%-40s| |--%-23"PRIu64" | |--%-23"PRIu64" | |--%-16"PRIu64" | |--%-16"PRIu64" |\n",
           " |  |--DL_CRYPTO_ENQUEUE",
           p->dl_crypto_enq_calls_total,
           p->dl_crypto_enq_cycles_total,
           p->dl_crypto_enq_cycles_per_call,
           p->dl_crypto_enq_cycles_per_mbuf);

    printf("|%-40s| `--%-23"PRIu64" | `--%-23"PRIu64" | `--%-16"PRIu64" | `--%-16"PRIu64" |\n",
           " |  `--DL_CRYPTO_DEQUEUE",
           p->dl_crypto_deq_calls_total,
           p->dl_crypto_deq_cycles_total,
           p->dl_crypto_deq_cycles_per_call,
           p->dl_crypto_deq_cycles_per_mbuf);
#endif

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_STA_UNLOCK",
           p->dl_sta_unlock_calls_total,
           p->dl_sta_unlock_cycles_total,
           p->dl_sta_unlock_cycles_per_call,
           p->dl_sta_unlock_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_VAP_TLV_ENCAP",
           p->dl_vap_tlv_encap_calls_total,
           p->dl_vap_tlv_encap_cycles_total,
           p->dl_vap_tlv_encap_cycles_per_call,
           p->dl_vap_tlv_encap_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_VAP_PAYLOAD_FRAGMENT",
           p->dl_vap_payload_fragment_calls_total,
           p->dl_vap_payload_fragment_cycles_total,
           p->dl_vap_payload_fragment_cycles_per_call,
           p->dl_vap_payload_fragment_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " |--DL_VAP_HDR_ENCAP",
           p->dl_vap_hdr_encap_calls_total,
           p->dl_vap_hdr_encap_cycles_total,
           p->dl_vap_hdr_encap_cycles_per_call,
           p->dl_vap_hdr_encap_cycles_per_mbuf);

    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
#if !defined RWPA_STATS_CAPTURE_PORTS_OFF
           " |--DL_AP_TUNNEL_ENCAP",
#else
           " `--DL_AP_TUNNEL_ENCAP",
#endif
           p->dl_ap_tunnel_encap_calls_total,
           p->dl_ap_tunnel_encap_cycles_total,
           p->dl_ap_tunnel_encap_cycles_per_call,
           p->dl_ap_tunnel_encap_cycles_per_mbuf);

#if !defined RWPA_STATS_CAPTURE_PORTS_OFF
    printf("|%-40s| %-26"PRIu64" | %-26"PRIu64" | %-19"PRIu64" | %-19"PRIu64" |\n",
           " `--DL_PMD_TX",
           p->dl_pmd_tx_calls_total,
           p->dl_pmd_tx_cycles_total,
           p->dl_pmd_tx_cycles_per_call ,
           p->dl_pmd_tx_cycles_per_mbuf);
#endif
#endif // RWPA_STATS_CAPTURE == CYCLE_CAPTURE_LEVEL_

    printf("%s\n", soft_spc);
#endif // ifndef RWPA_STATS_CAPTURE_DOWNLINK_OFF
}
