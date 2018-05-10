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

#ifndef __INCLUDE_STATISTICS_HANDLER_CYCLES_H__
#define __INCLUDE_STATISTICS_HANDLER_CYCLES_H__

struct parsed_statistics_cycle {
    
    /* uplink */
    uint64_t ul_cycles_total;
    uint64_t ul_cycles_per_call;
    uint64_t ul_cycles_per_mbuf;

    uint64_t ul_pmd_rx_cycles_total;
    uint64_t ul_pmd_rx_calls_total;
    uint64_t ul_pmd_rx_cycles_per_call;
    uint64_t ul_pmd_rx_cycles_per_mbuf;

    uint64_t ul_pmd_rx_excl_empties_cycles_total;
    uint64_t ul_pmd_rx_excl_empties_calls_total;
    uint64_t ul_pmd_rx_excl_empties_cycles_per_call;
    uint64_t ul_pmd_rx_excl_empties_cycles_per_mbuf;

    uint64_t ul_process_full_cycles_total;
    uint64_t ul_process_full_calls_total;
    uint64_t ul_process_full_cycles_per_call;
    uint64_t ul_process_full_cycles_per_mbuf;

    uint64_t ul_initial_pkt_classify_cycles_total;
    uint64_t ul_initial_pkt_classify_calls_total;
    uint64_t ul_initial_pkt_classify_cycles_per_call;
    uint64_t ul_initial_pkt_classify_cycles_per_mbuf;

    uint64_t ul_ap_tunnel_decap_cycles_total;
    uint64_t ul_ap_tunnel_decap_calls_total;
    uint64_t ul_ap_tunnel_decap_cycles_per_call;
    uint64_t ul_ap_tunnel_decap_cycles_per_mbuf;

    uint64_t ul_vap_hdr_parse_cycles_total;
    uint64_t ul_vap_hdr_parse_calls_total;
    uint64_t ul_vap_hdr_parse_cycles_per_call;
    uint64_t ul_vap_hdr_parse_cycles_per_mbuf;

    uint64_t ul_vap_payload_reassemble_cycles_total;
    uint64_t ul_vap_payload_reassemble_calls_total;
    uint64_t ul_vap_payload_reassemble_cycles_per_call;
    uint64_t ul_vap_payload_reassemble_cycles_per_mbuf;

    uint64_t ul_vap_hdr_decap_cycles_total;
    uint64_t ul_vap_hdr_decap_calls_total;
    uint64_t ul_vap_hdr_decap_cycles_per_call;
    uint64_t ul_vap_hdr_decap_cycles_per_mbuf;

    uint64_t ul_vap_tlv_decap_cycles_total;
    uint64_t ul_vap_tlv_decap_calls_total;
    uint64_t ul_vap_tlv_decap_cycles_per_call;
    uint64_t ul_vap_tlv_decap_cycles_per_mbuf;

    uint64_t ul_ieee80211_pkt_parse_cycles_total;
    uint64_t ul_ieee80211_pkt_parse_calls_total;
    uint64_t ul_ieee80211_pkt_parse_cycles_per_call;
    uint64_t ul_ieee80211_pkt_parse_cycles_per_mbuf;

    uint64_t ul_sta_lookup_cycles_total;
    uint64_t ul_sta_lookup_calls_total;
    uint64_t ul_sta_lookup_cycles_per_call;
    uint64_t ul_sta_lookup_cycles_per_mbuf;

    uint64_t ul_sta_lock_cycles_total;
    uint64_t ul_sta_lock_calls_total;
    uint64_t ul_sta_lock_cycles_per_call;
    uint64_t ul_sta_lock_cycles_per_mbuf;

    uint64_t ul_sta_decrypt_data_get_cycles_total;
    uint64_t ul_sta_decrypt_data_get_calls_total;
    uint64_t ul_sta_decrypt_data_get_cycles_per_call;
    uint64_t ul_sta_decrypt_data_get_cycles_per_mbuf;

    uint64_t ul_ccmp_replay_detect_cycles_total;
    uint64_t ul_ccmp_replay_detect_calls_total;
    uint64_t ul_ccmp_replay_detect_cycles_per_call;
    uint64_t ul_ccmp_replay_detect_cycles_per_mbuf;

    uint64_t ul_sta_decrypt_data_update_cycles_total;
    uint64_t ul_sta_decrypt_data_update_calls_total;
    uint64_t ul_sta_decrypt_data_update_cycles_per_call;
    uint64_t ul_sta_decrypt_data_update_cycles_per_mbuf;

    uint64_t ul_crypto_cycles_total;
    uint64_t ul_crypto_calls_total;
    uint64_t ul_crypto_cycles_per_call;
    uint64_t ul_crypto_cycles_per_mbuf;

    uint64_t ul_crypto_enq_cycles_total;
    uint64_t ul_crypto_enq_calls_total;
    uint64_t ul_crypto_enq_cycles_per_call;
    uint64_t ul_crypto_enq_cycles_per_mbuf;

    uint64_t ul_crypto_deq_cycles_total;
    uint64_t ul_crypto_deq_calls_total;
    uint64_t ul_crypto_deq_cycles_per_call;
    uint64_t ul_crypto_deq_cycles_per_mbuf;

    uint64_t ul_sta_unlock_cycles_total;
    uint64_t ul_sta_unlock_calls_total;
    uint64_t ul_sta_unlock_cycles_per_call;
    uint64_t ul_sta_unlock_cycles_per_mbuf;

    uint64_t ul_ieee80211_pkt_classify_cycles_total;
    uint64_t ul_ieee80211_pkt_classify_calls_total;
    uint64_t ul_ieee80211_pkt_classify_cycles_per_call;
    uint64_t ul_ieee80211_pkt_classify_cycles_per_mbuf;

    uint64_t ul_post_ieee80211_pkt_classify_cycles_total;
    uint64_t ul_post_ieee80211_pkt_classify_calls_total;
    uint64_t ul_post_ieee80211_pkt_classify_cycles_per_call;
    uint64_t ul_post_ieee80211_pkt_classify_cycles_per_mbuf;

    uint64_t ul_ieee80211_data_pkts_process_cycles_total;
    uint64_t ul_ieee80211_data_pkts_process_calls_total;
    uint64_t ul_ieee80211_data_pkts_process_cycles_per_call;
    uint64_t ul_ieee80211_data_pkts_process_cycles_per_mbuf;

    uint64_t ul_ieee80211_to_ether_conv_cycles_total;
    uint64_t ul_ieee80211_to_ether_conv_calls_total;
    uint64_t ul_ieee80211_to_ether_conv_cycles_per_call;
    uint64_t ul_ieee80211_to_ether_conv_cycles_per_mbuf;

    uint64_t ul_gre_encap_cycles_total;
    uint64_t ul_gre_encap_calls_total;
    uint64_t ul_gre_encap_cycles_per_call;
    uint64_t ul_gre_encap_cycles_per_mbuf;

    uint64_t ul_pmd_tx_cycles_total;
    uint64_t ul_pmd_tx_calls_total;
    uint64_t ul_pmd_tx_cycles_per_call;
    uint64_t ul_pmd_tx_cycles_per_mbuf;

    uint64_t ul_ieee80211_eapol_pkts_process_cycles_total;
    uint64_t ul_ieee80211_eapol_pkts_process_calls_total;
    uint64_t ul_ieee80211_eapol_pkts_process_cycles_per_call;
    uint64_t ul_ieee80211_eapol_pkts_process_cycles_per_mbuf;

    uint64_t ul_ccmp_decap_cycles_total;
    uint64_t ul_ccmp_decap_calls_total;
    uint64_t ul_ccmp_decap_cycles_per_call;
    uint64_t ul_ccmp_decap_cycles_per_mbuf;

    uint64_t ul_wpapt_cdi_frame_encap_cycles_total;
    uint64_t ul_wpapt_cdi_frame_encap_calls_total;
    uint64_t ul_wpapt_cdi_frame_encap_cycles_per_call;
    uint64_t ul_wpapt_cdi_frame_encap_cycles_per_mbuf;

    uint64_t ul_wpapt_cdi_hdr_encap_cycles_total;
    uint64_t ul_wpapt_cdi_hdr_encap_calls_total;
    uint64_t ul_wpapt_cdi_hdr_encap_cycles_per_call;
    uint64_t ul_wpapt_cdi_hdr_encap_cycles_per_mbuf;

    uint64_t ul_tls_tx_cycles_total;
    uint64_t ul_tls_tx_calls_total;
    uint64_t ul_tls_tx_cycles_per_call;
    uint64_t ul_tls_tx_cycles_per_mbuf;

    /* downlink */
    uint64_t dl_cycles_total;
    uint64_t dl_cycles_per_call;
    uint64_t dl_cycles_per_mbuf;

    uint64_t dl_pmd_rx_cycles_total;
    uint64_t dl_pmd_rx_calls_total;
    uint64_t dl_pmd_rx_cycles_per_call;
    uint64_t dl_pmd_rx_cycles_per_mbuf;

    uint64_t dl_pmd_rx_excl_empties_cycles_total;
    uint64_t dl_pmd_rx_excl_empties_calls_total;
    uint64_t dl_pmd_rx_excl_empties_cycles_per_call;
    uint64_t dl_pmd_rx_excl_empties_cycles_per_mbuf;

    uint64_t dl_process_full_cycles_total;
    uint64_t dl_process_full_calls_total;
    uint64_t dl_process_full_cycles_per_call;
    uint64_t dl_process_full_cycles_per_mbuf;

    uint64_t dl_initial_pkt_classify_cycles_total;
    uint64_t dl_initial_pkt_classify_calls_total;
    uint64_t dl_initial_pkt_classify_cycles_per_call;
    uint64_t dl_initial_pkt_classify_cycles_per_mbuf;

    uint64_t dl_gre_decap_cycles_total;
    uint64_t dl_gre_decap_calls_total;
    uint64_t dl_gre_decap_cycles_per_call;
    uint64_t dl_gre_decap_cycles_per_mbuf;

    uint64_t dl_sta_lookup_cycles_total;
    uint64_t dl_sta_lookup_calls_total;
    uint64_t dl_sta_lookup_cycles_per_call;
    uint64_t dl_sta_lookup_cycles_per_mbuf;

    uint64_t dl_sta_lock_cycles_total;
    uint64_t dl_sta_lock_calls_total;
    uint64_t dl_sta_lock_cycles_per_call;
    uint64_t dl_sta_lock_cycles_per_mbuf;

    uint64_t dl_sta_encrypt_data_get_cycles_total;
    uint64_t dl_sta_encrypt_data_get_calls_total;
    uint64_t dl_sta_encrypt_data_get_cycles_per_call;
    uint64_t dl_sta_encrypt_data_get_cycles_per_mbuf;

    uint64_t dl_ether_to_ieee80211_conv_cycles_total;
    uint64_t dl_ether_to_ieee80211_conv_calls_total;
    uint64_t dl_ether_to_ieee80211_conv_cycles_per_call;
    uint64_t dl_ether_to_ieee80211_conv_cycles_per_mbuf;

    uint64_t dl_ccmp_hdr_generate_cycles_total;
    uint64_t dl_ccmp_hdr_generate_calls_total;
    uint64_t dl_ccmp_hdr_generate_cycles_per_call;
    uint64_t dl_ccmp_hdr_generate_cycles_per_mbuf;

    uint64_t dl_crypto_cycles_total;
    uint64_t dl_crypto_calls_total;
    uint64_t dl_crypto_cycles_per_call;
    uint64_t dl_crypto_cycles_per_mbuf;

    uint64_t dl_crypto_enq_cycles_total;
    uint64_t dl_crypto_enq_calls_total;
    uint64_t dl_crypto_enq_cycles_per_call;
    uint64_t dl_crypto_enq_cycles_per_mbuf;

    uint64_t dl_crypto_deq_cycles_total;
    uint64_t dl_crypto_deq_calls_total;
    uint64_t dl_crypto_deq_cycles_per_call;
    uint64_t dl_crypto_deq_cycles_per_mbuf;

    uint64_t dl_sta_unlock_cycles_total;
    uint64_t dl_sta_unlock_calls_total;
    uint64_t dl_sta_unlock_cycles_per_call;
    uint64_t dl_sta_unlock_cycles_per_mbuf;

    uint64_t dl_vap_tlv_encap_cycles_total;
    uint64_t dl_vap_tlv_encap_calls_total;
    uint64_t dl_vap_tlv_encap_cycles_per_call;
    uint64_t dl_vap_tlv_encap_cycles_per_mbuf;

    uint64_t dl_vap_payload_fragment_cycles_total;
    uint64_t dl_vap_payload_fragment_calls_total;
    uint64_t dl_vap_payload_fragment_cycles_per_call;
    uint64_t dl_vap_payload_fragment_cycles_per_mbuf;

    uint64_t dl_vap_hdr_encap_cycles_total;
    uint64_t dl_vap_hdr_encap_calls_total;
    uint64_t dl_vap_hdr_encap_cycles_per_call;
    uint64_t dl_vap_hdr_encap_cycles_per_mbuf;

    uint64_t dl_ap_tunnel_encap_cycles_total;
    uint64_t dl_ap_tunnel_encap_calls_total;
    uint64_t dl_ap_tunnel_encap_cycles_per_call;
    uint64_t dl_ap_tunnel_encap_cycles_per_mbuf;

    uint64_t dl_pmd_tx_cycles_total;
    uint64_t dl_pmd_tx_calls_total;
    uint64_t dl_pmd_tx_cycles_per_call;
    uint64_t dl_pmd_tx_cycles_per_mbuf;
};

void
sts_hdlr_cycle_init(struct app_params *app);

void
sts_hdlr_cycle_free(void);

void
sts_hdlr_cycle_update_shadow_stats(void);

void
sts_hdlr_cycle_update_parsed_stats(void);

void
sts_hdlr_cycle_clear_stats(void);

void
sts_hdlr_cycle_print(enum rwpa_stats_lvl);

#endif // __INCLUDE_STATISTICS_HANDLER_CYCLES_H__
