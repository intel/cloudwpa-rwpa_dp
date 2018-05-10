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

#ifndef __INCLUDE_UPLINK_MACROS_H__
#define __INCLUDE_UPLINK_MACROS_H__

/*
 * HELPER MACROS
 * - should not be called from outside this file
 */

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

#define _STORE_STA_BULK_LOOKUP_STATS(n, f)                                     \
({                                                                             \
     uint8_t matched = 0;                                                      \
     for (unsigned int i = 0; i < n; i++) {                                    \
         if (f[i] >= 0)                                                        \
             matched++;                                                        \
     }                                                                         \
                                                                               \
     struct stats_sta_lookup *stats =                                          \
         stats_capture_sta_lookup_get_mem_info(STATS_STA_LOOKUP_TYPE_UL);      \
                                                                               \
     if (likely(stats != NULL)) {                                              \
         stats->matched += matched;                                            \
         stats->unmatched += n - matched;                                      \
         stats->num_pkts += n;                                                 \
         stats->last_burst[                                                    \
             stats->last_burst_index++ %                                       \
             STA_LOOKUP_BURST_LEN] = n;                                        \
         stats->call_num  += 1;                                                \
     }                                                                         \
})

#else // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

#define _STORE_STA_BULK_LOOKUP_STATS(n, f)                                     \
     do {} while(0)

#endif // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define _CCMP_BURST_ENQUEUE_STATS(l, e)                                        \
({                                                                             \
     struct stats_crypto *stats =                                              \
         stats_capture_crypto_get_mem_info(STATS_CRYPTO_TYPE_UL);              \
                                                                               \
     if (likely(stats != NULL)) {                                              \
         stats->driver_id = crypto_driver_id_get();                            \
         stats->call_num += 1;                                                 \
         stats->total_packets_enqueued += e;                                   \
         stats->total_enqueue_calls += 1;                                      \
         if (unlikely(enq < l))                                                \
             stats->total_enqueue_errors += (l - e);                           \
     }                                                                         \
})

#define _CCMP_BURST_DEQUEUE_CALL_STATS                                         \
({                                                                             \
     struct stats_crypto *stats =                                              \
         stats_capture_crypto_get_mem_info(STATS_CRYPTO_TYPE_UL);              \
                                                                               \
     if (likely(stats != NULL)) {                                              \
         stats->call_num += 1;                                                 \
         stats->total_dequeue_calls += 1;                                      \
     }                                                                         \
})

#else // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define _CCMP_BURST_ENQUEUE_STATS(l, e)                                        \
     do {} while(0)

#define _CCMP_BURST_DEQUEUE_CALL_STATS                                         \
     do {} while(0)

#endif // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_PORTS_OFF && !defined RWPA_STATS_CAPTURE_UPLINK_OFF

#define _UL_PMD_RX_CYCLE_CAPTURE_START                                         \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_PMD_RX)
#define _UL_PMD_RX_CYCLE_CAPTURE_STOP                                          \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_PMD_RX)
#define _UL_PMD_RX_CYCLE_CAPTURE_COPY_LAST                                     \
     CYCLE_CAPTURE_COPY_LAST(CYCLE_CAPTURE_UL_PMD_RX_EXCL_EMPTIES,             \
                             CYCLE_CAPTURE_UL_PMD_RX)

#else // !defined RWPA_STATS_CAPTURE_PORTS_OFF && !defined RWPA_STATS_CAPTURE_UPLINK_OFF

#define _UL_PMD_RX_CYCLE_CAPTURE_START
#define _UL_PMD_RX_CYCLE_CAPTURE_STOP
#define _UL_PMD_RX_CYCLE_CAPTURE_COPY_LAST

#endif // !defined RWPA_STATS_CAPTURE_PORTS_OFF && !defined RWPA_STATS_CAPTURE_UPLINK_OFF

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF &&                              \
    !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&                                  \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _UL_STA_LOOKUP_CYCLE_CAPTURE_START                                     \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_STA_LOOKUP)
#define _UL_STA_LOOKUP_CYCLE_CAPTURE_STOP                                      \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_STA_LOOKUP)

#else // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF &&
      // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _UL_STA_LOOKUP_CYCLE_CAPTURE_START
#define _UL_STA_LOOKUP_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF &&
       // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_CRYPTO_OFF &&                                  \
    !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&                                  \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _UL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_START                                 \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_CRYPTO_ENQUEUE)
#define _UL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_STOP                                  \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_CRYPTO_ENQUEUE)

#define _UL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_START                                 \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_CRYPTO_DEQUEUE)
#define _UL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_STOP                                  \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_CRYPTO_DEQUEUE)

#else // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF &&
      // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _UL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_START
#define _UL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_STOP

#define _UL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_START
#define _UL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF &&
       // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&                                  \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _UL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_START                           \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_INITIAL_PKT_CLASSIFY)
#define _UL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_STOP                            \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_INITIAL_PKT_CLASSIFY)

#define _UL_AP_TUNNEL_DECAP_CYCLE_CAPTURE_START                                \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_AP_TUNNEL_DECAP)
#define _UL_AP_TUNNEL_DECAP_CYCLE_CAPTURE_STOP                                 \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_AP_TUNNEL_DECAP)

#define _UL_VAP_HDR_PARSE_CYCLE_CAPTURE_START                                  \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_VAP_HDR_PARSE)
#define _UL_VAP_HDR_PARSE_CYCLE_CAPTURE_STOP                                   \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_VAP_HDR_PARSE)

#define _UL_VAP_HDR_DECAP_CYCLE_CAPTURE_START                                  \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_VAP_HDR_DECAP)
#define _UL_VAP_HDR_DECAP_CYCLE_CAPTURE_STOP                                   \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_VAP_HDR_DECAP)

#define _UL_VAP_TLV_DECAP_CYCLE_CAPTURE_START                                  \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_VAP_TLV_DECAP)
#define _UL_VAP_TLV_DECAP_CYCLE_CAPTURE_STOP                                   \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_VAP_TLV_DECAP)

#define _UL_IEEE80211_PKT_PARSE_CYCLE_CAPTURE_START                            \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_IEEE80211_PKT_PARSE)
#define _UL_IEEE80211_PKT_PARSE_CYCLE_CAPTURE_STOP                             \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_IEEE80211_PKT_PARSE)

#define _UL_STA_LOCK_CYCLE_CAPTURE_START                                       \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_STA_LOCK)
#define _UL_STA_LOCK_CYCLE_CAPTURE_STOP                                        \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_STA_LOCK)

#define _UL_STA_DECRYPT_DATA_GET_CYCLE_CAPTURE_START                           \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_GET)
#define _UL_STA_DECRYPT_DATA_GET_CYCLE_CAPTURE_STOP                            \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_GET)

#define _UL_CCMP_REPLAY_DETECT_CYCLE_CAPTURE_START                             \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_CCMP_REPLAY_DETECT)
#define _UL_CCMP_REPLAY_DETECT_CYCLE_CAPTURE_STOP                              \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_CCMP_REPLAY_DETECT)

#define _UL_STA_DECRYPT_DATA_UPDATE_CYCLE_CAPTURE_START                        \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_UPDATE)
#define _UL_STA_DECRYPT_DATA_UPDATE_CYCLE_CAPTURE_STOP                         \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_STA_DECRYPT_DATA_UPDATE)

#define _UL_STA_UNLOCK_CYCLE_CAPTURE_START                                     \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_STA_UNLOCK)
#define _UL_STA_UNLOCK_CYCLE_CAPTURE_STOP                                      \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_STA_UNLOCK)

#define _UL_IEEE80211_PKT_CLASSIFY_CYCLE_CAPTURE_START                         \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_IEEE80211_PKT_CLASSIFY)
#define _UL_IEEE80211_PKT_CLASSIFY_CYCLE_CAPTURE_STOP                          \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_IEEE80211_PKT_CLASSIFY)

#define _UL_IEEE80211_TO_ETHER_CONV_CYCLE_CAPTURE_START                        \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_IEEE80211_TO_ETHER_CONV);
#define _UL_IEEE80211_TO_ETHER_CONV_CYCLE_CAPTURE_STOP                         \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_IEEE80211_TO_ETHER_CONV);

#define _UL_GRE_ENCAP_CYCLE_CAPTURE_START                                      \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_GRE_ENCAP);
#define _UL_GRE_ENCAP_CYCLE_CAPTURE_STOP                                       \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_GRE_ENCAP);

#define _UL_CCMP_DECAP_CYCLE_CAPTURE_START                                     \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_CCMP_DECAP);
#define _UL_CCMP_DECAP_CYCLE_CAPTURE_STOP                                      \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_CCMP_DECAP);

#define _UL_WPAPT_CDI_FRAME_ENCAP_CYCLE_CAPTURE_START                          \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_WPAPT_CDI_FRAME_ENCAP);
#define _UL_WPAPT_CDI_FRAME_ENCAP_CYCLE_CAPTURE_STOP                           \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_WPAPT_CDI_FRAME_ENCAP);

#define _UL_WPAPT_CDI_HDR_ENCAP_CYCLE_CAPTURE_START                            \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_WPAPT_CDI_HDR_ENCAP);
#define _UL_WPAPT_CDI_HDR_ENCAP_CYCLE_CAPTURE_STOP                             \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_WPAPT_CDI_HDR_ENCAP);

#define _UL_TLS_TX_CYCLE_CAPTURE_START                                         \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_TLS_TX);
#define _UL_TLS_TX_CYCLE_CAPTURE_STOP                                          \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_TLS_TX);

#else // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _UL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_START
#define _UL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_STOP

#define _UL_AP_TUNNEL_DECAP_CYCLE_CAPTURE_START
#define _UL_AP_TUNNEL_DECAP_CYCLE_CAPTURE_STOP

#define _UL_VAP_HDR_PARSE_CYCLE_CAPTURE_START
#define _UL_VAP_HDR_PARSE_CYCLE_CAPTURE_STOP

#define _UL_VAP_HDR_DECAP_CYCLE_CAPTURE_START
#define _UL_VAP_HDR_DECAP_CYCLE_CAPTURE_STOP

#define _UL_VAP_TLV_DECAP_CYCLE_CAPTURE_START
#define _UL_VAP_TLV_DECAP_CYCLE_CAPTURE_STOP

#define _UL_IEEE80211_PKT_PARSE_CYCLE_CAPTURE_START
#define _UL_IEEE80211_PKT_PARSE_CYCLE_CAPTURE_STOP

#define _UL_STA_LOCK_CYCLE_CAPTURE_START
#define _UL_STA_LOCK_CYCLE_CAPTURE_STOP

#define _UL_STA_DECRYPT_DATA_GET_CYCLE_CAPTURE_START
#define _UL_STA_DECRYPT_DATA_GET_CYCLE_CAPTURE_STOP

#define _UL_CCMP_REPLAY_DETECT_CYCLE_CAPTURE_START
#define _UL_CCMP_REPLAY_DETECT_CYCLE_CAPTURE_STOP

#define _UL_STA_DECRYPT_DATA_UPDATE_CYCLE_CAPTURE_START
#define _UL_STA_DECRYPT_DATA_UPDATE_CYCLE_CAPTURE_STOP

#define _UL_STA_UNLOCK_CYCLE_CAPTURE_START
#define _UL_STA_UNLOCK_CYCLE_CAPTURE_STOP

#define _UL_IEEE80211_PKT_CLASSIFY_CYCLE_CAPTURE_START
#define _UL_IEEE80211_PKT_CLASSIFY_CYCLE_CAPTURE_STOP

#define _UL_IEEE80211_TO_ETHER_CONV_CYCLE_CAPTURE_START
#define _UL_IEEE80211_TO_ETHER_CONV_CYCLE_CAPTURE_STOP

#define _UL_GRE_ENCAP_CYCLE_CAPTURE_START
#define _UL_GRE_ENCAP_CYCLE_CAPTURE_STOP

#define _UL_CCMP_DECAP_CYCLE_CAPTURE_START
#define _UL_CCMP_DECAP_CYCLE_CAPTURE_STOP

#define _UL_WPAPT_CDI_FRAME_ENCAP_CYCLE_CAPTURE_START
#define _UL_WPAPT_CDI_FRAME_ENCAP_CYCLE_CAPTURE_STOP

#define _UL_WPAPT_CDI_HDR_ENCAP_CYCLE_CAPTURE_START
#define _UL_WPAPT_CDI_HDR_ENCAP_CYCLE_CAPTURE_STOP

#define _UL_TLS_TX_CYCLE_CAPTURE_START
#define _UL_TLS_TX_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_PORTS_OFF &&                                   \
    !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&                                  \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _UL_PMD_TX_CYCLE_CAPTURE_START                                         \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_PMD_TX)
#define _UL_PMD_TX_CYCLE_CAPTURE_STOP                                          \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_PMD_TX)

#else // !defined RWPA_STATS_CAPTURE_PORTS_OFF &&
      // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _UL_PMD_TX_CYCLE_CAPTURE_START
#define _UL_PMD_TX_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_PORTS_OFF &&
       // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

////////////////////////////////////////////////////////////////////////////////

/*
 * PUBLIC MACROS
 */

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_UPLINK_OFF && defined RWPA_STATS_CAPTURE

#define UL_DATA_DROP_STAT_INC(stat, amt)                                       \
     stats_capture_uplink_drops_inc(stat, (uint64_t)amt);

#define UL_DATA_PMD_READ_STAT_INC(stat, amt)                                   \
     stats_capture_uplink_pmd_reads_inc(stat, (uint64_t)amt);

#else

#define UL_DATA_DROP_STAT_INC(stat, amt)
#define UL_DATA_PMD_READ_STAT_INC(stat, amt)

#endif

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_CONTROL_OFF && defined RWPA_STATS_CAPTURE

#define UL_CTRL_DROP_STAT_INC(stat, amt)                                       \
     stats_capture_control_drops_inc(stat, (uint64_t)amt);

#else

#define UL_CTRL_DROP_STAT_INC(stat, amt)

#endif

////////////////////////////////////////////////////////////////////////////////

#define DATA_LOG_AND_DROP(p_mbuf, level, logtype, err_msg, stat)               \
({                                                                             \
     UL_DATA_DROP_STAT_INC(stat, 1);                                           \
     RWPA_LOG(level, logtype, err_msg);                                        \
     DROP(p_mbuf);                                                             \
})

#define CTRL_LOG_AND_DROP(p_mbuf, level, logtype, err_msg, stat)               \
({                                                                             \
     UL_CTRL_DROP_STAT_INC(stat, 1);                                           \
     RWPA_LOG(level, logtype, err_msg);                                        \
     DROP(p_mbuf);                                                             \
})

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define CCMP_BURST_DEQUEUE_STATS(nb_to_deq, nb_deq_success)                    \
({                                                                             \
     struct stats_crypto *stats =                                              \
         stats_capture_crypto_get_mem_info(STATS_CRYPTO_TYPE_UL);              \
                                                                               \
     if (likely(stats != NULL)) {                                              \
         stats->total_packets_dequeued += nb_to_deq;                           \
         if (unlikely(nb_deq_success < nb_to_deq))                             \
             stats->total_dequeue_errors += (nb_to_deq - nb_deq_success);      \
     }                                                                         \
})

#else // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define CCMP_BURST_DEQUEUE_STATS(nb_to_deq, nb_deq_success)                    \
     do {} while(0)

#endif // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&                                  \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define UL_VAP_PAYLOAD_REASSEMBLE_CYCLE_CAPTURE_START                          \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_VAP_PAYLOAD_REASSEMBLE)
#define UL_VAP_PAYLOAD_REASSEMBLE_CYCLE_CAPTURE_STOP                           \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_VAP_PAYLOAD_REASSEMBLE)

#else // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define UL_VAP_PAYLOAD_REASSEMBLE_CYCLE_CAPTURE_START
#define UL_VAP_PAYLOAD_REASSEMBLE_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#if !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&                                  \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_LOW

#define UL_PROCESS_FULL_CYCLE_CAPTURE_START                                    \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_UL_PROCESS_FULL)
#define UL_PROCESS_FULL_CYCLE_CAPTURE_STOP                                     \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_UL_PROCESS_FULL)

#else // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_LOW

#define UL_PROCESS_FULL_CYCLE_CAPTURE_START
#define UL_PROCESS_FULL_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_LOW

////////////////////////////////////////////////////////////////////////////////

#ifndef RWPA_CYCLE_CAPTURE

#define RTE_ETH_RX_BURST(p, q, r, n)        rte_eth_rx_burst(p, q, r, n)
#define INITIAL_PACKET_CLASSIFY(m)          initial_packet_classify(m)

#ifndef RWPA_AP_TUNNELLING_GRE
#define AP_TUNNEL_DECAP(m, meta)            udp_decap(m, meta)
#else
#define AP_TUNNEL_DECAP(m, meta)            gre_decap(m, meta)
#endif

#define VAP_HDR_PARSE(m, meta)              vap_hdr_parse(m, meta)
#define VAP_HDR_DECAP(m)                    vap_hdr_decap(m)
#define VAP_TLV_DECAP(m)                    vap_tlv_decap(m)
#define IEEE80211_PACKET_PARSE(m, meta)     ieee80211_packet_parse(m, meta)

#if !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

#define STORE_STA_BULK_LOOKUP(a, n, f)                                         \
({                                                                             \
     store_sta_bulk_lookup(a, n, f);                                           \
     _STORE_STA_BULK_LOOKUP_STATS(n, f);                                       \
})

#else // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

#define STORE_STA_BULK_LOOKUP(a, n, f)                                         \
     store_sta_bulk_lookup(a, n, f)

#endif // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

#define STA_READ_LOCK(s)                    sta_read_lock(s)
#define STA_DECRYPT_DATA_GET(s, t, a, c, v) sta_decrypt_data_get(s, t, a, c, v)
#define CCMP_REPLAY_DETECT(h, c)            ccmp_replay_detect(h, c)
#define STA_PTK_DECRYPT_COUNTER_SET(s, t, c)                                   \
     sta_ptk_decrypt_counter_set(s, t, c)

#if !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define CCMP_BURST_ENQUEUE(b, l, m, o, q, s)                                   \
({                                                                             \
     uint16_t enq = ccmp_burst_enqueue(b, l, m, o, q, s);                      \
     _CCMP_BURST_ENQUEUE_STATS(l, enq);                                        \
     enq;                                                                      \
})

#define CCMP_BURST_DEQUEUE(b, l, q, n, s)                                      \
({                                                                             \
     uint16_t deq = ccmp_burst_dequeue(b, l, q, n, s);                         \
     _CCMP_BURST_DEQUEUE_CALL_STATS;                                           \
     deq;                                                                      \
})

#else // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define CCMP_BURST_ENQUEUE(b, l, m, o, q, s)                                   \
     ccmp_burst_enqueue(b, l, m, o, q, s)

#define CCMP_BURST_DEQUEUE(b, l, q, n, s)                                      \
     ccmp_burst_dequeue(b, l, q, n, s)

#endif // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define STA_READ_UNLOCK(s)                  sta_read_unlock(s)
#define IEEE80211_PACKET_CLASSIFY(m, meta)  ieee80211_packet_classify(m, meta)
#define IEEE80211_TO_ETHER_CONVERT(m, meta) ieee80211_to_ether_convert(m, meta)
#define GRE_ENCAP(m, si, sm, di, dm)        gre_encap(m, si, sm, di, dm, 0, 0)
#define RTE_ETH_TX_BUFFER(p, q, t, m)       rte_eth_tx_buffer(p, q, t, m)
#define CCMP_DECAP(m, meta)                 ccmp_decap(m, meta)
#define WPAPT_CDI_FRAME_ENCAP(m, meta, l)   wpapt_cdi_frame_encap(m, meta, l)
#define WPAPT_CDI_HDR_ENCAP(m, i, l)        wpapt_cdi_hdr_encap(m, i, l)
#define TLS_SOCKET_WRITE(t, m)              tls_socket_write(t, m)

#else // ifndef RWPA_CYCLE_CAPTURE

#define RTE_ETH_RX_BURST(p, q, r, n)                                           \
({                                                                             \
     _UL_PMD_RX_CYCLE_CAPTURE_START;                                           \
     unsigned len = rte_eth_rx_burst(p, q, r, n);                              \
     _UL_PMD_RX_CYCLE_CAPTURE_STOP;                                            \
     if (len) {                                                                \
         _UL_PMD_RX_CYCLE_CAPTURE_COPY_LAST;                                   \
     }                                                                         \
     len;                                                                      \
})

#define INITIAL_PACKET_CLASSIFY(m)                                             \
({                                                                             \
     _UL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_START;                             \
     enum outer_pkt_type type = initial_packet_classify(m);                    \
     _UL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_STOP;                              \
     type;                                                                     \
})

#ifndef RWPA_AP_TUNNELLING_GRE
#define AP_TUNNEL_DECAP(m, meta)                                               \
({                                                                             \
     _UL_AP_TUNNEL_DECAP_CYCLE_CAPTURE_START;                                  \
     enum rwpa_status sts = udp_decap(m, meta);                                \
     _UL_AP_TUNNEL_DECAP_CYCLE_CAPTURE_STOP;                                   \
     sts;                                                                      \
})
#else
#define AP_TUNNEL_DECAP(m, meta)                                               \
({                                                                             \
     _UL_AP_TUNNEL_DECAP_CYCLE_CAPTURE_START;                                  \
     enum rwpa_status sts = gre_decap(m, meta);                                \
     _UL_AP_TUNNEL_DECAP_CYCLE_CAPTURE_STOP;                                   \
     sts;                                                                      \
})
#endif

#define VAP_HDR_PARSE(m, meta)                                                 \
({                                                                             \
     _UL_VAP_HDR_PARSE_CYCLE_CAPTURE_START;                                    \
     enum rwpa_status sts = vap_hdr_parse(m, meta);                            \
     _UL_VAP_HDR_PARSE_CYCLE_CAPTURE_STOP;                                     \
     sts;                                                                      \
})

#define VAP_HDR_DECAP(m)                                                       \
({                                                                             \
     _UL_VAP_HDR_DECAP_CYCLE_CAPTURE_START;                                    \
     enum rwpa_status sts = vap_hdr_decap(m);                                  \
     _UL_VAP_HDR_DECAP_CYCLE_CAPTURE_STOP;                                     \
     sts;                                                                      \
})

#define VAP_TLV_DECAP(m)                                                       \
({                                                                             \
     _UL_VAP_TLV_DECAP_CYCLE_CAPTURE_START;                                    \
     enum rwpa_status sts = vap_tlv_decap(m);                                  \
     _UL_VAP_TLV_DECAP_CYCLE_CAPTURE_STOP;                                     \
     sts;                                                                      \
})

#define IEEE80211_PACKET_PARSE(m, meta)                                        \
({                                                                             \
     _UL_IEEE80211_PKT_PARSE_CYCLE_CAPTURE_START;                              \
     ieee80211_packet_parse(m, meta);                                          \
     _UL_IEEE80211_PKT_PARSE_CYCLE_CAPTURE_STOP;                               \
})

#if !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

#define STORE_STA_BULK_LOOKUP(a, n, f)                                         \
({                                                                             \
     _UL_STA_LOOKUP_CYCLE_CAPTURE_START;                                       \
     store_sta_bulk_lookup(a, n, f);                                           \
     _UL_STA_LOOKUP_CYCLE_CAPTURE_STOP;                                        \
     _STORE_STA_BULK_LOOKUP_STATS(n, f);                                       \
})

#else // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

#define STORE_STA_BULK_LOOKUP(a, n, f)                                         \
({                                                                             \
     _UL_STA_LOOKUP_CYCLE_CAPTURE_START;                                       \
     store_sta_bulk_lookup(a, n, f);                                           \
     _UL_STA_LOOKUP_CYCLE_CAPTURE_STOP;                                        \
})

#endif // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

#define STA_READ_LOCK(s)                                                       \
({                                                                             \
     _UL_STA_LOCK_CYCLE_CAPTURE_START;                                         \
     sta_read_lock(s);                                                         \
     _UL_STA_LOCK_CYCLE_CAPTURE_STOP;                                          \
})

#define STA_DECRYPT_DATA_GET(s, t, a, c, v)                                    \
({                                                                             \
     _UL_STA_DECRYPT_DATA_GET_CYCLE_CAPTURE_START;                             \
     sta_decrypt_data_get(s, t, a, c, v);                                      \
     _UL_STA_DECRYPT_DATA_GET_CYCLE_CAPTURE_STOP;                              \
})

#define CCMP_REPLAY_DETECT(h, c)                                               \
({                                                                             \
     _UL_CCMP_REPLAY_DETECT_CYCLE_CAPTURE_START;                               \
     enum rwpa_status sts = ccmp_replay_detect(h, c);                          \
     _UL_CCMP_REPLAY_DETECT_CYCLE_CAPTURE_STOP;                                \
     sts;                                                                      \
})

#define STA_PTK_DECRYPT_COUNTER_SET(s, t, c)                                   \
({                                                                             \
     _UL_STA_DECRYPT_DATA_UPDATE_CYCLE_CAPTURE_START;                          \
     sta_ptk_decrypt_counter_set(s, t, c);                                     \
     _UL_STA_DECRYPT_DATA_UPDATE_CYCLE_CAPTURE_STOP;                           \
})

#if !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define CCMP_BURST_ENQUEUE(b, l, m, o, q, s)                                   \
({                                                                             \
     _UL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_START;                                   \
     uint16_t enq = ccmp_burst_enqueue(b, l, m, o, q, s);                      \
     _UL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_STOP;                                    \
     _CCMP_BURST_ENQUEUE_STATS(l, enq);                                        \
     enq;                                                                      \
})

#define CCMP_BURST_DEQUEUE(b, l, q, n, s)                                      \
({                                                                             \
     _UL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_START;                                   \
     uint16_t deq = ccmp_burst_dequeue(b, l, q, n, s);                         \
     _UL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_STOP;                                    \
     _CCMP_BURST_DEQUEUE_CALL_STATS;                                           \
     deq;                                                                      \
})

#else // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define CCMP_BURST_ENQUEUE(b, l, m, o, q, s)                                   \
({                                                                             \
     _UL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_START;                                   \
     uint16_t enq = ccmp_burst_enqueue(b, l, m, o, q, s);                      \
     _UL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_STOP;                                    \
     enq;                                                                      \
})

#define CCMP_BURST_DEQUEUE(b, l, q, n, s)                                      \
({                                                                             \
     _UL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_START;                                   \
     uint16_t deq = ccmp_burst_dequeue(b, l, q, n, s);                         \
     _UL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_STOP;                                    \
     deq;                                                                      \
})

#endif // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define STA_READ_UNLOCK(s)                                                     \
({                                                                             \
     _UL_STA_UNLOCK_CYCLE_CAPTURE_START;                                       \
     sta_read_unlock(s);                                                       \
     _UL_STA_UNLOCK_CYCLE_CAPTURE_STOP;                                        \
})

#define IEEE80211_PACKET_CLASSIFY(m, meta)                                     \
({                                                                             \
     _UL_IEEE80211_PKT_CLASSIFY_CYCLE_CAPTURE_START;                           \
     enum ieee80211_pkt_type pkt_type =                                        \
                             ieee80211_packet_classify(m, meta);               \
     _UL_IEEE80211_PKT_CLASSIFY_CYCLE_CAPTURE_STOP;                            \
     pkt_type;                                                                 \
})

#define IEEE80211_TO_ETHER_CONVERT(m, meta)                                    \
({                                                                             \
     _UL_IEEE80211_TO_ETHER_CONV_CYCLE_CAPTURE_START;                          \
     enum rwpa_status sts = ieee80211_to_ether_convert(m, meta);               \
     _UL_IEEE80211_TO_ETHER_CONV_CYCLE_CAPTURE_STOP;                           \
     sts;                                                                      \
})

#define GRE_ENCAP(m, si, sm, di, dm)                                           \
({                                                                             \
     _UL_GRE_ENCAP_CYCLE_CAPTURE_START;                                        \
     enum rwpa_status sts = gre_encap(m, si, sm, di, dm, 0, 0);                \
     _UL_GRE_ENCAP_CYCLE_CAPTURE_STOP;                                         \
     sts;                                                                      \
})

#define RTE_ETH_TX_BUFFER(p, q, t, m)                                          \
({                                                                             \
     _UL_PMD_TX_CYCLE_CAPTURE_START;                                           \
     rte_eth_tx_buffer(p, q, t, m);                                            \
     _UL_PMD_TX_CYCLE_CAPTURE_STOP;                                            \
})

#define CCMP_DECAP(m, meta)                                                    \
({                                                                             \
     _UL_CCMP_DECAP_CYCLE_CAPTURE_START;                                       \
     enum rwpa_status sts = ccmp_decap(m, meta);                               \
     _UL_CCMP_DECAP_CYCLE_CAPTURE_STOP;                                        \
     sts;                                                                      \
})

#define WPAPT_CDI_FRAME_ENCAP(m, meta, l)                                      \
({                                                                             \
     _UL_WPAPT_CDI_FRAME_ENCAP_CYCLE_CAPTURE_START;                            \
     enum rwpa_status sts = wpapt_cdi_frame_encap(m, meta, l);                 \
     _UL_WPAPT_CDI_FRAME_ENCAP_CYCLE_CAPTURE_STOP;                             \
     sts;                                                                      \
})

#define WPAPT_CDI_HDR_ENCAP(m, i, l)                                           \
({                                                                             \
     _UL_WPAPT_CDI_HDR_ENCAP_CYCLE_CAPTURE_START;                              \
     enum rwpa_status sts = wpapt_cdi_hdr_encap(m, i, l);                      \
     _UL_WPAPT_CDI_HDR_ENCAP_CYCLE_CAPTURE_STOP;                               \
     sts;                                                                      \
})

#define TLS_SOCKET_WRITE(t, m)                                                 \
({                                                                             \
     _UL_TLS_TX_CYCLE_CAPTURE_START;                                           \
     tls_socket_write(t, m);                                                   \
     _UL_TLS_TX_CYCLE_CAPTURE_STOP;                                            \
})

#endif // ifndef RWPA_CYCLE_CAPTURE

////////////////////////////////////////////////////////////////////////////////

#endif // __INCLUDE_UPLINK_MACROS_H__
