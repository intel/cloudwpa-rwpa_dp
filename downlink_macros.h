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

#ifndef __INCLUDE_DOWNLINK_MACROS_H__
#define __INCLUDE_DOWNLINK_MACROS_H__

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
         stats_capture_sta_lookup_get_mem_info(STATS_STA_LOOKUP_TYPE_DL);      \
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
         stats_capture_crypto_get_mem_info(STATS_CRYPTO_TYPE_DL);              \
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
         stats_capture_crypto_get_mem_info(STATS_CRYPTO_TYPE_DL);              \
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

#if !defined RWPA_STATS_CAPTURE_PORTS_OFF && !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF

#define _DL_PMD_RX_CYCLE_CAPTURE_START                                         \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_PMD_RX)
#define _DL_PMD_RX_CYCLE_CAPTURE_STOP                                          \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_PMD_RX)
#define _DL_PMD_RX_CYCLE_CAPTURE_COPY_LAST                                     \
     CYCLE_CAPTURE_COPY_LAST(CYCLE_CAPTURE_DL_PMD_RX_EXCL_EMPTIES,             \
                             CYCLE_CAPTURE_DL_PMD_RX)

#else // !defined RWPA_STATS_CAPTURE_PORTS_OFF && !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF

#define _DL_PMD_RX_CYCLE_CAPTURE_START
#define _DL_PMD_RX_CYCLE_CAPTURE_STOP
#define _DL_PMD_RX_CYCLE_CAPTURE_COPY_LAST

#endif // !defined RWPA_STATS_CAPTURE_PORTS_OFF && !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF &&                              \
    !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&                                \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _DL_STA_LOOKUP_CYCLE_CAPTURE_START                                     \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_STA_LOOKUP)
#define _DL_STA_LOOKUP_CYCLE_CAPTURE_STOP                                      \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_STA_LOOKUP)

#else // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF &&
      // !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _DL_STA_LOOKUP_CYCLE_CAPTURE_START
#define _DL_STA_LOOKUP_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF &&
       // !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_CRYPTO_OFF &&                                  \
    !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&                                \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _DL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_START                                 \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_CRYPTO_ENQUEUE)
#define _DL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_STOP                                  \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_CRYPTO_ENQUEUE)

#define _DL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_START                                 \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_CRYPTO_DEQUEUE)
#define _DL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_STOP                                  \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_CRYPTO_DEQUEUE)

#else // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF &&
      // !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _DL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_START
#define _DL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_STOP

#define _DL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_START
#define _DL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF &&
       // !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&                                \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _DL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_START                           \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_INITIAL_PKT_CLASSIFY)
#define _DL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_STOP                            \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_INITIAL_PKT_CLASSIFY)

#define _DL_GRE_DECAP_CYCLE_CAPTURE_START                                      \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_GRE_DECAP)
#define _DL_GRE_DECAP_CYCLE_CAPTURE_STOP                                       \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_GRE_DECAP)

#define _DL_STA_LOCK_CYCLE_CAPTURE_START                                       \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_STA_LOCK)
#define _DL_STA_LOCK_CYCLE_CAPTURE_STOP                                        \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_STA_LOCK)

#define _DL_STA_ENCRYPT_DATA_GET_CYCLE_CAPTURE_START                           \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_STA_ENCRYPT_DATA_GET)
#define _DL_STA_ENCRYPT_DATA_GET_CYCLE_CAPTURE_STOP                            \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_STA_ENCRYPT_DATA_GET)

#define _DL_ETHER_TO_IEEE80211_CONV_CYCLE_CAPTURE_START                        \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_ETHER_TO_IEEE80211_CONV)
#define _DL_ETHER_TO_IEEE80211_CONV_CYCLE_CAPTURE_STOP                         \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_ETHER_TO_IEEE80211_CONV)

#define _DL_CCMP_HDR_GENERATE_CYCLE_CAPTURE_START                              \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_CCMP_HDR_GENERATE)
#define _DL_CCMP_HDR_GENERATE_CYCLE_CAPTURE_STOP                               \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_CCMP_HDR_GENERATE)

#define _DL_STA_UNLOCK_CYCLE_CAPTURE_START                                     \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_STA_UNLOCK)
#define _DL_STA_UNLOCK_CYCLE_CAPTURE_STOP                                      \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_STA_UNLOCK)

#define _DL_VAP_TLV_ENCAP_CYCLE_CAPTURE_START                                  \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_VAP_TLV_ENCAP)
#define _DL_VAP_TLV_ENCAP_CYCLE_CAPTURE_STOP                                   \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_VAP_TLV_ENCAP)

#define _DL_VAP_PAYLOAD_FRAGMENT_CYCLE_CAPTURE_START                           \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_VAP_PAYLOAD_FRAGMENT)
#define _DL_VAP_PAYLOAD_FRAGMENT_CYCLE_CAPTURE_STOP                            \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_VAP_PAYLOAD_FRAGMENT)

#define _DL_VAP_HDR_ENCAP_CYCLE_CAPTURE_START                                  \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_VAP_HDR_ENCAP)
#define _DL_VAP_HDR_ENCAP_CYCLE_CAPTURE_STOP                                   \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_VAP_HDR_ENCAP)

#define _DL_AP_TUNNEL_ENCAP_CYCLE_CAPTURE_START                                \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_AP_TUNNEL_ENCAP)
#define _DL_AP_TUNNEL_ENCAP_CYCLE_CAPTURE_STOP                                 \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_AP_TUNNEL_ENCAP)

#else // !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _DL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_START
#define _DL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_STOP

#define _DL_GRE_DECAP_CYCLE_CAPTURE_START
#define _DL_GRE_DECAP_CYCLE_CAPTURE_STOP

#define _DL_STA_LOCK_CYCLE_CAPTURE_START
#define _DL_STA_LOCK_CYCLE_CAPTURE_STOP

#define _DL_STA_ENCRYPT_DATA_GET_CYCLE_CAPTURE_START
#define _DL_STA_ENCRYPT_DATA_GET_CYCLE_CAPTURE_STOP

#define _DL_ETHER_TO_IEEE80211_CONV_CYCLE_CAPTURE_START
#define _DL_ETHER_TO_IEEE80211_CONV_CYCLE_CAPTURE_STOP

#define _DL_CCMP_HDR_GENERATE_CYCLE_CAPTURE_START
#define _DL_CCMP_HDR_GENERATE_CYCLE_CAPTURE_STOP

#define _DL_STA_UNLOCK_CYCLE_CAPTURE_START
#define _DL_STA_UNLOCK_CYCLE_CAPTURE_STOP

#define _DL_VAP_TLV_ENCAP_CYCLE_CAPTURE_START
#define _DL_VAP_TLV_ENCAP_CYCLE_CAPTURE_STOP

#define _DL_VAP_PAYLOAD_FRAGMENT_CYCLE_CAPTURE_START
#define _DL_VAP_PAYLOAD_FRAGMENT_CYCLE_CAPTURE_STOP

#define _DL_VAP_HDR_ENCAP_CYCLE_CAPTURE_START
#define _DL_VAP_HDR_ENCAP_CYCLE_CAPTURE_STOP

#define _DL_AP_TUNNEL_ENCAP_CYCLE_CAPTURE_START
#define _DL_AP_TUNNEL_ENCAP_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#if !defined RWPA_STATS_CAPTURE_PORTS_OFF &&                                   \
    !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&                                \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _DL_PMD_TX_CYCLE_CAPTURE_START                                         \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_PMD_TX)
#define _DL_PMD_TX_CYCLE_CAPTURE_STOP                                          \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_PMD_TX)

#else // !defined RWPA_STATS_CAPTURE_PORTS_OFF &&
      // !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define _DL_PMD_TX_CYCLE_CAPTURE_START
#define _DL_PMD_TX_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_PORTS_OFF &&
       // !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

////////////////////////////////////////////////////////////////////////////////

/*
 * PUBLIC MACROS
 */

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF && defined RWPA_STATS_CAPTURE

#define DL_DATA_DROP_STAT_INC(stat, amt)                                       \
     stats_capture_downlink_drops_inc(stat, (uint64_t)amt);

#define DL_DATA_PMD_READ_STAT_INC(stat, amt)                                   \
     stats_capture_downlink_pmd_reads_inc(stat, (uint64_t)amt);

#else

#define DL_DATA_DROP_STAT_INC(stat, amt)
#define DL_DATA_PMD_READ_STAT_INC(stat, amt)

#endif

////////////////////////////////////////////////////////////////////////////////

#define LOG_AND_DROP(p_mbuf, level, logtype, err_msg, stat)                    \
({                                                                             \
     DL_DATA_DROP_STAT_INC(stat, 1);                                           \
     RWPA_LOG(level, logtype, err_msg);                                        \
     DROP(p_mbuf);                                                             \
})

////////////////////////////////////////////////////////////////////////////////

#if !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define CCMP_BURST_DEQUEUE_STATS(nb_to_deq, nb_deq_success)                    \
({                                                                             \
     struct stats_crypto *stats =                                              \
         stats_capture_crypto_get_mem_info(STATS_CRYPTO_TYPE_DL);              \
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

#if !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&                                \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define DL_STA_LOCK_AND_INFO_GET_CYCLE_CAPTURE_START                           \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_STA_LOCK_AND_INFO_GET)
#define DL_STA_LOCK_AND_INFO_GET_CYCLE_CAPTURE_STOP                            \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_STA_LOCK_AND_INFO_GET)

#else // !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#define DL_STA_LOCK_AND_INFO_GET_CYCLE_CAPTURE_START
#define DL_STA_LOCK_AND_INFO_GET_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_UPLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_HIGH

#if !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&                                \
    defined RWPA_CYCLE_CAPTURE &&                                              \
    RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_LOW

#define DL_PROCESS_FULL_CYCLE_CAPTURE_START                                    \
     CYCLE_CAPTURE_START(CYCLE_CAPTURE_DL_PROCESS_FULL)
#define DL_PROCESS_FULL_CYCLE_CAPTURE_STOP                                     \
     CYCLE_CAPTURE_STOP(CYCLE_CAPTURE_DL_PROCESS_FULL)

#else // !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&
      // defined RWPA_CYCLE_CAPTURE &&
      // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_LOW

#define DL_PROCESS_FULL_CYCLE_CAPTURE_START
#define DL_PROCESS_FULL_CYCLE_CAPTURE_STOP

#endif // !defined RWPA_STATS_CAPTURE_DOWNLINK_OFF &&
       // defined RWPA_CYCLE_CAPTURE &&
       // RWPA_CYCLE_CAPTURE == CYCLE_CAPTURE_LEVEL_LOW

////////////////////////////////////////////////////////////////////////////////

#ifndef RWPA_CYCLE_CAPTURE

#define RTE_ETH_RX_BURST(p, q, r, n)        rte_eth_rx_burst(p, q, r, n)
#define INITIAL_PACKET_CLASSIFY(m)          initial_packet_classify(m)
#define GRE_DECAP(m)                        gre_decap(m, NULL)

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
#define STA_ENCRYPT_DATA_GET(s, a, c, v)    sta_encrypt_data_get(s, a, c, v)
#define ETHER_TO_IEEE80211_CONVERT(m, meta) ether_to_ieee80211_convert(m, meta)
#define CCMP_HDR_GENERATE(p, k, h) ccmp_hdr_generate(p, k, h)

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
#define VAP_TLV_ENCAP(m)                    vap_tlv_encap(m)
#define VAP_PAYLOAD_FRAGMENT(m, fo, nfo, hm, dm)                               \
                                            vap_payload_fragment(m, fo, nfo, hm ,dm)
#define VAP_HDR_ENCAP(m, f, lf, sn, sm, dm) vap_hdr_encap(m, f, lf, sn, sm, dm)

#ifndef RWPA_AP_TUNNELLING_GRE
#define AP_TUNNEL_ENCAP(m, sp, si, sm, dp, di, dm)                             \
                                            udp_encap(m, sp, si, sm, dp, di, dm)
#else
#define AP_TUNNEL_ENCAP(m, sp, si, sm, dp, di, dm)                             \
                                            gre_encap(m, si, sm, di, dm, 0, 0)
#endif

#define RTE_ETH_TX_BUFFER(p, q, t, m)       rte_eth_tx_buffer(p, q, t, m)

#else // RWPA_CYCLE_CAPTURE

#define RTE_ETH_RX_BURST(p, q, r, n)                                           \
({                                                                             \
     _DL_PMD_RX_CYCLE_CAPTURE_START;                                           \
     unsigned len = rte_eth_rx_burst(p, q, r, n);                              \
     _DL_PMD_RX_CYCLE_CAPTURE_STOP;                                            \
     if (len) {                                                                \
         _DL_PMD_RX_CYCLE_CAPTURE_COPY_LAST;                                   \
     }                                                                         \
     len;                                                                      \
})

#define INITIAL_PACKET_CLASSIFY(m)                                             \
({                                                                             \
     _DL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_START;                             \
     enum outer_pkt_type type = initial_packet_classify(m);                    \
     _DL_INITIAL_PKT_CLASSIFY_CYCLE_CAPTURE_STOP;                              \
     type;                                                                     \
})

#define GRE_DECAP(m)                                                           \
({                                                                             \
     _DL_GRE_DECAP_CYCLE_CAPTURE_START;                                        \
     enum rwpa_status sts = gre_decap(m, NULL);                                \
     _DL_GRE_DECAP_CYCLE_CAPTURE_STOP;                                         \
     sts;                                                                      \
})

#if !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

#define STORE_STA_BULK_LOOKUP(a, n, f)                                         \
({                                                                             \
     _DL_STA_LOOKUP_CYCLE_CAPTURE_START;                                       \
     store_sta_bulk_lookup(a, n, f);                                           \
     _DL_STA_LOOKUP_CYCLE_CAPTURE_STOP;                                        \
     _STORE_STA_BULK_LOOKUP_STATS(n, f);                                       \
})

#else // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

#define STORE_STA_BULK_LOOKUP(a, n, f)                                         \
({                                                                             \
     _DL_STA_LOOKUP_CYCLE_CAPTURE_START;                                       \
     store_sta_bulk_lookup(a, n, f);                                           \
     _DL_STA_LOOKUP_CYCLE_CAPTURE_START;                                       \
})

#endif // !defined RWPA_STATS_CAPTURE_STA_LOOKUP_OFF && defined RWPA_STATS_CAPTURE

#define STA_READ_LOCK(s)                                                       \
({                                                                             \
     _DL_STA_LOCK_CYCLE_CAPTURE_START;                                         \
     sta_read_lock(s);                                                         \
     _DL_STA_LOCK_CYCLE_CAPTURE_STOP;                                          \
})

#define STA_ENCRYPT_DATA_GET(s, a, c, v)                                       \
({                                                                             \
     _DL_STA_ENCRYPT_DATA_GET_CYCLE_CAPTURE_START;                             \
     sta_encrypt_data_get(s, a, c, v);                                         \
     _DL_STA_ENCRYPT_DATA_GET_CYCLE_CAPTURE_STOP;                              \
})

#define ETHER_TO_IEEE80211_CONVERT(m, meta)                                    \
({                                                                             \
     _DL_ETHER_TO_IEEE80211_CONV_CYCLE_CAPTURE_START;                          \
     enum rwpa_status sts = ether_to_ieee80211_convert(m, meta);               \
     _DL_ETHER_TO_IEEE80211_CONV_CYCLE_CAPTURE_STOP;                           \
     sts;                                                                      \
})

#define CCMP_HDR_GENERATE(p, k, h)                                             \
({                                                                             \
     _DL_CCMP_HDR_GENERATE_CYCLE_CAPTURE_START;                                \
     enum rwpa_status sts = ccmp_hdr_generate(p, k, h);                        \
     _DL_CCMP_HDR_GENERATE_CYCLE_CAPTURE_STOP;                                 \
     sts;                                                                      \
})

#if !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define CCMP_BURST_ENQUEUE(b, l, m, o, q, s)                                   \
({                                                                             \
     _DL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_START;                                   \
     uint16_t enq = ccmp_burst_enqueue(b, l, m, o, q, s);                      \
     _DL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_STOP;                                    \
     _CCMP_BURST_ENQUEUE_STATS(l, enq);                                        \
     enq;                                                                      \
})

#define CCMP_BURST_DEQUEUE(b, l, q, n, s)                                      \
({                                                                             \
     _DL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_START;                                   \
     uint16_t deq = ccmp_burst_dequeue(b, l, q, n, s);                         \
     _DL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_STOP;                                    \
     _CCMP_BURST_DEQUEUE_CALL_STATS;                                           \
     deq;                                                                      \
})

#else // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define CCMP_BURST_ENQUEUE(b, l, m, o, q, s)                                   \
({                                                                             \
     _DL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_START;                                   \
     uint16_t enq = ccmp_burst_enqueue(b, l, m, o, q, s);                      \
     _DL_CRYPTO_ENQUEUE_CYCLE_CAPTURE_STOP;                                    \
     enq;                                                                      \
})

#define CCMP_BURST_DEQUEUE(b, l, q, n, s)                                      \
({                                                                             \
     _DL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_START;                                   \
     uint16_t deq = ccmp_burst_dequeue(b, l, q, n, s);                         \
     _DL_CRYPTO_DEQUEUE_CYCLE_CAPTURE_STOP;                                    \
     deq;                                                                      \
})

#endif // !defined RWPA_STATS_CAPTURE_CRYPTO_OFF && defined RWPA_STATS_CAPTURE

#define STA_READ_UNLOCK(s)                                                     \
({                                                                             \
     _DL_STA_UNLOCK_CYCLE_CAPTURE_START;                                       \
     sta_read_unlock(s);                                                       \
     _DL_STA_UNLOCK_CYCLE_CAPTURE_STOP;                                        \
})

#define VAP_TLV_ENCAP(m)                                                       \
({                                                                             \
     _DL_VAP_TLV_ENCAP_CYCLE_CAPTURE_START;                                    \
     enum rwpa_status sts = vap_tlv_encap(m);                                  \
     _DL_VAP_TLV_ENCAP_CYCLE_CAPTURE_STOP;                                     \
     sts;                                                                      \
})

#define VAP_PAYLOAD_FRAGMENT(m, fo, nfo, hm, dm)                               \
({                                                                             \
     _DL_VAP_PAYLOAD_FRAGMENT_CYCLE_CAPTURE_START;                             \
     enum rwpa_status sts = vap_payload_fragment(m, fo, nfo, hm, dm);          \
     _DL_VAP_PAYLOAD_FRAGMENT_CYCLE_CAPTURE_STOP;                              \
     sts;                                                                      \
})

#define VAP_HDR_ENCAP(m, f, lf, sn, sm, dm)                                    \
({                                                                             \
     _DL_VAP_HDR_ENCAP_CYCLE_CAPTURE_START;                                    \
     enum rwpa_status sts = vap_hdr_encap(m, f, lf, sn, sm, dm);               \
     _DL_VAP_HDR_ENCAP_CYCLE_CAPTURE_STOP;                                     \
     sts;                                                                      \
})

#ifndef RWPA_AP_TUNNELLING_GRE
#define AP_TUNNEL_ENCAP(m, sp, si, sm, dp, di, dm)                             \
({                                                                             \
     _DL_AP_TUNNEL_ENCAP_CYCLE_CAPTURE_START;                                  \
     enum rwpa_status sts = udp_encap(m, sp, si, sm, dp, di, dm);              \
     _DL_AP_TUNNEL_ENCAP_CYCLE_CAPTURE_STOP;                                   \
     sts;                                                                      \
})
#else
#define AP_TUNNEL_ENCAP(m, sp, si, sm, dp, di, dm)                             \
({                                                                             \
     _DL_AP_TUNNEL_ENCAP_CYCLE_CAPTURE_START;                                  \
     enum rwpa_status sts = gre_encap(m, si, sm, di, dm, 0, 0);                \
     _DL_AP_TUNNEL_ENCAP_CYCLE_CAPTURE_STOP;                                   \
     sts;                                                                      \
})
#endif

#define RTE_ETH_TX_BUFFER(p, q, t, m)                                          \
({                                                                             \
     _DL_PMD_TX_CYCLE_CAPTURE_START;                                           \
     rte_eth_tx_buffer(p, q, t, m);                                            \
     _DL_PMD_TX_CYCLE_CAPTURE_STOP;                                            \
})

#endif // RWPA_CYCLE_CAPTURE

////////////////////////////////////////////////////////////////////////////////

#endif // __INCLUDE_DOWNLINK_MACROS_H__
