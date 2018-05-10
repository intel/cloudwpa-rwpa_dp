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
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_hash.h>
#include <rte_log.h>
#include <rte_rwlock.h>
#include <rte_ip.h>

#include "app.h"
#include "parser.h"
#include "thread.h"
#include "r-wpa_global_vars.h"
#include "key.h"
#include "ccmp_sa.h"
#include "station.h"
#include "vap.h"
#include "store.h"
#include "meta.h"
#include "classifier.h"
#include "arp.h"
#include "gre.h"
#include "udp.h"
#include "vap_hdrs.h"
#include "ieee80211.h"
#include "crypto.h"
#include "ccmp.h"
#include "convert.h"
#include "vap_frag.h"
#include "cycle_capture.h"
#ifdef RWPA_STATS_CAPTURE
#include "statistics_capture.h"
#endif
#include "downlink_macros.h"
#include "downlink_thread.h"

#define DL_NUM_SRC_PORTS           1
#define DL_NUM_DST_PORTS           2
#define DL_NUM_PORTS               DL_NUM_SRC_PORTS + \
                                   DL_NUM_DST_PORTS

#define DL_SRC_PORT                0
#define DL_DST_PORT_AP             0
#define DL_DST_PORT_WAG            1

#define DL_TP_FRAG_HDR_MEMPOOL_ID  "frag_hdr_mempool_id"
#define DL_TP_FRAG_DATA_MEMPOOL_ID "frag_data_mempool_id"

extern volatile int force_quit;
struct app_params *g_app;

static struct app_thread_params *tp_downlink;
static struct app_addr_params *addr_params;

static struct src_port_params src_ports[DL_NUM_SRC_PORTS];
static struct dst_port_params dst_ports[DL_NUM_DST_PORTS];

struct ether_addr *vnfd_eth_addr_to_ap;
struct ether_addr *vnfd_eth_addr_to_wag;

static uint32_t frag_hdr_mempool_id;
static uint32_t frag_data_mempool_id;

static void *
thread_downlink_init(struct app_thread_params *p, void *arg)
{
    unsigned lcore_id, socket_id;

    g_app = (struct app_params *)arg;
    tp_downlink = p;
    addr_params = &g_app->addr_params;

    lcore_id = rte_lcore_id();
    socket_id = rte_socket_id();

    unsigned n_ports_in = tp_downlink->n_ports_in;
    unsigned n_ports_out = tp_downlink->n_ports_out;

    /* check number of ports */
    if (n_ports_in > DL_NUM_SRC_PORTS || n_ports_out > DL_NUM_DST_PORTS)
        rte_exit(EXIT_FAILURE,
                 "More than %d src or %d dst port assigned to downlink\n",
                 DL_NUM_SRC_PORTS, DL_NUM_DST_PORTS);
    else if ((n_ports_in + n_ports_out) != DL_NUM_PORTS)
        rte_exit(EXIT_FAILURE,
                 "Must be exactly %d ports assigned to downlink\n",
                 DL_NUM_PORTS);

    /* get src port info */
    src_ports[DL_SRC_PORT].port_id =
        thread_port_in_get_id(&tp_downlink->port_in[DL_SRC_PORT]);

    /* get AP dest port info */
    dst_ports[DL_DST_PORT_AP].port_id =
        thread_port_out_get_id(&tp_downlink->port_out[DL_DST_PORT_AP]);
    dst_ports[DL_DST_PORT_AP].queue_id =
        thread_port_out_get_queue_id(&tp_downlink->port_out[DL_DST_PORT_AP]);
    dst_ports[DL_DST_PORT_AP].tx_buffer =
        thread_port_out_get_tx_buffer(&tp_downlink->port_out[DL_DST_PORT_AP]);

    /* get WAG dest port info */
    dst_ports[DL_DST_PORT_WAG].port_id =
        thread_port_out_get_id(&tp_downlink->port_out[DL_DST_PORT_WAG]);
    dst_ports[DL_DST_PORT_WAG].queue_id =
        thread_port_out_get_queue_id(&tp_downlink->port_out[DL_DST_PORT_WAG]);
    dst_ports[DL_DST_PORT_WAG].tx_buffer =
        thread_port_out_get_tx_buffer(&tp_downlink->port_out[DL_DST_PORT_WAG]);

    /* save vnfd ethernet addresses from link parameters */
    vnfd_eth_addr_to_ap = &g_app->link_params[dst_ports[DL_DST_PORT_AP].port_id].mac_addr;
    vnfd_eth_addr_to_wag = &g_app->link_params[dst_ports[DL_DST_PORT_WAG].port_id].mac_addr;

    /* find the fragmentation mempool ids */
    int frag_hdr_mempool_id_rd_sts = -1;
    int frag_data_mempool_id_rd_sts = -1;
    for (uint32_t i = 0; i < tp_downlink->n_args; i++) {
        if (strcmp(tp_downlink->args_name[i], DL_TP_FRAG_HDR_MEMPOOL_ID) == 0) {
            frag_hdr_mempool_id_rd_sts =
                                 parser_read_uint32(&frag_hdr_mempool_id,
                                                    tp_downlink->args_value[i]);
        } else if (strcmp(tp_downlink->args_name[i], DL_TP_FRAG_DATA_MEMPOOL_ID) == 0) {
            frag_data_mempool_id_rd_sts =
                                 parser_read_uint32(&frag_data_mempool_id,
                                                    tp_downlink->args_value[i]);
        }
    }
    if (frag_hdr_mempool_id_rd_sts != 0 ||
        frag_data_mempool_id_rd_sts != 0)
        rte_exit(EXIT_FAILURE,
                 "Could not find valid %s thread param for %s\n",
                 frag_hdr_mempool_id_rd_sts != 0 ?
                     DL_TP_FRAG_HDR_MEMPOOL_ID :
                     DL_TP_FRAG_DATA_MEMPOOL_ID,
                 tp_downlink->name);

    RTE_LOG(INFO, RWPA_DL,
            "%s (%s): Initializing on lcore %u (socket %u)\n",
            tp_downlink->name, tp_downlink->type, lcore_id, socket_id);

    return NULL;
}

static void
data_packets_process(struct pkt_buffer *pkts_in)
{
    unsigned i, j;
    struct rte_mbuf *m;
    struct rwpa_meta meta[MAX_PKT_BURST] = {0};
    struct ether_addr *sta_addrs[MAX_PKT_BURST];
    uint32_t nb_sta_addrs = 0;
    int32_t found[MAX_PKT_BURST];
    struct pkt_buffer pkts_crypto_in __rte_cache_aligned;
    struct rwpa_meta *meta_crypto_in[MAX_PKT_BURST] = {0};
#ifndef RWPA_NO_CRYPTO
    struct pkt_buffer pkts_crypto_out __rte_cache_aligned;
    uint16_t nb_crypto_enq, nb_crypto_deq;
    uint16_t nb_crypto_deq_success, nb_crypto_deq_success_acc;
    uint8_t crypto_enq_success[MAX_PKT_BURST] = {0};
    uint8_t crypto_deq_success[MAX_PKT_BURST] = {0};

    pkts_crypto_out.len = 0;
#endif
    pkts_crypto_in.len = 0;

    /*
     * RX PROCESSING
     */
    for (i = 0; i < pkts_in->len; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts_in->buffer[i], void *));

        /*
         * if packet was GRE encapsulated, the GRE headers have
         * already been removed
         * - now left with the inner Ethernet packet
         * - get the destination station address for the store lookup
         */
        struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts_in->buffer[i], struct ether_hdr *);
        sta_addrs[nb_sta_addrs++] = &(eth_hdr->d_addr);
    }

    /*
     * STORE LOOKUP
     * - search the store for each of the stations
     */
    STORE_STA_BULK_LOOKUP(sta_addrs, nb_sta_addrs, found);

    for (i = 0, j = 0; i < pkts_in->len; i++) {
        m = pkts_in->buffer[i];

        if (likely(m != NULL && j < nb_sta_addrs)) {
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));

            if (unlikely(!is_unicast_ether_addr(sta_addrs[j]))) {
                /*
                 * BROADCAST/MULTICAST... dropping packet for now
                 * VNFD does not currently support broadcast/multicast
                 */
                LOG_AND_DROP(m, ERR, RWPA_DL,
                             "Broadcast/multicast packet, dropping for now\n",
                             STATS_DL_DROPS_TYPE_BROAD_MULTI_CAST_PACKET);
            } else if (likely(found[j] >= 0)) {
                /*
                 * UNICAST PACKET AND STATION FOUND
                 */

                /* get the station and lock it */
                meta[i].sta = store_sta_get(found[j]);
                STA_READ_LOCK(meta[i].sta);

                /* get the PTK SA, PTK's encrypt counter and vAP */
                STA_ENCRYPT_DATA_GET(meta[i].sta, &(meta[i].sa),
                                     &(meta[i].counter), &(meta[i].vap));

                /*
                 * check is there a key for this station
                 * - i.e. has it been authorized
                 */
                if (likely(meta[i].sa != NULL &&
                           meta[i].sa->tk_len > 0)) {

                    /*
                     * ETHERNET -> IEEE802.11 CONVERSION
                     * - allocates space for CCMP encap
                     */
                    if (unlikely(ETHER_TO_IEEE80211_CONVERT(
                                         m, &meta[i]) != RWPA_STS_OK)) {
                        STA_READ_UNLOCK(meta[i].sta);
                        LOG_AND_DROP(m, ERR, RWPA_DL,
                                     "Error converting packet to 802.11, dropping\n",
                                     STATS_DL_DROPS_TYPE_WIFI_CONVERT_ERROR);
                    } else {
                        /*
                         * CCMP HEADER INSERTION
                         */
                        uint8_t *ccmp_hdr =
                            rte_pktmbuf_mtod_offset(m, uint8_t *,
                                                    meta[i].wifi_hdr_sz);

                        if (unlikely(CCMP_HDR_GENERATE(
                                         meta[i].counter, 0, ccmp_hdr) != RWPA_STS_OK)) {
                            STA_READ_UNLOCK(meta[i].sta);
                            LOG_AND_DROP(m, ERR, RWPA_DL,
                                         "Error adding CCMP header to packet, dropping\n",
                                         STATS_DL_DROPS_TYPE_WIFI_CONVERT_ERROR);
                        } else {
                            /*
                             * setup the packets which have been successfully processed
                             * so far and are ready to be encrypted
                             */
                            pkts_crypto_in.buffer[pkts_crypto_in.len] = m;
                            meta_crypto_in[pkts_crypto_in.len] = &meta[i];
                            pkts_crypto_in.len++;
                        }
                    }
                } else {
                    /*
                     * NO KEY
                     * - drop the packet
                     */
                    STA_READ_UNLOCK(meta[i].sta);
                    LOG_AND_DROP(m, ERR, RWPA_DL,
                                 "No key set for station, dropping\n",
                                 STATS_DL_DROPS_TYPE_NO_STATION_KEY);
                }
            } else {
                /*
                 * STATION NOT FOUND
                 * - drop the packet
                 */
                LOG_AND_DROP(m, ERR, RWPA_DL,
                             "Station not found, dropping\n",
                             STATS_DL_DROPS_TYPE_STATION_NOT_FOUND);
            }
            j++;
        }
    }

#ifndef RWPA_NO_CRYPTO
    RWPA_CHECK_ARRAY_OFFSET(pkts_crypto_in.len, MAX_PKT_BURST);

    /*
     * CCMP ENCRYPTION
     * - enqueue packets for encryption
     */
    nb_crypto_enq = CCMP_BURST_ENQUEUE(pkts_crypto_in.buffer, pkts_crypto_in.len,
                                       meta_crypto_in, CCMP_OP_ENCRYPT,
                                       tp_downlink->crypto_qp, crypto_enq_success);

    /*
     * dequeue packets from crypto devices
     * - the same number of packets that were enqueued must be dequeued
     * This loop will continue until all crypto ops are dequeued.
     */
    nb_crypto_deq_success_acc = 0;
    do {
        nb_crypto_deq_success = 0;
        nb_crypto_deq = CCMP_BURST_DEQUEUE((pkts_crypto_out.buffer + pkts_crypto_out.len),
                                           (nb_crypto_enq - pkts_crypto_out.len),
                                           tp_downlink->crypto_qp, &nb_crypto_deq_success,
                                           (crypto_deq_success + pkts_crypto_out.len));

        pkts_crypto_out.len += nb_crypto_deq;
        nb_crypto_deq_success_acc += nb_crypto_deq_success;
    } while ((!force_quit) && (pkts_crypto_out.len < nb_crypto_enq));

    CCMP_BURST_DEQUEUE_STATS(nb_crypto_enq, nb_crypto_deq_success_acc);

    /*
     * CRYPTO TIDYUP
     */

    /* log error for any failed crypto ops */
    if (unlikely(nb_crypto_deq_success_acc < pkts_crypto_in.len)) {
        DL_DATA_DROP_STAT_INC(STATS_DL_DROPS_TYPE_ENCRYPTION_ERROR,
                              (pkts_crypto_in.len - nb_crypto_deq_success_acc));

#ifdef RWPA_EXTRA_DEBUG
        RTE_LOG(ERR, RWPA_DL,
                "CCMP encryption failed for %d out of %d "
                "packets, dropping\n",
                (pkts_crypto_in.len - nb_crypto_deq_success_acc),
                pkts_crypto_in.len);
#endif
    }
#endif

    /* unlock station and free mbuf for any failed crypto ops */
    for (i = 0, j = 0; i < pkts_crypto_in.len; i++) {
        STA_READ_UNLOCK(meta_crypto_in[i]->sta);

#ifndef RWPA_NO_CRYPTO
        if (crypto_enq_success[i] == FALSE) {
            DROP(pkts_crypto_in.buffer[i]);
        } else if (j < nb_crypto_enq &&
                   crypto_deq_success[j++] == FALSE) {
            DROP(pkts_crypto_in.buffer[i]);
        }
#endif
    }

    /*
     * POST CRYPTO PROCESSING
     */
    for (i = 0; i < pkts_crypto_in.len; i++) {
        m = pkts_crypto_in.buffer[i];

        if (likely(m != NULL)) {
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));

            /*
             * VAP TLV ENCAP
             * - add the vAP TLV
             */
            if (unlikely(VAP_TLV_ENCAP(m) != RWPA_STS_OK)) {
                LOG_AND_DROP(m, ERR, RWPA_DL,
                             "Error adding vAP TLV, dropping\n",
                             STATS_DL_DROPS_TYPE_PACKET_ENCAP_ERROR);

            } else {
                /*
                 * FRAGMENTATION NOT REQUIRED
                 */
                if (likely(rte_pktmbuf_data_len(m) <= g_app->misc_params.max_vap_frag_sz)) {
                    /*
                     * VAP HEADER ENCAP
                     * - add the inner Ethernet and vAP headers
                     */
                    if (unlikely(VAP_HDR_ENCAP(m,
                                               FALSE, FALSE, 0,
                                               vnfd_eth_addr_to_ap,
                                               meta_crypto_in[i]->p_sta_addr) != RWPA_STS_OK)) {
                        LOG_AND_DROP(m, ERR, RWPA_DL,
                                     "Error adding vAP headers, dropping\n",
                                     STATS_DL_DROPS_TYPE_PACKET_ENCAP_ERROR);

                    /*
                     * AP TUNNEL ENCAP
                     * - add the outer Ethernet, IP and UDP/GRE headers
                     * - NOTE: not locking the vap element before accessing the
                     *   tunnel addresses, as these addresses should hardly ever
                     *   change
                     *   - even if the vap element is being/has been reset and
                     *     garbage addresses are used, it's not a big deal as
                     *     that vap is no longer live and the packet won't be
                     *     delivered through it anyways
                     */
                    } else if (unlikely(meta_crypto_in[i]->vap == NULL ||
                                        AP_TUNNEL_ENCAP(m,
                                                        addr_params->vnfd_port_to_ap,
                                                        addr_params->vnfd_ip_to_ap,
                                                        vnfd_eth_addr_to_ap,
                                                        meta_crypto_in[i]->vap->tun_port,
                                                        meta_crypto_in[i]->vap->tun_ip,
                                                        &(meta_crypto_in[i]->vap->tun_mac)) != RWPA_STS_OK)) {
                        LOG_AND_DROP(m, ERR, RWPA_DL,
                                     "Error adding AP tunnel headers, dropping\n",
                                     STATS_DL_DROPS_TYPE_PACKET_ENCAP_ERROR);

                    /*
                     * WRITE TO TX BUFFER
                     */
                    } else {
                        RTE_ETH_TX_BUFFER(dst_ports[DL_DST_PORT_AP].port_id,
                                          dst_ports[DL_DST_PORT_AP].queue_id,
                                          dst_ports[DL_DST_PORT_AP].tx_buffer, m);
                    }
                /*
                 * FRAGMENTATION REQUIRED
                 */
                } else {
                    struct rte_mbuf *frags[MAX_FRAGS_PER_PKT];

                    /*
                     * FRAGMENT
                     */
                    if (unlikely(VAP_PAYLOAD_FRAGMENT(
                                     m, frags, MAX_FRAGS_PER_PKT,
                                     g_app->mempool[frag_hdr_mempool_id],
                                     g_app->mempool[frag_data_mempool_id]) != RWPA_STS_OK)) {
                        LOG_AND_DROP(m, ERR, RWPA_DL,
                                     "Error fragmenting packet, dropping\n",
                                     STATS_DL_DROPS_TYPE_FRAGMENTATION_ERROR);
                    } else {
                        /*
                         * after fragmenting, each fragment will be made up
                         * of 2 mbufs
                         * - the 1st mbuf is a direct mbuf and will be empty
                         *   - the remaining vAP and GRE headers will be
                         *     put in this mbuf
                         * - the 2nd mbuf is an indirect mbuf pointing to
                         *   the vAP payload in the original mbuf
                         */

                        /* free the original mbuf */
                        rte_pktmbuf_free(m);

                        /*
                         * get the next fragment sequence number
                         * for this station's vAP
                         */
                        seq_num_val_t frag_seq_num =
                                          vap_next_frag_seq_num_get(meta_crypto_in[i]->vap);

                        /* loop through each fragment */
                        for (j = 0; j < MAX_FRAGS_PER_PKT && frags[j] != NULL; j++) {
                            /*
                             * VAP HEADER ENCAP
                             * - add the inner Ethernet and vAP headers
                             */
                            uint8_t last = ((j + 1 == MAX_FRAGS_PER_PKT ||
                                             frags[j + 1] == NULL) ? TRUE : FALSE);
                            if (unlikely(VAP_HDR_ENCAP(frags[j],
                                                       TRUE, last, frag_seq_num,
                                                       vnfd_eth_addr_to_ap,
                                                       meta_crypto_in[i]->p_sta_addr) != RWPA_STS_OK)) {
                                LOG_AND_DROP(frags[j], ERR, RWPA_DL,
                                             "Error adding vAP headers, dropping\n",
                                             STATS_DL_DROPS_TYPE_PACKET_ENCAP_ERROR);

                            /*
                             * AP TUNNEL ENCAP
                             * - add the outer Ethernet, IP and UDP/GRE headers
                             * - NOTE: not locking the vap element before accessing the
                             *   tunnel addresses, as these addresses should hardly ever
                             *   change
                             *   - even if the vap element is being/has been reset and
                             *     garbage addresses are used, it's not a big deal as
                             *     that vap is no longer live and the packet won't be
                             *     delivered through it anyways
                             */
                            } else if (unlikely(meta_crypto_in[i]->vap == NULL ||
                                                AP_TUNNEL_ENCAP(frags[j],
                                                                addr_params->vnfd_port_to_ap,
                                                                addr_params->vnfd_ip_to_ap,
                                                                vnfd_eth_addr_to_ap,
                                                                meta_crypto_in[i]->vap->tun_port,
                                                                meta_crypto_in[i]->vap->tun_ip,
                                                                &(meta_crypto_in[i]->vap->tun_mac)) != RWPA_STS_OK)) {
                                LOG_AND_DROP(frags[j], ERR, RWPA_DL,
                                             "Error adding AP tunnel headers, dropping\n",
                                             STATS_DL_DROPS_TYPE_PACKET_ENCAP_ERROR);

                            /*
                             * WRITE TO TX BUFFER
                             */
                            } else {
                                RTE_ETH_TX_BUFFER(dst_ports[DL_DST_PORT_AP].port_id,
                                                  dst_ports[DL_DST_PORT_AP].queue_id,
                                                  dst_ports[DL_DST_PORT_AP].tx_buffer,
                                                  frags[j]);
                            }
                        }
                    }
                }
            }
        }
    }
}

static void
downlink_packets_process(struct pkt_buffer *pkts_in)
{
    unsigned i;
    struct rte_mbuf *m;
    struct pkt_buffer pkts_data __rte_cache_aligned;

    pkts_data.len = 0;

    /*
     * do some initial classification on the packet
     * - ARPs and ICMPs are processed immediately, if they are
     *   not destined to a wifi station
     * - Any packets destined to a wifi station are buffered
     *   up to be processed in a batch
     */
    for (i = 0; i < pkts_in->len; i++) {
        m = pkts_in->buffer[i];
        rte_prefetch0(rte_pktmbuf_mtod(m, void *));
        enum outer_pkt_type type = INITIAL_PACKET_CLASSIFY(m);
        struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
        switch (type) {
            /*
             * ARP
             */
            case OUTER_PKT_TYPE_ARP:
                if (g_app->misc_params.no_wag == FALSE ||
                    is_same_ether_addr(&(eth_hdr->d_addr),
                                       vnfd_eth_addr_to_wag)) {
                    if (arp_reply(m, dst_ports[DL_DST_PORT_WAG].port_id, addr_params->vnfd_ip_to_wag))
	                    rte_eth_tx_buffer(dst_ports[DL_DST_PORT_WAG].port_id,
					      dst_ports[DL_DST_PORT_WAG].queue_id,
					      dst_ports[DL_DST_PORT_WAG].tx_buffer, m);
                } else {
                    pkts_data.buffer[pkts_data.len++] = m;
                }
                break;

            /*
             * ICMP
             */
            case OUTER_PKT_TYPE_ICMP:
                if (g_app->misc_params.no_wag == FALSE ||
                    is_same_ether_addr(&(eth_hdr->d_addr),
                                       vnfd_eth_addr_to_wag)) {
                    rte_pktmbuf_free(m);
                } else {
                    pkts_data.buffer[pkts_data.len++] = m;
                }
                break;

            /*
             * GRE
             */
            case OUTER_PKT_TYPE_GRE:
                if (likely(g_app->misc_params.no_wag == FALSE)) {
                    /*
                     * GRE DECAP
                     */
                    if (likely(GRE_DECAP(m) == RWPA_STS_OK)) {
                        pkts_data.buffer[pkts_data.len++] = m;
                    } else {
                        LOG_AND_DROP(m, ERR, RWPA_DL,
                                     "Error removing GRE headers, dropping\n",
                                     STATS_DL_DROPS_TYPE_PACKET_DECAP_ERROR);
                    }
                } else {
                    LOG_AND_DROP(m, ERR, RWPA_DL,
                                 "Received unexpected GRE encapsulated packet "
                                 "in no_wag mode, dropping\n",
                                 STATS_DL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE);
                }
                break;

            /*
             * UDP or Other IP
             */
            case OUTER_PKT_TYPE_UDP:
            case OUTER_PKT_TYPE_OTHER_IP:
                if (g_app->misc_params.no_wag == FALSE) {
                    LOG_AND_DROP(m, ERR, RWPA_DL,
                                 "Not handling non-GRE encapsulated downlink "
                                 "IP traffic, dropping\n",
                                 STATS_DL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE);
                } else {
                    pkts_data.buffer[pkts_data.len++] = m;
                }
                break;

            /*
             * Other
             */
            default:
                LOG_AND_DROP(m, ERR, RWPA_DL,
                             "Could not classify outer packet, dropping\n",
                             STATS_DL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE);
                break;
        }
    }

    /*
     * process the data packets
     */
    data_packets_process(&pkts_data);
}

static void
downlink_main_loop(void)
{
    struct pkt_buffer pkts_in __rte_cache_aligned;
    uint64_t prev_tsc, diff_tsc, cur_tsc;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
                               BURST_TX_DRAIN_US;

    prev_tsc = 0;

    while (!force_quit) {
        cur_tsc = rte_rdtsc();

        /*
         * tx burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            for (int i = 0; i < DL_NUM_DST_PORTS; i++)
                rte_eth_tx_buffer_flush(dst_ports[i].port_id,
                                        dst_ports[i].queue_id,
                                        dst_ports[i].tx_buffer);
            prev_tsc = cur_tsc;
        }

        /*
         * read packet from RX queues
         */
        pkts_in.len = RTE_ETH_RX_BURST(src_ports[DL_SRC_PORT].port_id, 0,
                                       pkts_in.buffer, MAX_PKT_BURST);

        if (likely(pkts_in.len)) {
            DL_DATA_PMD_READ_STAT_INC(STATS_PMD_READS_TYPE_NON_EMPTY, 1);
            DL_PROCESS_FULL_CYCLE_CAPTURE_START;
            downlink_packets_process(&pkts_in);
            DL_PROCESS_FULL_CYCLE_CAPTURE_STOP;
        } else {
            DL_DATA_PMD_READ_STAT_INC(STATS_PMD_READS_TYPE_EMPTY, 1);
        }
    }
}

static int
thread_downlink_run(__rte_unused void *arg)
{
    unsigned lcore_id, socket_id;

    lcore_id = rte_lcore_id();
    socket_id = rte_socket_id();

    RTE_LOG(INFO, RWPA_DL,
            "%s (%s): Entering main loop on lcore %u (socket %u)\n",
            tp_downlink->name, tp_downlink->type, lcore_id, socket_id);

    downlink_main_loop();

    return 0;
}

static int
thread_downlink_free(__rte_unused void *arg)
{
    unsigned lcore_id, socket_id;

    lcore_id = rte_lcore_id();
    socket_id = rte_socket_id();

    RTE_LOG(INFO, RWPA_DL,
            "%s (%s): Freeing on lcore %u (socket %u)\n",
            tp_downlink->name, tp_downlink->type, lcore_id, socket_id);

    return 0;
}

uint8_t
downlink_thread_src_port_get(void)
{
    return src_ports[DL_SRC_PORT].port_id;
}

static struct thread_ops_s thread_downlink_ops = {
    .f_init = thread_downlink_init,
    .f_free = thread_downlink_free,
    .f_run  = thread_downlink_run,
};

struct thread_type thread_downlink = {
    .name = "DOWNLINK_THREAD",
    .thread_ops = &thread_downlink_ops,
};
