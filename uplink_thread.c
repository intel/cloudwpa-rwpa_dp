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

#include <unistd.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_hash.h>
#include <rte_log.h>
#include <rte_rwlock.h>
#include <rte_ip.h>
#include <rte_string_fns.h>

#include "app.h"
#include "parser.h"
#include "thread.h"
#include "ring.h"
#include "poll_wrr.h"
#include "r-wpa_global_vars.h"
#include "key.h"
#include "ccmp_sa.h"
#include "station.h"
#include "vap.h"
#include "store.h"
#include "meta.h"
#include "wpapt_cdi.h"
#include "wpapt_cdi_helper.h"
#include "classifier.h"
#include "arp.h"
#include "gre.h"
#include "udp.h"
#include "vap_hdrs.h"
#include "ieee80211.h"
#include "ieee80211_utils.h"
#include "crypto.h"
#include "ccmp.h"
#include "convert.h"
#include "tls_socket.h"
#include "vap_frag.h"
#include "cycle_capture.h"
#ifdef RWPA_STATS_CAPTURE
#include "statistics_capture.h"
#endif
#include "uplink_macros.h"
#include "uplink_thread.h"

#define UL_NUM_SRC_PORTS        1
#define UL_NUM_DST_PORTS        2
#define UL_NUM_PORTS            UL_NUM_SRC_PORTS + \
                                UL_NUM_DST_PORTS

#define UL_SRC_PORT             0
#define UL_DST_PORT_WAG         0
#define UL_DST_PORT_AP          1

#define UL_TP_TLS_MEMPOOL_ID    "tls_mempool_id"

extern volatile int force_quit;
struct app_params *g_app;

static struct app_thread_params *tp_uplink;
static struct app_addr_params *addr_params;

struct ether_addr *vnfd_eth_addr_to_ap;
struct ether_addr *vnfd_eth_addr_to_wag;

static struct src_port_params src_ports[UL_NUM_SRC_PORTS];
static struct dst_port_params dst_ports[UL_NUM_DST_PORTS];

#ifndef RWPA_UL_NO_TLS_POLLING
static struct tls_socket *tls;

static uint32_t tls_mempool_id;

static struct poll_wrr_elem *wrr_elements[MAX_UL_WRR_ELEMS];

static void tls_dequeue(uint64_t cur_tsc);
#endif
static void pmd_dequeue(uint64_t cur_tsc);

static void *
thread_uplink_init(struct app_thread_params *p, void *arg)
{
    unsigned lcore_id, socket_id;

    g_app = (struct app_params *)arg;
    tp_uplink = p;
    addr_params = &g_app->addr_params;

    lcore_id = rte_lcore_id();
    socket_id = rte_socket_id();

    unsigned n_ports_in = tp_uplink->n_ports_in;
    unsigned n_ports_out = tp_uplink->n_ports_out;

    if (n_ports_in > UL_NUM_SRC_PORTS || n_ports_out > UL_NUM_DST_PORTS)
        rte_exit(EXIT_FAILURE,
                 "More than %d src or %d dst port assigned to uplink\n",
                 UL_NUM_SRC_PORTS, UL_NUM_DST_PORTS);
    else if ((n_ports_in + n_ports_out) != UL_NUM_PORTS)
        rte_exit(EXIT_FAILURE,
                 "Must be exactly %d ports assigned to uplink\n",
                 UL_NUM_PORTS);

    /* get src port info */
    src_ports[UL_SRC_PORT].port_id =
        thread_port_in_get_id(&tp_uplink->port_in[UL_SRC_PORT]);

    /* get WAG dest port info */
    dst_ports[UL_DST_PORT_WAG].port_id =
        thread_port_out_get_id(&tp_uplink->port_out[UL_DST_PORT_WAG]);
    dst_ports[UL_DST_PORT_WAG].queue_id =
        thread_port_out_get_queue_id(&tp_uplink->port_out[UL_DST_PORT_WAG]);
    dst_ports[UL_DST_PORT_WAG].tx_buffer =
        thread_port_out_get_tx_buffer(&tp_uplink->port_out[UL_DST_PORT_WAG]);

    /* get AP dest port info */
    dst_ports[UL_DST_PORT_AP].port_id =
        thread_port_out_get_id(&tp_uplink->port_out[UL_DST_PORT_AP]);
    dst_ports[UL_DST_PORT_AP].queue_id =
        thread_port_out_get_queue_id(&tp_uplink->port_out[UL_DST_PORT_AP]);
    dst_ports[UL_DST_PORT_AP].tx_buffer =
        thread_port_out_get_tx_buffer(&tp_uplink->port_out[UL_DST_PORT_AP]);

    /* save vnfd ethernet addresses from link parameters */
    vnfd_eth_addr_to_ap = &g_app->link_params[dst_ports[UL_DST_PORT_AP].port_id].mac_addr;
    vnfd_eth_addr_to_wag = &g_app->link_params[dst_ports[UL_DST_PORT_WAG].port_id].mac_addr;

#ifndef RWPA_UL_NO_TLS_POLLING
    /* initialise wrr elements from config file */
    struct poll_wrr_elem *wrr_elem_pmd = NULL;
    wrr_elem_pmd = malloc(sizeof(struct poll_wrr_elem));
    RWPA_CHECK_NOT_NULL(wrr_elem_pmd);
    wrr_elem_pmd->allocated_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * g_app->misc_params.uplink_pmd_us;
    wrr_elem_pmd->p_func = pmd_dequeue;
    wrr_elements[0] = wrr_elem_pmd;
    
    struct poll_wrr_elem *wrr_elem_tls = malloc(sizeof(struct poll_wrr_elem));
    RWPA_CHECK_NOT_NULL(wrr_elem_tls);
    wrr_elem_tls->allocated_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * g_app->misc_params.uplink_tls_us;
    wrr_elem_tls->p_func = tls_dequeue;
    wrr_elements[1] = wrr_elem_tls;

    /* find the tls mempool id */
    int tls_mempool_id_rd_sts = -1;
    for (uint32_t i = 0; i < tp_uplink->n_args; i++) {
        if (strcmp(tp_uplink->args_name[i], UL_TP_TLS_MEMPOOL_ID) == 0) {
            tls_mempool_id_rd_sts = parser_read_uint32(&tls_mempool_id,
                                                       tp_uplink->args_value[i]);
        }
    }
    if (tls_mempool_id_rd_sts != 0)
        rte_exit(EXIT_FAILURE,
                 "Could not find valid %s thread param for %s\n",
                 UL_TP_TLS_MEMPOOL_ID,
                 tp_uplink->name);

    /* initialise tls socket */
    tls = malloc(sizeof(struct tls_socket));
    RWPA_CHECK_NOT_NULL(tls);
    tls_socket_init(tls, tls_handlers, g_app->mempool[tls_mempool_id],
                    addr_params->vnfc_tls_ss_ip, addr_params->vnfc_tls_ss_port,
                    &g_app->misc_params);
#endif
  
    RTE_LOG(INFO, RWPA_UL,
            "%s (%s): Initializing on lcore %u (socket %u)\n",
            tp_uplink->name, tp_uplink->type, lcore_id, socket_id);

    return NULL;
}

#ifndef RWPA_UL_NO_TLS_POLLING
static void 
eapols_process(struct pkt_buffer *eapols_in)
{
    unsigned i, j, k;
    int wep_save;
    struct rte_mbuf *m;
    struct rwpa_meta meta[MAX_PKT_BURST] = {0};
    struct ether_addr *sta_addrs[MAX_PKT_BURST];
    uint32_t nb_sta_addrs = 0;
    int32_t found[MAX_PKT_BURST];
    struct pkt_buffer eapols_crypto_in __rte_cache_aligned;
    struct rwpa_meta *meta_crypto_in[MAX_PKT_BURST] = {0};
#ifndef RWPA_NO_CRYPTO
    struct pkt_buffer eapols_crypto_out __rte_cache_aligned;
    uint16_t nb_crypto_enq, nb_crypto_deq;
    uint16_t nb_crypto_deq_success, nb_crypto_deq_success_acc;
    uint8_t crypto_enq_success[MAX_PKT_BURST] = {0};
    uint8_t crypto_deq_success[MAX_PKT_BURST] = {0};

    eapols_crypto_out.len = 0;
#else
    UNUSED(k);
    UNUSED(meta_crypto_in);
#endif
    eapols_crypto_in.len = 0;

    for (i = 0; i < eapols_in->len; i++) {
        m = eapols_in->buffer[i];
        rte_prefetch0(rte_pktmbuf_mtod(m, void *));

        /*
         * 802.11 HEADER PARSE
         */
        ieee80211_packet_parse(eapols_in->buffer[i], &meta[i]);

        /*
         * 802.11 PACKET CLASSIFY
         * - for group handshake EAPOLs received from HostAPD, the
         *   wep flag seems to be set in the 802.11 header,
         *   even though the packet isn't encrypted. This throws the
         *   ieee80211_packet_classify() function off as it expects
         *   a CCMP header to be present if the wep bit is set
         *   - the flag is cleared in the meta info so as to keep the
         *     classify happy. The correct value of the flag is set
         *     back then later
         */
        wep_save = meta[i].wep;
        meta[i].wep = FALSE;
        enum ieee80211_pkt_type pkt_type =
                    ieee80211_packet_classify(m, &meta[i]);

        if (pkt_type == IEEE80211_PKT_TYPE_EAPOL) {
            /*
             * get the destination station address for the
             * store lookup and reset the wep flag
             * in the meta info
             */
            sta_addrs[nb_sta_addrs++] = meta[i].p_sta_addr;
            meta[i].wep = wep_save;
        } else {
            CTRL_LOG_AND_DROP(eapols_in->buffer[i], ERR, RWPA_UL,
                              "Non-EAPOL 802.11 frame received over TLS, dropping\n",
                              STATS_CTRL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE);
        }
    }

    /*
     * STORE LOOKUP
     * - search the store for each of the stations
     */
    store_sta_bulk_lookup(sta_addrs, nb_sta_addrs, found);

    for (i = 0, j = 0; i < eapols_in->len; i++) {
        m = eapols_in->buffer[i];

        if (likely(m != NULL && j < nb_sta_addrs)) {
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));

            if (found[j] >= 0) {
                /*
                 * STATION FOUND
                 */

                /* get the station and lock it */
                meta[i].sta = store_sta_get(found[j]);
                sta_read_lock(meta[i].sta);

                /* get the PTK SA, PTK's encrypt counter and vAP */
                sta_encrypt_data_get(meta[i].sta, &(meta[i].sa),
                                     &(meta[i].counter), &(meta[i].vap));

                /*
                 * check is there a key for this station
                 * - i.e. has it been authorized
                 */
                if (meta[i].sa != NULL &&
                    meta[i].sa->tk_len > 0) {
                     /*
                      * CCMP ENCAP
                      * - add the CCMP header and space for the MIC
                      */
                     if (unlikely(ccmp_encap(m, &meta[i]) != RWPA_STS_OK)) {
                         sta_read_unlock(meta[i].sta);
                         CTRL_LOG_AND_DROP(eapols_in->buffer[i], ERR, RWPA_UL,
                                           "Error adding CCMP header to EAPOL packet, dropping\n",
                                           STATS_CTRL_DROPS_TYPE_PACKET_ENCAP_ERROR);
                     } else {
                         /* setup the array of packets to be encrypted */
                         eapols_crypto_in.buffer[eapols_crypto_in.len] = m;
                         meta_crypto_in[eapols_crypto_in.len] = &meta[i];
                         eapols_crypto_in.len++;
                    }
                 } else {
                     sta_read_unlock(meta[i].sta);
                 }
            } else {
                /*
                 * STATION NOT FOUND
                 * - drop the packet
                 */
                CTRL_LOG_AND_DROP(eapols_in->buffer[i], ERR, RWPA_UL,
                                  "Station not found, dropping\n",
                                  STATS_CTRL_DROPS_TYPE_STATION_NOT_FOUND);
            }
            j++;
        }
    }

#ifndef RWPA_NO_CRYPTO
    /*
     * CCMP ENCRYPTION
     * - enqueue packets for encryption
     */
    nb_crypto_enq = ccmp_burst_enqueue(eapols_crypto_in.buffer, eapols_crypto_in.len,
                                       meta_crypto_in, CCMP_OP_ENCRYPT,
                                       tp_uplink->crypto_qp, crypto_enq_success);

    /*
     * dequeue packets from crypto devices
     * - the same number of packets that were enqueued must be dequeued
     * This loop will continue until all crypto ops are dequeued.
     */
    nb_crypto_deq_success_acc = 0;
    do {
        nb_crypto_deq_success = 0;
        nb_crypto_deq = ccmp_burst_dequeue((eapols_crypto_out.buffer + eapols_crypto_out.len),
                                           (nb_crypto_enq - eapols_crypto_out.len),
                                           tp_uplink->crypto_qp, &nb_crypto_deq_success,
                                           (crypto_deq_success + eapols_crypto_out.len));

        eapols_crypto_out.len += nb_crypto_deq;
        nb_crypto_deq_success_acc += nb_crypto_deq_success;
    } while ((!force_quit) && (eapols_crypto_out.len < nb_crypto_enq));

    /*
     * CRYPTO TIDYUP
     */

    /* log error for any failed crypto ops */
    if (unlikely(nb_crypto_deq_success_acc < eapols_crypto_in.len)) {
        UL_CTRL_DROP_STAT_INC(STATS_CTRL_DROPS_TYPE_ENCRYPTION_ERROR,
                              (eapols_crypto_in.len - nb_crypto_deq_success_acc));

#ifdef RWPA_EXTRA_DEBUG
        RTE_LOG(ERR, RWPA_UL,
                "CCMP encryption failed for %d out of %d "
                "EAPOL packets, dropping\n",
                (eapols_crypto_in.len - nb_crypto_deq_success_acc),
                eapols_crypto_in.len);
#endif
    }
#endif

    /* unlock station and free mbuf for any failed crypto ops */
    for (i = 0, j = 0, k = 0; i < eapols_in->len; i++) {
        if (eapols_in->buffer[i] != NULL &&
            meta[i].sa != NULL &&
            meta[i].sa->tk_len > 0) {

            sta_read_unlock(meta[i].sta);

#ifndef RWPA_NO_CRYPTO
            if (unlikely(j < eapols_crypto_in.len &&
                         crypto_enq_success[j++] == FALSE)) {
                DROP(eapols_in->buffer[i]);
            } else if (unlikely(k < nb_crypto_enq &&
                                crypto_deq_success[k++] == FALSE)) {
                DROP(eapols_in->buffer[i]);
            }
#endif
        }
    }

    /*
     * POST CRYPTO PROCESSING
     */
    for (i = 0; i < eapols_in->len; i++) {
        m = eapols_in->buffer[i];

        if (likely(m != NULL)) {
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));

            /*
             * VAP TLV ENCAP
             * - add the vAP TLV
             */
            if (unlikely(vap_tlv_encap(m) != RWPA_STS_OK)) {
                CTRL_LOG_AND_DROP(m, ERR, RWPA_UL,
                                  "Error adding vAP TLV, dropping\n",
                                  STATS_CTRL_DROPS_TYPE_PACKET_ENCAP_ERROR);

            /*
             * VAP HEADER ENCAP
             * - add the inner Ethernet and vAP headers
             */
            } else if (unlikely(vap_hdr_encap(m,
                                              FALSE, FALSE, 0,
                                              vnfd_eth_addr_to_ap,
                                              meta[i].p_sta_addr) != RWPA_STS_OK)) {
                CTRL_LOG_AND_DROP(m, ERR, RWPA_UL,
                                  "Error adding vAP headers, dropping\n",
                                  STATS_CTRL_DROPS_TYPE_PACKET_ENCAP_ERROR);
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
#ifndef RWPA_AP_TUNNELLING_GRE
            } else if (unlikely(meta[i].vap == NULL ||
                                meta[i].vap->tun_port == addr_params->vap_tun_def_port ||
                                udp_encap(m, addr_params->vnfd_port_to_ap,
                                          addr_params->vnfd_ip_to_ap,
                                          vnfd_eth_addr_to_ap,
                                          meta[i].vap->tun_port,
                                          meta[i].vap->tun_ip,
                                          &(meta[i].vap->tun_mac)) != RWPA_STS_OK)) {
                if (meta[i].vap != NULL &&
                    meta[i].vap->tun_port == addr_params->vap_tun_def_port) {
                    CTRL_LOG_AND_DROP(m, DEBUG, RWPA_UL,
                                      "No tunnel port set for AP, dropping\n",
                                      STATS_CTRL_DROPS_TYPE_NO_AP_TUNNEL_PORT);
                } else {
                    CTRL_LOG_AND_DROP(m, ERR, RWPA_UL,
                                      "Error adding AP tunnel headers, dropping\n",
                                      STATS_CTRL_DROPS_TYPE_PACKET_ENCAP_ERROR);
                }
#else
            } else if (unlikely(meta[i].vap == NULL ||
                                gre_encap(m, addr_params->vnfd_ip_to_ap,
                                          vnfd_eth_addr_to_ap,
                                          meta[i].vap->tun_ip,
                                          &(meta[i].vap->tun_mac), 0, 0) != RWPA_STS_OK)) {
                CTRL_LOG_AND_DROP(m, ERR, RWPA_UL,
                                  "Error adding AP tunnel headers, dropping\n",
                                  STATS_CTRL_DROPS_TYPE_PACKET_ENCAP_ERROR);
#endif

            /*
             * WRITE TO TX BUFFER
             */
            } else {
                rte_eth_tx_buffer(dst_ports[UL_DST_PORT_AP].port_id,
                                  dst_ports[UL_DST_PORT_AP].queue_id,
                                  dst_ports[UL_DST_PORT_AP].tx_buffer, m);

            }
        }
    }
}

static void
tls_dequeue(uint64_t cur_tsc)
{
    unsigned i, j;
    struct rte_mbuf *m;
    struct pkt_buffer pkts_in __rte_cache_aligned;
    struct pkt_buffer eapols __rte_cache_aligned;

    UNUSED(cur_tsc);

    pkts_in.len = poll_sock(tls, pkts_in.buffer, MAX_PKT_BURST);

    eapols.len = 0;

    for (i = 0; i < pkts_in.len; i++) {
        RWPA_CHECK_ARRAY_OFFSET(i, MAX_PKT_BURST - 1);

        m = pkts_in.buffer[i];
        rte_prefetch0(rte_pktmbuf_mtod(m, void *));

        struct wpapt_cdi_msg_header *data = rte_pktmbuf_mtod(m, struct wpapt_cdi_msg_header *);
        uint16_t type = data->message_id;

        for (j = 0; tls->ctx[j].type != EOL; j++) {
            if (tls->ctx[j].cmd == type) {
                if (wpapt_cdi_hdr_decap(m) == RWPA_STS_OK) {
                    unsigned action = tls->ctx[j].handler(m);
                    switch (action) {
                        case TLS_HANDLER_ACTION_PROCESS:
                            eapols.buffer[eapols.len++] = m;
                            break;
                        case TLS_HANDLER_ACTION_TLS_TX:
                            tls_socket_write(tls, m);
                            break;
                        case TLS_HANDLER_ACTION_ERROR:
                            CTRL_LOG_AND_DROP(m, ERR, RWPA_UL,
                                              "Error handling WPAPT message, dropping\n",
                                              STATS_CTRL_DROPS_TYPE_MSG_HANDLING_ERROR);
                            break;
                        case TLS_HANDLER_ACTION_NONE:
                        default:
                            rte_pktmbuf_free(m);
                            break;
                    }
                } else {
                    CTRL_LOG_AND_DROP(m, ERR, RWPA_UL,
                                      "Error removing WPAPT header, dropping\n",
                                      STATS_CTRL_DROPS_TYPE_PACKET_DECAP_ERROR);
                }
                break;
            }
        }

        if (tls->ctx[j].type == EOL) {
#ifdef RWPA_EXTRA_DEBUG
            RTE_LOG(ERR, RWPA_UL,
                    "Unknown WPAPT message type [%d] received, dropping\n",
                    type);
#endif
            UL_CTRL_DROP_STAT_INC(STATS_UL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE, 1);
            DROP(m);
        }
    }


    /*
     * process the EAPOL packets
     */
    eapols_process(&eapols);
}
#endif

static void
ap_tunnel_packets_process(struct pkt_buffer *pkts_in, uint64_t cur_tsc)
{
    unsigned i, j, k;
    struct rte_mbuf *m;
    struct rwpa_meta meta[MAX_PKT_BURST] = {0};
    struct ether_addr *sta_addrs[MAX_PKT_BURST];
    uint32_t nb_sta_addrs = 0;
    int32_t found[MAX_PKT_BURST];
#ifndef RWPA_NO_CRYPTO
    struct pkt_buffer pkts_crypto_in __rte_cache_aligned;
    struct pkt_buffer pkts_crypto_out __rte_cache_aligned;
    struct rwpa_meta *meta_crypto_in[MAX_PKT_BURST] = {0};
    uint16_t nb_crypto_enq, nb_crypto_deq;
    uint16_t  nb_crypto_deq_success, nb_crypto_deq_success_acc;
    uint8_t crypto_enq_success[MAX_PKT_BURST] = {0};
    uint8_t crypto_deq_success[MAX_PKT_BURST] = {0};

    pkts_crypto_in.len = 0;
    pkts_crypto_out.len = 0;
#else
    UNUSED(k);
#endif

    /*
     * RX HEADERS DECAPSULATION
     */
    for (i = 0; i < pkts_in->len; i++) {
        m = pkts_in->buffer[i];
        rte_prefetch0(rte_pktmbuf_mtod(m, void *));

        /*
         * AP TUNNEL DECAP
         * - remove the AP tunnelling headers
         *   i.e. outer Ethernet, IP and UDP/GRE headers
         */
        if (unlikely(AP_TUNNEL_DECAP(m, &meta[i]) != RWPA_STS_OK)) {
            DATA_LOG_AND_DROP(pkts_in->buffer[i], ERR, RWPA_UL,
                              "Error removing AP tunnelling headers, dropping\n",
                              STATS_UL_DROPS_TYPE_PACKET_DECAP_ERROR);

        /*
         * VAP HEADERS PARSE
         * - parse the inner Ethernet and vAP headers
         */
        } else if (unlikely(VAP_HDR_PARSE(m, &meta[i]) != RWPA_STS_OK)) {
            DATA_LOG_AND_DROP(pkts_in->buffer[i], ERR, RWPA_UL,
                              "Error parsing vAP headers, dropping\n",
                              STATS_UL_DROPS_TYPE_PACKET_DECAP_ERROR);

        } else {
            /* check is the packet fragmented */
            if (unlikely(meta[i].fragment)) {
                /*
                 * REASSEMBLE
                 *
                 * the packet is fragmented
                 * - need to reassemble the fragments of the packet
                 *   before continuing
                 * - there should only be at most 2 fragments in
                 *   a fragmented packet
                 * - fragments of the same packet are identified by
                 *   the Source MAC Address and vAP Sequence Number
                 */
                UL_VAP_PAYLOAD_REASSEMBLE_CYCLE_CAPTURE_START;
                if (unlikely(vap_payload_reassemble(
                                 m, &m, cur_tsc, &meta[i]) != RWPA_STS_OK)) {
                    DATA_LOG_AND_DROP(m, ERR, RWPA_UL,
                                      "Error reassembling packet, dropping\n",
                                      STATS_UL_DROPS_TYPE_REASSEMBLY_ERROR);

                /* has the packet been fully reassembled? */
                } else if (m != NULL) {
                    /*
                     * LINEARIZE CHAINED FRAGMENTS
                     * - this is required for the crypto operation
                     *   - if the MIC is split across 2 mbufs, then
                     *     decryption is going to fail
                     */
                    if (unlikely(rte_pktmbuf_linearize(m) != 0)) {
                        DATA_LOG_AND_DROP(m, ERR, RWPA_UL,
                                          "Error linearizing chained fragments, dropping\n",
                                          STATS_UL_DROPS_TYPE_REASSEMBLY_ERROR);
                    }
                }

                pkts_in->buffer[i] = m;
                UL_VAP_PAYLOAD_REASSEMBLE_CYCLE_CAPTURE_STOP;
            }

            /* have we still got an mbuf? */
            if (likely(m != NULL)) {

                /*
                 * VAP HEADERS DECAP
                 * - remove the inner Ethernet and vAP headers
                 */
                if (unlikely(VAP_HDR_DECAP(m) != RWPA_STS_OK)) {
                    DATA_LOG_AND_DROP(pkts_in->buffer[i], ERR, RWPA_UL,
                                      "Error removing vAP headers, dropping\n",
                                      STATS_UL_DROPS_TYPE_PACKET_DECAP_ERROR);

                /*
                 * VAP TLV DECAP
                 * - remove the vAP TLV
                 */
                } else if (unlikely(VAP_TLV_DECAP(m) != RWPA_STS_OK)) {
                    DATA_LOG_AND_DROP(pkts_in->buffer[i], ERR, RWPA_UL,
                                      "Error removing vAP TLV, dropping\n",
                                      STATS_UL_DROPS_TYPE_PACKET_DECAP_ERROR);

                } else {
                    /*
                     * 802.11 HEADER PARSE
                     */
                    IEEE80211_PACKET_PARSE(m, &meta[i]);

                    /* get the source station address for the store lookup */
                    sta_addrs[nb_sta_addrs++] = meta[i].p_sta_addr;
                }
            }
        }
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

            if (found[j] >= 0) {
                /*
                 * STATION FOUND
                 */
                uint8_t tid = (meta[i].has_qc ? meta[i].p_qc->le.tid : 0);

                /* get the station and lock it */
                meta[i].sta = store_sta_get(found[j]);
                STA_READ_LOCK(meta[i].sta);

                /* get the PTK SA, PTK's decrypt counter and parent vAP */
                STA_DECRYPT_DATA_GET(meta[i].sta, tid, &(meta[i].sa),
                                     &(meta[i].counter), &(meta[i].vap));

#ifndef RWPA_DYNAMIC_AP_CONF_UPDATE_OFF
                /* save the vAP's tunnel mac, ip and port */
                vap_tun_mac_set(meta[i].vap, &(meta[i].vap_tun_mac));
                vap_tun_ip_set(meta[i].vap, meta[i].vap_tun_ip);
#ifndef RWPA_AP_TUNNELLING_GRE
                vap_tun_port_set(meta[i].vap, meta[i].vap_tun_port);
#endif
#endif

                /* check is the packet encrypted */
                if (likely(meta[i].wep)) {
                    /*
                     * ENCRYPTED
                     * - check is there a key for this station
                     *   i.e. has it been authorized
                     */
                    if (likely(meta[i].sa != NULL &&
                               meta[i].sa->tk_len > 0)) {
                        /*
                         * REPLAY DETECTION
                         */
                        struct ccmp_hdr *ccmp_hdr =
                            rte_pktmbuf_mtod_offset(m,
                                                    struct ccmp_hdr *,
                                                    meta[i].wifi_hdr_sz);

                        if (unlikely(CCMP_REPLAY_DETECT(
                                         ccmp_hdr, &(meta[i].counter)) == RWPA_STS_ERR)) {
                            STA_READ_UNLOCK(meta[i].sta);
                            DATA_LOG_AND_DROP(pkts_in->buffer[i], ERR, RWPA_UL,
                                              "Replay detected, dropping\n",
                                              STATS_UL_DROPS_TYPE_REPLAY_DETECTED);
                        } else {
                            /*
                             * save the CCMP header PN to the store for next
                             * replay check
                             * NOTE: this function writes to the ptk_decrypt_ctr of
                             * the station, but the read lock has only been taken
                             * - this is ok as this is the only 'read' thread which
                             *   will be touching this counter
                             */
                            STA_PTK_DECRYPT_COUNTER_SET(meta[i].sta, tid, meta[i].counter);

#ifndef RWPA_NO_CRYPTO
                            /*
                             * setup the packets which have been successfully processed
                             * so far and are ready to be decrypted
                             */
                            pkts_crypto_in.buffer[pkts_crypto_in.len] = m;
                            meta_crypto_in[pkts_crypto_in.len] = &meta[i];
                            pkts_crypto_in.len++;
#endif
                        }
                    } else {
                        /*
                         * NO KEY
                         * - drop the packet
                         */
                        STA_READ_UNLOCK(meta[i].sta);
                        DATA_LOG_AND_DROP(pkts_in->buffer[i], ERR, RWPA_UL,
                                          "No key set for station, dropping\n",
                                          STATS_UL_DROPS_TYPE_NO_STATION_KEY);
                    }
                } else {
                    /*
                     * NOT ENCRYPTED
                     * - just unlock the station
                     */
                    STA_READ_UNLOCK(meta[i].sta);
                }
            } else {
                /*
                 * STATION NOT FOUND
                 * - drop the packet
                 */
                DATA_LOG_AND_DROP(pkts_in->buffer[i], ERR, RWPA_UL,
                                  "Station not found, dropping\n",
                                  STATS_UL_DROPS_TYPE_STATION_NOT_FOUND);
            }
            j++;
        }
    }

#ifndef RWPA_NO_CRYPTO
    /*
     * CCMP DECRYPTION
     * - enqueue packets for decryption
     */
    nb_crypto_enq = CCMP_BURST_ENQUEUE(pkts_crypto_in.buffer, pkts_crypto_in.len,
                                       meta_crypto_in, CCMP_OP_DECRYPT,
                                       tp_uplink->crypto_qp, crypto_enq_success);

    /*
     * dequeue packets from crypto devices
     * - the same number of packets that were enqueued must be dequeued
     */
    nb_crypto_deq_success_acc = 0;
    do {
        nb_crypto_deq_success = 0;
        nb_crypto_deq = CCMP_BURST_DEQUEUE((pkts_crypto_out.buffer + pkts_crypto_out.len),
                                           (nb_crypto_enq - pkts_crypto_out.len),
                                           tp_uplink->crypto_qp, &nb_crypto_deq_success,
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
        UL_DATA_DROP_STAT_INC(STATS_UL_DROPS_TYPE_DECRYPTION_ERROR,
                              (pkts_crypto_in.len - nb_crypto_deq_success_acc));

#ifdef RWPA_EXTRA_DEBUG
        RTE_LOG(ERR, RWPA_UL,
            "CCMP decryption failed for %d out of %d "
            "packets, dropping\n",
            (pkts_crypto_in.len - nb_crypto_deq_success_acc),
            pkts_crypto_in.len);
#endif
    }
#endif

    /* unlock station and free mbuf for any failed crypto ops */
    for (i = 0, j = 0, k = 0; i < pkts_in->len; i++) {
        if (likely(pkts_in->buffer[i] != NULL &&
                   meta[i].wep)) {

            STA_READ_UNLOCK(meta[i].sta);

#ifndef RWPA_NO_CRYPTO
            if (unlikely(j < pkts_crypto_in.len &&
                         crypto_enq_success[j++] == FALSE)) {
                DROP(pkts_in->buffer[i]);
            } else if (unlikely(k < nb_crypto_enq &&
                                crypto_deq_success[k++] == FALSE)) {
                DROP(pkts_in->buffer[i]);
            }
#endif
        }
    }

    /*
     * POST CRYPTO PROCESSING
     */
    for (i = 0, j = 0; i < pkts_in->len; i++) {
        m = pkts_in->buffer[i];

        if (likely(m != NULL)) {
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));

            /*
             * 802.11 PACKET CLASSIFICATION
             */
            enum ieee80211_pkt_type pkt_type =
                IEEE80211_PACKET_CLASSIFY(m, &meta[i]);

            if (likely(pkt_type == IEEE80211_PKT_TYPE_DATA)) {
                /* DATA */

                /*
                 * IEEE802.11 -> ETHERNET CONVERSION
                 * - handles CCMP decap
                 */
                if (unlikely(IEEE80211_TO_ETHER_CONVERT(
                                 m, &meta[i]) != RWPA_STS_OK)) {
                    DATA_LOG_AND_DROP(m, ERR, RWPA_UL,
                                      "Error converting packet to Ethernet, dropping\n",
                                      STATS_UL_DROPS_TYPE_ETH_CONVERT_ERROR);

                /*
                 * GRE ENCAP
                 * - add the outer Ethernet, IP and GRE headers
                 * - only if sending to a WAG
                 */
                } else if (unlikely(g_app->misc_params.no_wag == FALSE &&
                                    GRE_ENCAP(m, addr_params->vnfd_ip_to_wag,
                                              vnfd_eth_addr_to_wag,
                                              addr_params->wag_tun_ip,
                                              &(addr_params->wag_tun_mac)) != RWPA_STS_OK)) {
                    DATA_LOG_AND_DROP(m, ERR, RWPA_UL,
                                      "Error adding GRE headers, dropping\n",
                                      STATS_UL_DROPS_TYPE_DATA_PACKET_ENCAP_ERROR);

                /*
                 * WRITE TO TX BUFFER
                 */
                } else {
                    RTE_ETH_TX_BUFFER(dst_ports[UL_DST_PORT_WAG].port_id,
                                      dst_ports[UL_DST_PORT_WAG].queue_id,
                                      dst_ports[UL_DST_PORT_WAG].tx_buffer, m);
                }

            }  else if (pkt_type == IEEE80211_PKT_TYPE_EAPOL) {
                /* EAPOL */

                /*
                 * CCMP DECAP
                 * - remove the CCMP header and MIC
                 */
                if (meta[i].wep &&
                    CCMP_DECAP(m, &meta[i]) == RWPA_STS_ERR) {
                    DATA_LOG_AND_DROP(m, ERR, RWPA_UL,
                                      "Error removing CCMP header, dropping\n",
                                      STATS_UL_DROPS_TYPE_PACKET_DECAP_ERROR);

                /*
                 * WPAPT_CDI_MSG_FRAME ENCAP
                 * - add the wpapt_cdi_msg_frame encapsulation
                 */
                } else if (unlikely(WPAPT_CDI_FRAME_ENCAP(
                                      m, &meta[i], m->data_len) != RWPA_STS_OK)) {
                    DATA_LOG_AND_DROP(m, ERR, RWPA_UL,
                                      "Error adding TLS message frame, dropping\n",
                                      STATS_UL_DROPS_TYPE_CTRL_PACKET_ENCAP_ERROR);

                /*
                 * WPAPT_CDI_MSG_HEADER ENCAP
                 * -add the wpapt_cdi_msg_header
                 */
                } else if (unlikely(WPAPT_CDI_HDR_ENCAP(
                                        m, WPAPT_CDI_MSG_FRAME, m->data_len) != RWPA_STS_OK)) {
                    DATA_LOG_AND_DROP(m, ERR, RWPA_UL,
                                 "Error adding TLS message header, dropping\n",
                                 STATS_UL_DROPS_TYPE_CTRL_PACKET_ENCAP_ERROR);

                /*
                 * WRITE TO TLS SOCKET
                 */
                } else {
#ifndef RWPA_UL_NO_TLS_POLLING
                    TLS_SOCKET_WRITE(tls, m);
#endif
                }
            } else {
                /* Something Else */
                DATA_LOG_AND_DROP(m, ERR, RWPA_UL,
                                  "Could not classify 802.11 packet, dropping\n",
                                  STATS_UL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE);
            }
        }
    }
}

static void
uplink_pmd_packets_process(struct pkt_buffer *pkts_in, uint64_t cur_tsc)
{
    unsigned i;
    struct rte_mbuf *m;
    struct pkt_buffer pkts_ap_tunnel __rte_cache_aligned;

    pkts_ap_tunnel.len = 0;

    for (i = 0; i < pkts_in->len; i++) {
        m = pkts_in->buffer[i];
        rte_prefetch0(rte_pktmbuf_mtod(m, void *));
        enum outer_pkt_type type = INITIAL_PACKET_CLASSIFY(m);
        switch (type) {
            /*
             * ARP
             */
            case OUTER_PKT_TYPE_ARP:
                if (arp_reply(m, dst_ports[UL_DST_PORT_AP].port_id, addr_params->vnfd_ip_to_ap))
			rte_eth_tx_buffer(dst_ports[UL_DST_PORT_AP].port_id,
					  dst_ports[UL_DST_PORT_AP].queue_id,
					  dst_ports[UL_DST_PORT_AP].tx_buffer, m);
                break;

            /*
             * ICMP
             */
            case OUTER_PKT_TYPE_ICMP:
                rte_pktmbuf_free(m);
                break;

#ifndef RWPA_AP_TUNNELLING_GRE
            /*
             * UDP
             */
            case OUTER_PKT_TYPE_UDP:
#else
            /*
             * GRE
             */
            case OUTER_PKT_TYPE_GRE:
#endif
                pkts_ap_tunnel.buffer[pkts_ap_tunnel.len++] = m;
                break;

            /*
             * Other IP
             */
#ifndef RWPA_AP_TUNNELLING_GRE
            case OUTER_PKT_TYPE_GRE:
#else
            case OUTER_PKT_TYPE_UDP:
#endif
            case OUTER_PKT_TYPE_OTHER_IP:
#ifndef RWPA_AP_TUNNELLING_GRE
                DATA_LOG_AND_DROP(m, ERR, RWPA_UL,
                                  "Not handling non-UDP encapsulated uplink "
                                  "IP traffic, dropping\n",
                                  STATS_UL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE);
#else
                DATA_LOG_AND_DROP(m, ERR, RWPA_UL,
                                  "Not handling non-GRE encapsulated uplink "
                                  "IP traffic, dropping\n",
                                  STATS_UL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE);
#endif
                break;

            /*
             * Other
             */
            default:
                DATA_LOG_AND_DROP(m, ERR, RWPA_UL,
                                  "Could not classify outer packet, dropping\n",
                                  STATS_UL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE);
                break;
        }
    }

    /*
     * process the AP tunnel encapsulated packets
     */
    ap_tunnel_packets_process(&pkts_ap_tunnel, cur_tsc);
}

static void
pmd_dequeue(uint64_t cur_tsc)
{
    struct pkt_buffer pkts_in __rte_cache_aligned;

    pkts_in.len = RTE_ETH_RX_BURST(src_ports[UL_SRC_PORT].port_id, 0,
                                   pkts_in.buffer, MAX_PKT_BURST);

    if (likely(pkts_in.len)) {
        UL_DATA_PMD_READ_STAT_INC(STATS_PMD_READS_TYPE_NON_EMPTY, 1);
        UL_PROCESS_FULL_CYCLE_CAPTURE_START;
        uplink_pmd_packets_process(&pkts_in, cur_tsc);
        UL_PROCESS_FULL_CYCLE_CAPTURE_STOP;
    } else {
        UL_DATA_PMD_READ_STAT_INC(STATS_PMD_READS_TYPE_EMPTY, 1);
    }
}

static void
uplink_main_loop(void)
{
#ifndef RWPA_UL_NO_TLS_POLLING
    unsigned wrr_index = 0;
    struct poll_wrr_elem *cur_wrr = wrr_elements[wrr_index];
    uint64_t cur_wrr_tsc, prev_wrr_tsc;
#endif
    uint64_t prev_tsc, diff_tsc, cur_tsc;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
                               US_PER_S * BURST_TX_DRAIN_US;

    prev_tsc = 0;
#ifndef RWPA_UL_NO_TLS_POLLING
    prev_wrr_tsc = 0;
#endif

    while (!force_quit) {
        cur_tsc = rte_rdtsc();

        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            for (int i = 0; i < UL_NUM_DST_PORTS; i++)
                rte_eth_tx_buffer_flush(dst_ports[i].port_id,
                                        dst_ports[i].queue_id,
                                        dst_ports[i].tx_buffer);
            prev_tsc = cur_tsc;
        }

        /*
         * Read packet from RX queues
         */
#ifndef RWPA_UL_NO_TLS_POLLING
        cur_wrr_tsc = rte_rdtsc();
        diff_tsc = cur_wrr_tsc - prev_wrr_tsc;
        if (unlikely(diff_tsc > cur_wrr->allocated_tsc)) {
            if (wrr_index < (MAX_UL_WRR_ELEMS - 1)) {
                wrr_index++;
            } else {
                wrr_index = 0;
            }
            cur_wrr = wrr_elements[wrr_index];
            prev_wrr_tsc = cur_wrr_tsc;
        }

        cur_wrr->p_func(cur_wrr_tsc);
#else
        pmd_dequeue(cur_tsc);
#endif
        vap_frag_free_death_row();
    }
}

static int
thread_uplink_run(__rte_unused void *arg)
{
    unsigned lcore_id, socket_id;

    lcore_id = rte_lcore_id();
    socket_id = rte_socket_id();

    RTE_LOG(INFO, RWPA_UL,
            "%s (%s): Entering main loop on lcore %u (socket %u)\n",
            tp_uplink->name, tp_uplink->type, lcore_id, socket_id);

    uplink_main_loop();

    return 0;
}

static int
thread_uplink_free(__rte_unused void *arg)
{
    unsigned lcore_id, socket_id;

    lcore_id = rte_lcore_id();
    socket_id = rte_socket_id();

    RTE_LOG(INFO, RWPA_UL,
            "%s (%s): Freeing on lcore %u (socket %u)\n",
            tp_uplink->name, tp_uplink->type, lcore_id, socket_id);

    tls_socket_free();

    return 0;
}

uint8_t
uplink_thread_src_port_get(void)
{
    return src_ports[UL_SRC_PORT].port_id;
}

static struct thread_ops_s thread_uplink_ops = {
    .f_init = thread_uplink_init,
    .f_free = thread_uplink_free,
    .f_run  = thread_uplink_run,
};

struct thread_type thread_uplink = {
    .name = "UPLINK_THREAD",
    .thread_ops = &thread_uplink_ops,
};
