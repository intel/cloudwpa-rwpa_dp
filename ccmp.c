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
#include <rte_ether.h>
#include <rte_cryptodev.h>

#include "app.h"
#include "r-wpa_global_vars.h"
#include "key.h"
#include "counter.h"
#include "seq_num.h"
#include "meta.h"
#include "ieee80211.h"
#include "crypto.h"
#include "ccmp_sa.h"
#include "ccmp.h"

/*
 * AAD Frame Control Mask
 * Mask the following fields to 0
 * - Subtype (bits 4,5,6) if Data frame
 * - Retry (bit 11)
 * - Power Management (bit 12)
 * - More Data (bit 13)
 */
#define AAD_FC_DATA_MASK     0xC78F
#define AAD_FC_NON_DATA_MASK 0xC7FF

/*
 * AAD Sequence Control Mask
 * - Mask the Sequence Number to 0
 * - Fragment Number is untouched
 */
#define AAD_SC_MASK          0x000F

/*
 * AAD QoS Control Mask
 * - 802.11 spec is quite detailed in relation to this field
 *   - different fields masked depending on whether in a DMG BSS or not
 *     or if STA and peer have their SPP A-MSDU Capable field equal to
 *     0 or 1
 * - Keeping simple for now and masking everything except the TID, which
 *   is always present
 */
#define AAD_QC_MASK          0x000F

static inline enum rwpa_status
op_setup(struct rte_mbuf      *mbuf,
         struct rwpa_meta     *meta,
         enum ccmp_op          op,
         struct rte_crypto_op *cop);

static inline void
counter_val_to_pn(counter_val_t  ctr_val,
                  uint8_t       *pn,
                  int            msb);

static inline counter_val_t
pn_to_counter_val(const uint8_t *pn);

enum rwpa_status
ccmp_aad_generate(struct ieee80211_hdr *wifi_hdr,
                  struct rwpa_meta     *meta,
                  uint8_t              *aad,
                  uint8_t              *aad_len)
{
    /* check parameters */
    if (unlikely(wifi_hdr == NULL ||
                 meta == NULL ||
                 aad == NULL ||
                 aad_len == NULL))
        return RWPA_STS_ERR;

    struct ccmp_aad *aad_p = (struct ccmp_aad *)aad;

    /*
     * Frame Control
     * - mask certain fields to 0, as per defined masks
     * - ensure wep field is 1
     * - order bit only masked to 0 if QoS Control present
     */
    aad_p->frame_ctrl.u16 = wifi_hdr->frame_ctrl.le.type == IEEE80211_TYPE_DATA ? 
                                wifi_hdr->frame_ctrl.u16 & AAD_FC_DATA_MASK :
                                wifi_hdr->frame_ctrl.u16 & AAD_FC_NON_DATA_MASK;
    aad_p->frame_ctrl.le.wep = 1;
    if (meta->has_qc) aad_p->frame_ctrl.le.order = 0;

    /*
     * Addresses 1,2 and 3
     * - copy over all 3 in 1 go
     */
    rte_memcpy(&(aad_p->addr1), &(wifi_hdr->addr1), 3 * sizeof(struct ether_addr));

    /*
     * Sequence Control
     * - mask sequence number to 0
     */
    aad_p->seq_ctrl.u16 = wifi_hdr->seq_ctrl.u16 & AAD_SC_MASK;

    /*
     * all mandatory fields filled in at this stage, so
     * set the current length
     */
    *aad_len = sizeof(struct ccmp_aad);

    /* Address 4, if present */
    if (meta->has_a4 && meta->p_a4) {
        struct ether_addr *aad_a4 = (struct ether_addr *)(aad + *aad_len);
        ether_addr_copy(meta->p_a4, aad_a4);
        *aad_len += sizeof(struct ether_addr);
    }

    /* QoS Control, if present */
    if (meta->has_qc && meta->p_qc) {
        union qos_ctrl *aad_qc = (union qos_ctrl *)(aad + *aad_len);
        aad_qc->u16 = meta->p_qc->u16 & AAD_QC_MASK;
        *aad_len += sizeof(union qos_ctrl);
    }

    return RWPA_STS_OK;
}

enum rwpa_status
ccmp_nonce_generate(struct ieee80211_hdr *wifi_hdr,
                    struct rwpa_meta     *meta,
                    counter_val_t         ctr_val,
                    uint8_t              *nonce)
{
    /* check parameters */
    if (unlikely(wifi_hdr == NULL ||
                 meta == NULL ||
                 nonce == NULL))
        return RWPA_STS_ERR;

    struct ccmp_nonce *nonce_p = (struct ccmp_nonce *)nonce;

    /*
     * Nonce Flags
     * - clear all to 0 initially
     * - if Qos Control is present though, set the priority
     *   equal to the TID
     * - Note: when management frames are supported, then the
     *   management flag may need to be set appropriately
     */
    nonce_p->flags.u8 = 0;
    if (meta->has_qc && meta->p_qc)
        nonce_p->flags.le.priority = meta->p_qc->le.tid;

    /* Address 2, copy directly from 802.11 header */
    ether_addr_copy(&(wifi_hdr->addr2), &(nonce_p->addr2));

    /* PN */
    counter_val_to_pn(ctr_val, nonce_p->pn, TRUE);

    return RWPA_STS_OK;
}

enum rwpa_status
ccmp_hdr_generate(counter_val_t  pn,
                  enum key_id    key_id,
                  uint8_t       *ccmp_hdr)
{
    uint8_t hdr_pn[CCMP_PN_LEN];

    /* check parameters */
    if (unlikely(ccmp_hdr == NULL))
        return RWPA_STS_ERR;

    struct ccmp_hdr *ccmp_hdr_p = (struct ccmp_hdr *)ccmp_hdr;

    counter_val_to_pn(pn, hdr_pn, FALSE);

    rte_memcpy(&(ccmp_hdr_p->pn0), hdr_pn, 2);
    rte_memcpy(&(ccmp_hdr_p->pn2), hdr_pn + 2, 4);

    ccmp_hdr_p->rsvd1 = 0;
    ccmp_hdr_p->key_id.le.rsvd2 = 0;
    ccmp_hdr_p->key_id.le.ext_iv = 1;
    ccmp_hdr_p->key_id.le.key_id = key_id;

    return RWPA_STS_OK;
}

uint16_t
ccmp_burst_enqueue(struct rte_mbuf  *pkts_in[],
                   uint16_t          pkts_in_sz,
                   struct rwpa_meta *meta[],
                   enum ccmp_op      op,
                   uint16_t          qp,
                   uint8_t           success[])
{
    enum rwpa_status crypto_sts;
    struct rte_crypto_op *ops[MAX_PKT_BURST];
    uint8_t ops_success[MAX_PKT_BURST];
    uint16_t nb_ops, nb_enq, nb_enq_ret, i;

    /* check parameters */
    if (unlikely(pkts_in == NULL ||
                 meta == NULL ||
                 success == NULL)) {
        if (success != NULL)
            memset(success, FALSE, pkts_in_sz);

        return 0;
    }

    RWPA_CHECK_ARRAY_OFFSET(pkts_in_sz, MAX_PKT_BURST);

    /* allocate the crypto ops */
    crypto_sts = crypto_ops_alloc(pkts_in_sz, ops);
    if (unlikely(crypto_sts == RWPA_STS_ERR)) {
        memset(success, FALSE, pkts_in_sz);
        return 0;
    } 

    /* setup the crypto ops */
    nb_ops = 0;
    for (i = 0; i < pkts_in_sz; i++) {
        if (likely(op_setup(pkts_in[i], meta[i], op, ops[nb_ops]) == RWPA_STS_OK)) {
            success[i] = TRUE;
            ops_success[nb_ops++] = i;
        } else
            success[i] = FALSE;
    }

    /* enqueue the burst of crypto operations */
    if (likely(nb_ops > 0))
        nb_enq = nb_enq_ret = crypto_burst_enqueue(ops, nb_ops, qp);
    else
        nb_enq = nb_enq_ret = 0;

    /* free any crypto ops not successfully enqueued */
    if (unlikely(nb_enq < nb_ops)) {
        do {
            success[ops_success[nb_enq]] = FALSE;
            rte_crypto_op_free(ops[nb_enq]);
        } while (++nb_enq < nb_ops);
    }

    /* free any crypto ops not successfully setup */ 
    if (unlikely(nb_ops < pkts_in_sz)) {
        do {
            rte_crypto_op_free(ops[nb_ops]);
        } while (++nb_ops < pkts_in_sz);
    }

    return nb_enq_ret;
}

uint16_t
ccmp_burst_dequeue(struct rte_mbuf *pkts_out[],
                   uint16_t         pkts_out_sz,
                   uint16_t         qp,
                   uint16_t        *nb_success,
                   uint8_t          success[])
{
    struct rte_crypto_op *ops[MAX_PKT_BURST];
    uint16_t nb_deq, i;

    /* check parameters */
    if (unlikely(pkts_out == NULL ||
                 nb_success == NULL ||
                 success == NULL)) {
        if (success != NULL)
            memset(success, FALSE, pkts_out_sz);
        if (nb_success != NULL)
            *nb_success = 0;
        return 0;
    }

    /* dequeue the burst of crypto operations */
    if (likely(pkts_out_sz > 0))
        nb_deq = *nb_success = crypto_burst_dequeue(ops, pkts_out_sz, qp);
    else
        nb_deq = *nb_success = 0;

    for (i = 0; i < nb_deq; i++) {
        /*
         * check the crypto status and set the success flag
         * appropriately
         */
        pkts_out[i] = ops[i]->sym->m_src;

        if (likely(ops[i]->status == RTE_CRYPTO_OP_STATUS_SUCCESS))
            success[i] = TRUE;
        else {
            success[i] = FALSE;
            (*nb_success)--;
        }

        rte_crypto_op_free(ops[i]);
    }

    return nb_deq;
}

enum rwpa_status
ccmp_replay_detect(struct ccmp_hdr *hdr,
                   counter_val_t   *ctr_check)
{
    uint8_t hdr_pn[CCMP_PN_LEN];
    counter_val_t ctr_val;

    /* check parameters */
    if (unlikely(hdr == NULL ||
                 ctr_check == NULL))
        return RWPA_STS_ERR;

    /* extract PN from CCMP header */
    rte_memcpy(hdr_pn, &(hdr->pn0), 2);
    rte_memcpy(hdr_pn + 2, &(hdr->pn2), 4);

    ctr_val = pn_to_counter_val(hdr_pn);

#ifndef RWPA_NO_REPLAY_CHECK
    /* check for replay */
    if (unlikely(ctr_val <= *ctr_check))
        return RWPA_STS_ERR;
#endif

    /* return the CCMP header PN */
    *ctr_check = ctr_val;

    return RWPA_STS_OK;
}

enum rwpa_status
ccmp_encap(struct rte_mbuf *mbuf,
           struct rwpa_meta *meta)
{
    /* check parameters */
    if (unlikely(mbuf == NULL ||
                 meta == NULL ||
                 meta->sa == NULL))
        return RWPA_STS_ERR;

    /* save original wifi header */
    uint8_t wifi_hdr_u8_tmp[IEEE80211_HDR_SZ_MAX];
    uint8_t wifi_hdr_sz = meta->wifi_hdr_sz < IEEE80211_HDR_SZ_MAX ?
                          meta->wifi_hdr_sz : IEEE80211_HDR_SZ_MAX;
    rte_memcpy(wifi_hdr_u8_tmp, rte_pktmbuf_mtod(mbuf, uint8_t *), wifi_hdr_sz);

    /* create space for ccmp header */
    uint8_t *wifi_hdr_u8 = (uint8_t *)rte_pktmbuf_prepend(mbuf, sizeof(struct ccmp_hdr));

    /* fill new wifi header with old values */
    rte_memcpy(wifi_hdr_u8, wifi_hdr_u8_tmp, wifi_hdr_sz);

    /* get pointer to ccmp_hdr */
    uint8_t *ccmp_hdr =
        rte_pktmbuf_mtod_offset(mbuf, uint8_t *,
                                meta->wifi_hdr_sz);
    /* fill ccmp_hdr */
    if (unlikely(ccmp_hdr_generate(
                     meta->counter, 0, ccmp_hdr) != RWPA_STS_OK)) {
        return RWPA_STS_ERR;
    } else {
        /*
         * append space to the end of the packet mbuf for
         * CCMP MIC
         * - MIC is half the length of the key
         */
        if (unlikely(rte_pktmbuf_append(mbuf, (meta->sa->tk_len >> 1)) == NULL))
            return RWPA_STS_ERR;
    }

    /* update meta pointers to bssid and station MAC addresses */
    meta->p_bssid = (struct ether_addr *)
                        (((uint8_t *)meta->p_bssid) - sizeof(struct ccmp_hdr));
    meta->p_sta_addr = (struct ether_addr *)
                        (((uint8_t *)meta->p_sta_addr) - sizeof(struct ccmp_hdr));

    return RWPA_STS_OK;
}

enum rwpa_status
ccmp_decap(struct rte_mbuf  *mbuf,
           struct rwpa_meta *meta)
{
    /* check parameters */
    if (unlikely(mbuf == NULL ||
                 meta == NULL ||
                 meta->sa == NULL))
        return RWPA_STS_ERR;

    /*
     * CCMP header is in between the 802.11 and SNAP headers
     * - need to remove this CCMP header
     * - unfortunately, cannot do this with just mbuf adjustments, so
     *   will require some memcpys
     *   - because the CCMP header is only 8 bytes, we cannot move the
     *     802.11 header in 1 step as the source and dest addresses
     *     would overlap, so need to:
     *     1) copy 802.11 header from mbuf to a local variable
     *     2) remove 8 bytes from the front of the mbuf
     *     3) copy the 802.11 header back into the mbuf
     * - also need to remove the MIC from the end
     */
    uint8_t *wifi_hdr_u8 = rte_pktmbuf_mtod(mbuf, uint8_t *);
    uint8_t wifi_hdr_u8_tmp[IEEE80211_HDR_SZ_MAX];
    uint8_t wifi_hdr_sz = meta->wifi_hdr_sz < IEEE80211_HDR_SZ_MAX ?
                          meta->wifi_hdr_sz : IEEE80211_HDR_SZ_MAX;

    rte_memcpy(wifi_hdr_u8_tmp, wifi_hdr_u8, wifi_hdr_sz);

    if (unlikely((wifi_hdr_u8 = (uint8_t *)rte_pktmbuf_adj(
                                            mbuf, sizeof(struct ccmp_hdr))) == NULL ||
                 rte_pktmbuf_trim(mbuf, (meta->sa->tk_len >> 1)) == -1))
        return RWPA_STS_ERR;

    rte_memcpy(wifi_hdr_u8, wifi_hdr_u8_tmp, wifi_hdr_sz);

    /* update meta pointers to bssid and station MAC addresses */
    meta->p_bssid = (struct ether_addr *)
                        (((uint8_t *)meta->p_bssid) + sizeof(struct ccmp_hdr));
    meta->p_sta_addr = (struct ether_addr *)
                        (((uint8_t *)meta->p_sta_addr) + sizeof(struct ccmp_hdr));

    return RWPA_STS_OK;
}

static inline void
counter_val_to_pn(counter_val_t  ctr_val,
                  uint8_t       *pn,
                  int            msb)
{
    int i;
    uint8_t *p_pn = pn + ( msb ? (CCMP_PN_LEN - 1) : 0 );
    int delta = ( msb ? -1 : 1 );

    for (i = 0; i < CCMP_PN_LEN; i++) {
        *p_pn = ctr_val & 0xFF;
        p_pn += delta;
        ctr_val >>= 8;
    }
}

static inline counter_val_t
pn_to_counter_val(const uint8_t *pn)
{
    uint8_t i;
    counter_val_t ret = 0;

    for (i = CCMP_PN_LEN; i > 0; i--) {
        ret <<= 8;
        ret |= (counter_val_t) pn[i-1];
    }

    return ret;
}

static inline enum rwpa_status
op_setup(struct rte_mbuf      *mbuf,
         struct rwpa_meta     *meta,
         enum ccmp_op          op,
         struct rte_crypto_op *cop)
{
    struct ieee80211_hdr *wifi_hdr;
    uint8_t aad_len = 0;
    uint32_t data_offset;
    uint32_t data_length;
    uint32_t digest_length;

    /* check parameters */
    if (unlikely(mbuf == NULL ||
                 meta == NULL ||
                 meta->sa == NULL ||
                 cop == NULL ||
                 (wifi_hdr =
                      rte_pktmbuf_mtod(mbuf, struct ieee80211_hdr *)) == NULL))
        return RWPA_STS_ERR;

    /*
     * digest length is half the key length
     * - CCMP-128 has 16 byte key and 8 byte MIC
     * - CCMP-256 has 32 byte key and 16 byte MIC
     */
    digest_length = meta->sa->tk_len >> 1;

    /*
     * fill in the crypto op data
     *
     * data offset and length
     * - skip over the wifi header and the space left for the
     *   CCMP header to get the offset
     * - subtract the wifi header, CCMP header and space left
     *   for the MIC from the overall packet length to get the
     *   data length
     */
    data_offset = meta->wifi_hdr_sz + sizeof(struct ccmp_hdr);
    data_length = mbuf->data_len - data_offset - digest_length;

    cop->sym->aead.data.offset = data_offset;
    cop->sym->aead.data.length = data_length;

    /*
     * MIC (digest) is placed after the encrypted data
     * - space has been reserved in the mbuf for the MIC
     */
    cop->sym->aead.digest.data =
        rte_pktmbuf_mtod_offset(mbuf, uint8_t *, (data_offset + data_length));
    cop->sym->aead.digest.phys_addr =
        rte_pktmbuf_mtophys_offset(mbuf, (data_offset + data_length));

    /*
     * Nonce (IV) is appended at the end of the crypto
     * operation
     * - 1 byte left too for cryptodev to write to, hence
     *   the '+1' below
     */
    uint8_t *nonce = rte_crypto_op_ctod_offset(
                         cop, uint8_t *, IV_OFFSET);
    ccmp_nonce_generate(wifi_hdr, meta, meta->counter, nonce+1);

    /* AAD is appended after the nonce */
    uint8_t *aad = rte_crypto_op_ctod_offset(
                       cop, uint8_t *, AAD_OFFSET);
    ccmp_aad_generate(wifi_hdr, meta, aad, &aad_len);

    /*
     * the AAD is written 18 bytes after the actual aad
     * pointer, which for us is the same as the pointer
     * to the nonce
     */
    cop->sym->aead.aad.data = nonce;
    cop->sym->aead.aad.phys_addr =
        rte_crypto_op_ctophys_offset(cop, IV_OFFSET);

    /* setup the source mbuf */
    cop->sym->m_src = mbuf;

    /*
     * select the correct crypto session from the SA
     * and attach to the operation
     */
    struct rte_cryptodev_sym_session *session =
                                ccmp_sa_session_select(meta->sa,
                                                       op,
                                                       aad_len);

    if (likely(session != NULL))
        rte_crypto_op_attach_sym_session(cop, session);
    else
        return RWPA_STS_ERR;

    return RWPA_STS_OK;
}
