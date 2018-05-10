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

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#include "r-wpa_global_vars.h"
#include "key.h"
#include "counter.h"
#include "seq_num.h"
#include "meta.h"
#include "wpapt_cdi.h"
#include "wpapt_cdi_helper.h"

enum rwpa_status
wpapt_cdi_hdr_decap(struct rte_mbuf *mbuf)
{
    /* remove the wpapt_cdi_msg_header */
    if (unlikely(rte_pktmbuf_adj(mbuf, sizeof(struct wpapt_cdi_msg_header)) == NULL))
        return RWPA_STS_ERR;

    return RWPA_STS_OK;
}

enum rwpa_status
wpapt_cdi_hdr_encap(struct rte_mbuf *mbuf, uint16_t message_id, uint16_t payload_len)
{
    struct wpapt_cdi_msg_header *hdr;

    /* prepend enough space for the wpapt_cdi_msg_header */
    if (unlikely((hdr = (struct wpapt_cdi_msg_header *)
                             rte_pktmbuf_prepend(mbuf, sizeof(struct wpapt_cdi_msg_header))) == NULL))
        return RWPA_STS_ERR;

    hdr->magic = WPAPT_CDI_MAGIC;
    hdr->message_id = message_id;
    hdr->payload_len = payload_len;

    return RWPA_STS_OK;
}

enum rwpa_status
wpapt_cdi_frame_decap(struct rte_mbuf *mbuf)
{
    /* remove the wpapt_cdi_msg_frame */
    if (unlikely(rte_pktmbuf_adj(mbuf, sizeof(struct wpapt_cdi_msg_frame)) == NULL))
        return RWPA_STS_ERR;

    return RWPA_STS_OK;
}

enum rwpa_status
wpapt_cdi_frame_encap(struct rte_mbuf *mbuf, struct rwpa_meta *meta, uint16_t frame_len)
{
    struct wpapt_cdi_msg_frame *frame;

    /* prepend enough space for the wpapt_cdi_msg_frame */
    if (unlikely((frame = (struct wpapt_cdi_msg_frame *)
                             rte_pktmbuf_prepend(mbuf, sizeof(struct wpapt_cdi_msg_frame))) == NULL))
        return RWPA_STS_ERR;

    if (meta && meta->p_bssid && meta->p_sta_addr) {
        rte_memcpy(frame->bssid, meta->p_bssid, WPAPT_ETH_ALEN);
        rte_memcpy(frame->sta_addr, meta->p_sta_addr, WPAPT_ETH_ALEN);
    }
    frame->frame_type = WPAPT_FRAME_EAPOL;
    frame->frame_len = frame_len;
 
    return RWPA_STS_OK;
}

enum rwpa_status
wpapt_cdi_eapol_mic_decap(struct rte_mbuf *mbuf)
{
    /* remove the wpapt_cdi_msg_eapol_mic */
    if (unlikely(rte_pktmbuf_adj(mbuf, sizeof(struct wpapt_cdi_msg_eapol_mic)) == NULL))
        return RWPA_STS_ERR;

    return RWPA_STS_OK;
}
