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

/* Interface between Control VNF server (CVNF) and Data VNF server (DVNF).
 * This header defives the format of the messages dent between DVNF and CVNF.
 *
 * Note 1: The unserline transport is assumed to be stream-based,
 *         it does not necessarily keeps the boundaries betweem messages.
 *
 * Note 2: All numeric fields are in the LITTLE ENDIAN format.
 *
 * Note 3: Naming convention:
 *         WPAPT_ or wpapt_ is a generic prefix used to avoid name collission.
 *         Relates to all servers and clients involved in WPA Pass Through.
 *         WPAPT_CDI_ or wpapt_cdi_ is used for CVNF to DVNF interface.
 *
 * Note 4: Error handling concept:
 *       - If either of CVNF or DVNF fails in a way that it cannot continue
 *         it sends a WPAPT_CDI_MSG_STATUS message with an error code and
 *         textual explanations.
 *       - Non-critical failures and informational messages about server health
 *         are also reported through WPAPT_CDI_MSG_STATUS (status could be OK
 *         or Warning).
 *       - If a failure in DVNF affects a specific BSS or STA only it is
 *         reported to CVNF through WPAPT_CDI_MSG_BSS_REMOVE or
 *         WPAPT_CDI_MSG_STA_REMOVE respectively.
 */

#ifndef WPAPT_CDI_H
#define WPAPT_CDI_H

/*                      WPA Pass Through Definitions
 =============================================================================*/

#define WPAPT_ETH_ALEN          6 /* The length of a MAC address */
#define WPAPT_SSID_MAX_LEN     32 /* Not counting terminating '\0' */
#define WPAPT_MAX_KEY_LEN      32

#define WPAPT_KEY_RSC_LEN       8 /* WPA_KEY_RSC_LEN in hostapd */
#define WPAPT_KCK_MAX_LEN      24


/*                          CVNF to DVNF Interface
 =============================================================================*/

#define WPAPT_CDI_VERSION           1 /* Protocol version */
#define WPAPT_CDI_MAX_MSG        1500 /* Maximum message size */
#define WPAPT_CDI_MAGIC    0x57434449 /* 'WCDI' in ASCII */

/* Cipher algorithms, as in hostapd (WPA_CIPHER_...) */
enum WPAPT_CIPHER_ALG {
    WPAPT_ALG_NONE,
    WPAPT_ALG_WEP,
    WPAPT_ALG_TKIP,
    WPAPT_ALG_CCMP,
    WPAPT_ALG_IGTK,
    WPAPT_ALG_PMK,
    WPAPT_ALG_GCMP,
    WPAPT_ALG_SMS4,
    WPAPT_ALG_KRK,
    WPAPT_ALG_GCMP_256,
    WPAPT_ALG_CCMP_256,
    WPAPT_ALG_BIP_GMAC_128,
    WPAPT_ALG_BIP_GMAC_256,
    WPAPT_ALG_BIP_CMAC_256
};


/* Message identifiers */
#define WPAPT_CDI_MSG_INIT          1
#define WPAPT_CDI_MSG_STATUS        2
#define WPAPT_CDI_MSG_BSS_ADD       3
#define WPAPT_CDI_MSG_BSS_REMOVE    4
#define WPAPT_CDI_MSG_STA_ADD       5
#define WPAPT_CDI_MSG_STA_REMOVE    6
#define WPAPT_CDI_MSG_SET_KEY       7
#define WPAPT_CDI_MSG_FRAME         8
#define WPAPT_CDI_MSG_EAPOL_MIC     9


#pragma pack(push,1)

/* Each message starts by this header. By reading this header from a TCP
 * stream we double check the validity of data in the stream by checking
 * the magic number, find out the message type and its length.
 */

struct wpapt_cdi_msg_header
{
    uint32_t  magic;       /* expected to be WPAPT_CDI_MAGIC */
    uint16_t  message_id;  /* message code */
    uint16_t  payload_len; /* payload length (not counting this header) */
};


/*               Message WPAPT_CDI_MSG_INIT
 * ----------------------------------------------------------
 * Direction: Both
 * Purpose:   Initial handshaking, initial information exchange.
*/

struct wpapt_cdi_msg_init
{
    uint16_t  prot_version; /* stepped up whatever compatibility
                               between peers is concerned */
    uint32_t  peer_version; /* e.g.0x05050001 for version 5.5.0.1 */
    uint16_t  peer_id_len;  /* Length of the string that follows */
    char      peer_id[0];   /* Printable id string */
};


/*               Message WPAPT_CDI_MSG_STATUS
 * ----------------------------------------------------------
 * Direction: Both
 * Purpose:   Error handling, letting the parties to follow the health
 *            of each other.
*/

#define WPAPT_CDI_STATUS_OK              0
#define WPAPT_CDI_STATUS_WARNING         1
#define WPAPT_CDI_STATUS_ERROR           2
#define WPAPT_CDI_STATUS_SHUTTING_DOWN   3

struct wpapt_cdi_msg_status
{
    uint16_t  peer_status;
    uint16_t  message_len;  /* Length of the reason string */
    char      message[0];   /* Printable string providing details */
};


/*               Message WPAPT_CDI_MSG_BSS_ADD
 * ----------------------------------------------------------
 * Direction: From CVNF to DVNF
 * Purpose:   CVNF informs DVNF that a new CPE has connected.
 */

struct wpapt_cdi_msg_bss_add
{
    uint8_t  bssid[WPAPT_ETH_ALEN];
    uint8_t  essid_len;
    uint8_t  essid[0];
};


/*               Message WPAPT_CDI_MSG_BSS_REMOVE
 * ----------------------------------------------------------
 * Direction: From CVNF to DVNF during normal operation flow.
 *            From DVNF to CVNF to report BSS failure.
 * Purpose:   A request to remove the given BSS from database.
 */

struct wpapt_cdi_msg_bss_remove
{
    uint8_t  bssid[WPAPT_ETH_ALEN];
    uint32_t reason;     /* Enum is TBD */
};


/*               Message WPAPT_CDI_MSG_STA_ADD
 * ----------------------------------------------------------
 * Direction: From CVNF to DVNF
 * Purpose:   CVNF informs DVNF that a new wireless station has connected.
 */

struct wpapt_cdi_msg_sta_add
{
    uint8_t  bssid[WPAPT_ETH_ALEN];
    uint8_t  sta_addr[WPAPT_ETH_ALEN];
};


/*               Message WPAPT_CDI_MSG_STA_REMOVE
 * ----------------------------------------------------------
 * Direction: From CVNF to DVNF during normal operation flow.
 *            From DVNF to CVNF to report a failure.
 * Purpose:   A request to remove the given station from database.
 */

struct wpapt_cdi_msg_sta_remove
{
    uint8_t  bssid[WPAPT_ETH_ALEN];
    uint8_t  sta_addr[WPAPT_ETH_ALEN];
    uint32_t reason;     /* Enum is TBD */
};


/*               Message WPAPT_CDI_MSG_SET_KEY
 * ----------------------------------------------------------
 * Direction: From CVNF to DVNF
 * Purpose:   To send encryption keys to DVNF so that it can encrypt/decrypt
 *            data traffic and management frames (11w).
 */

struct wpapt_cdi_msg_set_key
{
    uint8_t  bssid[WPAPT_ETH_ALEN];
    uint8_t  sta_addr[WPAPT_ETH_ALEN]; /* FF:FF:FF:FF:FF:FF for GTK */
    uint16_t key_idx;                  /* 0: PTK; 1,2: GTK; 3,4: IGTK */
    uint16_t cipher_suite;             /* enum WPAPT_CIPHER_ALG */
    uint8_t  key_len;
    uint8_t  key[0];
};


/*               Message WPAPT_CDI_MSG_FRAME
 * ----------------------------------------------------------
 * Direction: Both
 * Purpose:   To deliver EAPOL or management frames, in 802.11 format.
 *
 * Note: If MIC in EAPOL Tx messages is calculated in hostapd, each EAPOL Rx
 *       comimg from DVNF to CVNF shall be preceeded with WPAPT_CDI_MSG_RSC.
 */

#define WPAPT_FRAME_EAPOL 0
#define WPAPT_FRAME_MGMT  1

struct wpapt_cdi_msg_frame
{
    uint8_t     bssid[WPAPT_ETH_ALEN];
    uint8_t     sta_addr[WPAPT_ETH_ALEN];
    uint16_t    frame_type; /* as per #define-s above */
    uint16_t    frame_len;  /* Length of the 802.11 frame */
    uint8_t     frame[0];   /* staring from .11 header */
};


/*               Message WPAPT_CDI_MSG_EAPOL_MIC
 * ----------------------------------------------------------
 * Direction: From CVNF to DVNF
 * Purpose:   Used if MIC in EAPOL Tx messages is calculated in DVNF.
 *            DVNF assigns RSC, calculates MIC for Tx EAPOL and send
 *            it to STA.
 */

/* IEEE 802.11, 8.5.2 EAPOL-Key frames */
#define WPAPT_CDI_KEY_INFO_TYPE_MASK ((u16) (BIT(0) | BIT(1) | BIT(2)))
#define WPAPT_CDI_KEY_INFO_TYPE_AKM_DEFINED 0
#define WPAPT_CDI_KEY_INFO_TYPE_HMAC_MD5_RC4 BIT(0)
#define WPAPT_CDI_KEY_INFO_TYPE_HMAC_SHA1_AES BIT(1)
#define WPAPT_CDI_KEY_INFO_TYPE_AES_128_CMAC 3

/* Bit definitions for wpapt_cdi_msg_eapol_mic::akm */
#define WPAPT_CDI_KEY_MGMT_OSEN BIT(0)
#define WPAPT_CDI_KEY_MGMT_IEEE8021X_SUITE_B BIT(1)
#define WPAPT_CDI_KEY_MGMT_IEEE8021X_SUITE_B_192 BIT(2)

struct wpapt_cdi_msg_eapol_mic
{
    uint8_t     bssid[WPAPT_ETH_ALEN];
    uint8_t     sta_addr[WPAPT_ETH_ALEN];
    uint16_t    frame_type; /* as per #define-s above */
    uint8_t     key[WPAPT_KCK_MAX_LEN];
    uint8_t     key_len;
    uint8_t     key_info_type;
    uint8_t     akm;
    uint16_t    frame_len;  /* Length of the 802.11 frame */
    uint8_t     frame[0];   /* staring from .11 header */
};

#pragma pack(pop)

#endif /* WPAPT_CDI_H */
