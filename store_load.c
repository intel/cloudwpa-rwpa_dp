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
#include <rte_ether.h>

#include <stdio.h>
#include <string.h>

#include "r-wpa_global_vars.h"
#include "app.h"
#include "store_load.h"
#include "key.h"
#include "ccmp_defns.h"
#include "ccmp_sa.h"
#include "vap.h"
#include "station.h"
#include "store.h"
#include "parser.h"

#define FILE_LINE_NUM_ELEMS 3
#define FILE_STA_MAC_IDX    0
#define FILE_VAP_MAC_IDX    1
#define FILE_KEY_IDX        2

static uint32_t
split(char *string, char *tokens[], uint32_t nb_tokens, const char *delim)
{
    uint32_t i;

    if ((string == NULL) ||
        (tokens == NULL) ||
        (nb_tokens < 1))
        return 0;

    for (i = 0; i < nb_tokens; i++) {
        tokens[i] = strtok_r(string, delim, &string);
        if (tokens[i] == NULL)
            break;
    }

    return i;
}

static uint32_t
hex_string_to_byte_array(const char *hexstring_in, uint8_t bytes_out[])
{
    uint32_t i;
    uint32_t bytes_len = strlen(hexstring_in) / 2;

    for(i = 0; i < bytes_len; i++) {
        sscanf(hexstring_in, "%2hhx", &bytes_out[i]);
        hexstring_in += 2;
    }

    return bytes_len;
}

static int
station_add(char *sta_mac_c, char *vap_mac_c, char *key_c)
{
    struct ether_addr sta_mac;
    struct ether_addr vap_mac;
    uint8_t key_b[KEY_LEN_MAX] = {0};

    /* station mac */
    if (parse_mac_addr(sta_mac_c, &sta_mac) == -1) {
        RTE_LOG(ERR, RWPA_STORE_LOAD,
                "Invalid station MAC: %s\n",
                sta_mac_c);
        return -1;
    }

    /* vap mac */
    if (parse_mac_addr(vap_mac_c, &vap_mac) == -1) {
        RTE_LOG(ERR, RWPA_STORE_LOAD,
                "Invalid vAP MAC: %s\n",
                vap_mac_c);
        return -1;
    }

    /* key */
    unsigned int key_len = hex_string_to_byte_array(key_c, key_b);

    /* check key length */
    if (!(key_len == CCMP_128_KEY_LEN || key_len == CCMP_256_KEY_LEN)) {
        RTE_LOG(ERR, RWPA_STORE_LOAD,
                "Invalid key length (must be %d or %d): %d\n",
                CCMP_128_KEY_LEN, CCMP_256_KEY_LEN, key_len);
        return -1;
    }

    /*
     * check if vAP is already in the store
     * - add if not
     */
    if (store_vap_lookup(&vap_mac) == NULL) {
        RTE_LOG(INFO, RWPA_STORE_LOAD,
                "Adding vAP %02x:%02x:%02x:%02x:%02x:%02x to the store\n",
                vap_mac.addr_bytes[0],
                vap_mac.addr_bytes[1],
                vap_mac.addr_bytes[2],
                vap_mac.addr_bytes[3],
                vap_mac.addr_bytes[4],
                vap_mac.addr_bytes[5]);
        store_vap_add(&vap_mac);
    }

    /*
     * check if the station is already in the store
     * - if not found, add it now
     * - if it is found, check if the key is the same
     *   and if not, set the new key
     *   - also need to log a message here because some
     *     packets may be encrypted with the old key
     */
    struct sta_elem *sta;
    if ((sta = store_sta_lookup(&sta_mac)) == NULL) {
        RTE_LOG(INFO, RWPA_STORE_LOAD,
                "Adding station %02x:%02x:%02x:%02x:%02x:%02x to store "
                "with key %s\n",
                sta_mac.addr_bytes[0],
                sta_mac.addr_bytes[1],
                sta_mac.addr_bytes[2],
                sta_mac.addr_bytes[3],
                sta_mac.addr_bytes[4],
                sta_mac.addr_bytes[5],
                key_c);
        sta = store_sta_add(&sta_mac, &vap_mac);
        sta_ptk_set(sta, key_b, key_len);
    } else {
        if (!((sta->ptk_sa.tk_len == key_len) &&
              (memcmp(sta->ptk_sa.tk, key_b, key_len) == 0))) {
           RTE_LOG(WARNING, RWPA_STORE_LOAD,
                   "Resetting key for station %02x:%02x:%02x:%02x:%02x:%02x "
                   "to %s, which may cause packets encrypted with the old key "
                   "to fail\n",
                   sta_mac.addr_bytes[0],
                   sta_mac.addr_bytes[1],
                   sta_mac.addr_bytes[2],
                   sta_mac.addr_bytes[3],
                   sta_mac.addr_bytes[4],
                   sta_mac.addr_bytes[5],
                   key_c);
           sta_ptk_set(sta, key_b, key_len);
        }
    }

    return 0;
}

void
store_load(const char *filename)
{
    FILE *fp;
    const char *mode = "r";
    char line[1024], line_save[1024];

    RTE_LOG(INFO, RWPA_STORE_LOAD,
            "Loading vAP and station store from preload file %s\n",
            filename);

    fp = fopen(filename, mode);

    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *tokens[FILE_LINE_NUM_ELEMS] = {0};
            strcpy(line_save, line);
            if (split(line, tokens, FILE_LINE_NUM_ELEMS, ",\n")  == FILE_LINE_NUM_ELEMS)
                station_add(tokens[FILE_STA_MAC_IDX],
                            tokens[FILE_VAP_MAC_IDX],
                            tokens[FILE_KEY_IDX]);
            else
                RTE_LOG(ERR, RWPA_STORE_LOAD,
                        "Invalid format of input file entry: %s", line_save);
        }

        fclose(fp);
    } else {
        RTE_LOG(ERR, RWPA_STORE_LOAD,
                "Failed to open store preload file: %s\n",
                filename);
    }

    return;
}
