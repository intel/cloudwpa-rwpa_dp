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

#include <rte_hash.h>
#include <rte_ethdev.h>

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC rte_jhash
#endif

#include "r-wpa_global_vars.h"
#include "app.h"
#include "parser.h"
#include "ap_config.h"

static struct app_addr_params *addr_params;

static struct rte_hash *ap_config_store = NULL;
static struct ap_config ap_config[NUM_VAP_MAX];

static uint8_t
entry_add(struct ether_addr bssid,
          struct ether_addr ap_tun_mac,
          uint32_t ap_tun_ip,
          uint16_t ap_tun_port)
{
    int32_t index;

    if ((index = rte_hash_add_key(ap_config_store, &bssid)) < 0) {
        RTE_LOG(ERR, RWPA_AP_CONFIG, "Error adding entry to AP config store\n");
        return 1;
    }

    ap_config[index].tun_mac = ap_tun_mac;
    ap_config[index].tun_ip = ap_tun_ip;
    ap_config[index].tun_port = ap_tun_port;

    return 0;
}

static int8_t
conf_entry_parse(char *entry,
                 int entry_num)
{
    int status = 1;
    char *bssid = strtok(entry, ",\n");
    char *tun_mac_str = strtok(NULL, ",\n");
#ifndef RWPA_AP_TUNNELLING_GRE
    char *tun_ip_str = strtok(NULL, ",\n");
    char *tun_port_str = strtok(NULL, ",\n");
#else
    char *tun_ip_str = strtok(NULL, ",\n");
#endif

    if (bssid != NULL) {
        struct ether_addr tun_mac, bssid_mac;
        uint32_t tun_ip;
        uint16_t tun_port;

        status = parse_mac_addr(bssid, &bssid_mac);

        if (status == 0) {
#ifndef RWPA_AP_TUNNELLING_GRE
            if (tun_port_str == NULL ||
                parser_read_uint16(&tun_port, tun_port_str) != 0) {
                RTE_LOG(DEBUG, RWPA_AP_CONFIG,
                        "Invalid port in entry #%d of AP config file, "
                        "using default AP tunnel port\n", entry_num);
                tun_port = addr_params->vap_tun_def_port;
            }
#else
            tun_port = addr_params->vap_tun_def_port;
#endif

            if (tun_ip_str == NULL ||
                parse_ipv4_addr(tun_ip_str, &tun_ip) != 0) {
                RTE_LOG(DEBUG, RWPA_AP_CONFIG,
                        "Invalid IP address in entry #%d of AP config file, "
                        "using default AP tunnel IP address\n", entry_num);
                tun_ip = addr_params->vap_tun_def_ip;
            }

            if (tun_mac_str == NULL ||
                parse_mac_addr(tun_mac_str, &tun_mac) != 0) {
                RTE_LOG(DEBUG, RWPA_AP_CONFIG,
                        "Invalid MAC address in entry #%d of AP config file, "
                        "using default AP tunnel MAC address\n", entry_num);
                ether_addr_copy(&(addr_params->vap_tun_def_mac), &tun_mac);
            }

            status = entry_add(bssid_mac, tun_mac, tun_ip, tun_port);
        } else {
            RTE_LOG(DEBUG, RWPA_AP_CONFIG,
                    "Invalid BSSID in entry #%d of AP config file\n", entry_num);
        }
    }

    return status;
}

void
ap_config_init(int socket_id,
               struct app_addr_params *app_addr_params)
{
    char name[RTE_HASH_NAMESIZE] = "ap_config_store";
    FILE *fp;
    char entry[1024];
    uint32_t entry_num = 0;

#ifndef RWPA_DYNAMIC_AP_CONF_UPDATE_OFF
    RTE_LOG(INFO, RWPA_AP_CONFIG,
            "Loading AP config from %s but dynamic updates are ON so addresses "
            "will be updated from data in tunnel headers\n",
            app_addr_params->ap_config_file);
#else
    RTE_LOG(INFO, RWPA_AP_CONFIG,
            "Loading AP config from %s\n",
            app_addr_params->ap_config_file);
#endif

    struct rte_hash_parameters ap_config_hash_params = {
            .name = name,
            .entries = NUM_VAP_MAX,
            .socket_id = socket_id,
            .key_len = sizeof(struct ether_addr)
    };

    ap_config_store = rte_hash_create(&ap_config_hash_params);
    if (ap_config_store == NULL)
        rte_panic("Error creating AP config store, exiting\n");

    memset(&ap_config, 0x0, sizeof(ap_config));

    addr_params = app_addr_params;

    fp = fopen(addr_params->ap_config_file, "r");
    if (fp) {
        while (fgets(entry, sizeof(entry), fp)) {
            entry_num++;
            if (conf_entry_parse(entry, entry_num) != 0)
                RTE_LOG(WARNING, RWPA_AP_CONFIG,
                        "Could not add entry #%d to AP config store\n", entry_num);
        }
        fclose(fp);
    }
}

uint8_t
ap_config_get(struct ether_addr bssid,
              struct ether_addr *ap_tun_mac,
              uint32_t *ap_tun_ip,
              uint16_t *ap_tun_port)
{
    int32_t index;

    index = rte_hash_lookup(ap_config_store, &bssid);
    if (likely(index >= 0)) {
        *ap_tun_mac = ap_config[index].tun_mac;
        *ap_tun_ip = ap_config[index].tun_ip;
        *ap_tun_port = ap_config[index].tun_port;
        return 0;
    } else
        return 1;
}

void
ap_config_cleanup(void)
{
   rte_hash_free(ap_config_store);
}
