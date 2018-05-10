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

#include <getopt.h>
#include <unistd.h>

#include <rte_errno.h>
#include <rte_cfgfile.h>
#include <rte_string_fns.h>

#include "app.h"
#include "parser.h"

/**
 * Default config values
 **/

static struct app_params app_params_default = {
    .config_file = "../config/default.cfg",
    .log_level = RTE_LOG_INFO,
    .port_mask = 3,

    .eal_params = {
        .channels = 4,
    },
};

static const struct app_mempool_params mempool_params_default = {
    .parsed = 0,
    .buffer_size = 2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM,
    .pool_size = 32 * 1024,
    .cache_size = 256,
    .cpu_socket_id = 0,
};

static const struct app_link_params link_params_default = {
    .parsed = 0,
    .pmd_id = 0,
    .rss_qs = {0},
    .n_rss_qs = 0,
    .state = 0,
    .ip = 0,
    .depth = 0,
    .mac_addr = { .addr_bytes={0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},

    .conf = {
        .link_speeds = 0,
        .rxmode = {
            .mq_mode = ETH_MQ_RX_NONE,

            .header_split   = 0, /* Header split */
            .hw_ip_checksum = 0, /* IP checksum offload */
            .hw_vlan_filter = 0, /* VLAN filtering */
            .hw_vlan_strip  = 0, /* VLAN strip */
            .hw_vlan_extend = 0, /* Extended VLAN */
            .jumbo_frame    = 1, /* Jumbo frame support */
            .hw_strip_crc   = 1, /* CRC strip by HW */
            .enable_scatter = 0, /* Scattered packets RX handler */

            .max_rx_pkt_len = 2000, /* Jumbo frame max packet len */
            .split_hdr_size = 0, /* Header split buffer size */
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL,
                .rss_key_len = 40,
                .rss_hf = 0,
            },
        },
        .txmode = {
            .mq_mode = ETH_MQ_TX_NONE,
        },
    },

    .promisc = 1,
};

static const struct app_pktq_hwq_in_params default_hwq_in_params = {
    .parsed = 0,
    .mempool_id = 0,
    .size = 128,
    .burst = 32,

    .conf = {
        .rx_thresh = {
            .pthresh = 8,
            .hthresh = 8,
            .wthresh = 4,
        },
        .rx_free_thresh = 64,
        .rx_drop_en = 0,
        .rx_deferred_start = 0,
    }
};

static const struct app_pktq_hwq_out_params default_hwq_out_params = {
    .parsed = 0,
    .size = 512,
    .burst = 32,
    .dropless = 0,
    .n_retries = 0,

    .conf = {
        .tx_thresh = {
            .pthresh = 36,
            .hthresh = 0,
            .wthresh = 0,
        },
        .tx_rs_thresh = 0,
        .tx_free_thresh = 0,
        .txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS |
            ETH_TXQ_FLAGS_NOOFFLOADS,
        .tx_deferred_start = 0,
    }
};

struct app_thread_params default_thread_params = {
    .parsed = 0,
    .socket_id = 0,
    .core_id = 0,
    .hyper_th_id = 0,
    .crypto_qp = 0,
    .n_args = 0,
};

struct app_stat_params default_stat_params = {
    .parsed = 0,
    .timer_period = 0,
    .stats_level = 0,
    .stats_refresh_period_global_ms = 1000,
    .stats_print_period_ms = 1000,
};

struct app_crypto_params default_crypto_params = {
    .type = CDEV_TYPE_SW,
    .cdev_type_string = "SW",
    .cryptodev_mask = 1,
    .n_qp = 2,
};

struct app_addr_params default_addr_params = {
    .vnfd_port_to_ap = 38105,
    .vnfd_ip_to_ap = IPv4(192,168,0,0),
    .vnfd_ip_to_wag = IPv4(192,168,0,0),
    .vnfc_tls_ss_ip = IPv4(192,168,0,0),
    .vnfc_tls_ss_port = 20000,
    .wag_tun_ip = IPv4(192,168,0,0),
    .wag_tun_mac = { .addr_bytes={0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    .vap_tun_def_mac = { .addr_bytes={0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    .vap_tun_def_ip = IPv4(192,168,0,0),
    .vap_tun_def_port = 0,
    .ap_config_file = "/tmp/ap.conf",
};

struct app_misc_params default_misc_params = {
    .uplink_pmd_us = 199,
    .uplink_tls_us = 1,
    .preloaded_key_store = "../config/stations.txt",
    .certs_dir = "../certs/",
    .certs_password = "MadCowBetaRelease",
    .max_vap_frag_sz = 1432,
    .frag_ttl_ms = 1000,
    .no_wag = 0,
};

typedef void (*config_section_load)(struct app_params *p, const char *section_name, struct rte_cfgfile *cfg);

static const char app_usage[] =
"Usage: %s [-f CONFIG_FILE] [-p PORT_MASK] [-l LOG_LEVEL]\n"
"\n"
"Arguments:\n"
"\t-f CONFIG_FILE: Default config file is %s\n"
"\t-p PORT_MASK: Mask of NIC port IDs in hex format (generated from config file when not provided)\n"
"\t-l LOG_LEVEL: 0 = NONE, 1 = HIGH PRIO (default), 2 = LOW PRIO\n"
"\n";

static void
app_print_usage(char *prgname)
{
    rte_exit(0, app_usage, prgname,
             app_params_default.config_file);
}

#define APP_PARAM_ADD(set, key)                                          \
({                                                                       \
     ssize_t pos = APP_PARAM_FIND(set, key);                             \
     ssize_t size = RTE_DIM(set);                                        \
                                                                         \
     if (pos < 0) {                                                      \
     for (pos = 0; pos < size; pos++) {                                  \
     if (!APP_PARAM_VALID(&((set)[pos])))                                \
     break;                                                              \
     }                                                                   \
                                                                         \
     APP_CHECK((pos < size),                                             \
             "Parse error: size of %s is limited to %u elements",        \
#set, (uint32_t) size);                                                  \
                                                                         \
     (set)[pos].name = strdup(key);                                      \
     APP_CHECK(((set)[pos].name),                                        \
             "Parse error: no free memory");                             \
     }                                                                   \
     pos;                                                                \
})

#define APP_PARAM_ADD_LINK_FOR_RXQ(app, rxq_name)                        \
({                                                                       \
     char link_name[APP_PARAM_NAME_SIZE];                                \
     ssize_t link_param_pos;                                             \
     uint32_t link_id, queue_id;                                         \
     sscanf((rxq_name), "RXQ%" SCNu32 ".%" SCNu32, &link_id, &queue_id); \
     sprintf(link_name, "LINK%" PRIu32, link_id);                        \
     link_param_pos = APP_PARAM_ADD((app)->link_params, link_name);      \
     link_param_pos;                                                     \
})

#define APP_PARAM_ADD_LINK_FOR_TXQ(app, txq_name)                        \
({                                                                       \
     char link_name[APP_PARAM_NAME_SIZE];                                \
     ssize_t link_param_pos;                                             \
     uint32_t link_id, queue_id;                                         \
     sscanf((txq_name), "TXQ%" SCNu32 ".%" SCNu32, &link_id, &queue_id); \
     sprintf(link_name, "LINK%" PRIu32, link_id);                        \
     link_param_pos = APP_PARAM_ADD((app)->link_params, link_name);      \
     link_param_pos;                                                     \
})

#define APP_PARAM_ADD_LINK_FOR_TM(app, tm_name)                          \
({                                                                       \
     char link_name[APP_PARAM_NAME_SIZE];                                \
     ssize_t link_param_pos;                                             \
     uint32_t link_id;                                                   \
     sscanf((tm_name), "TM%" SCNu32, &link_id);                          \
     sprintf(link_name, "LINK%" PRIu32, link_id);                        \
     link_param_pos = APP_PARAM_ADD((app)->link_params, link_name);      \
     link_param_pos;                                                     \
})

#define PARSE_CHECK_DUPLICATE_SECTION(obj)                               \
    do {                                                                 \
        APP_CHECK(((obj)->parsed == 0),                                  \
                "Parse error: duplicate \"%s\" section", (obj)->name);   \
        (obj)->parsed++;                                                 \
    } while (0)

#define PARSE_CHECK_DUPLICATE_SECTION_EAL(obj)                           \
    do {                                                                 \
        APP_CHECK(((obj)->parsed == 0),                                  \
                "Parse error: duplicate \"%s\" section", "EAL");         \
        (obj)->parsed++;                                                 \
    } while (0)

#define PARSE_ERROR(exp, section, entry)                                 \
    APP_CHECK(exp, "Parse error in section \"%s\": entry \"%s\"", section, entry)

#define PARSE_ERROR_MESSAGE(exp, section, entry, message)                \
    APP_CHECK(exp, "Parse error in section \"%s\", entry \"%s\": %s", section, entry, message)

#define PARSE_ERROR_NO_ELEMENTS(exp, section, entry)                     \
    APP_CHECK(exp, "Parse error in section \"%s\", entry \"%s\": no elements detected",  section, entry)

#define PARSE_ERROR_TOO_MANY_ELEMENTS(exp, section, entry, max)          \
    APP_CHECK(exp, "Parse error in section \"%s\", entry \"%s\": maximum number of elements allowed is %u", section, entry, max)

#define PARSE_ERROR_INVALID_ELEMENT(exp, section, entry, value)          \
    APP_CHECK(exp, "Parse error in section \"%s\", entry \"%s\": Invalid element value \"%s\"",  section, entry, value)

#define PARSE_ERROR_MALLOC(exp)                                          \
    APP_CHECK(exp, "Parse error: no free memory")

#define PARSE_ERROR_SECTION(exp, section)                                \
    APP_CHECK(exp, "Parse error in section \"%s\"", section)

#define PARSE_ERROR_SECTION_NO_ENTRIES(exp, section)                     \
    APP_CHECK(exp, "Parse error in section \"%s\": no entries", section)

#define PARSE_WARNING_IGNORED(exp, section, entry)                       \
    do                                                                   \
        if (!(exp))                                                      \
            fprintf(stderr, "Parse warning in section \"%s\": "          \
                    "entry \"%s\" is ignored", section, entry);          \
    while (0)

#define PARSE_ERROR_INVALID(exp, section, entry)                         \
    APP_CHECK(exp, "Parse error in section \"%s\": unrecognized entry \"%s\"", section, entry)

#define PARSE_ERROR_DUPLICATE(exp, section, entry) \
    APP_CHECK(exp, "Parse error in section \"%s\": duplicate entry \"%s\"", section, entry)

static int
validate_name(const char *name, const char *prefix, int num)
{
    size_t i, j;

    for (i = 0; (name[i] != '\0') && (prefix[i] != '\0'); i++) {
        if (name[i] != prefix[i])
            return -1;
    }

    if (prefix[i] != '\0')
        return -1;

    if (!num) {
        if (name[i] != '\0')
            return -1;
        else
            return 0;
    }

    if (num == 2) {
        j = skip_digits(&name[i]);
        i += j;
        if ((j == 0) || (name[i] != '.'))
            return -1;
        i++;
    }

    if (num == 1) {
        j = skip_digits(&name[i]);
        i += j;
        if ((j == 0) || (name[i] != '\0'))
            return -1;
    }

    return 0;
}


static void
parse_eal(struct app_params *app, const char *section_name, struct rte_cfgfile *cfg)
{
    struct app_eal_params *p = &app->eal_params;
    struct rte_cfgfile_entry *entries;
    int n_entries, i;

    n_entries = rte_cfgfile_section_num_entries(cfg, section_name);
    PARSE_ERROR_SECTION_NO_ENTRIES((n_entries > 0), section_name);

    entries = malloc(n_entries * sizeof(struct rte_cfgfile_entry));
    PARSE_ERROR_MALLOC(entries != NULL);

    rte_cfgfile_section_entries(cfg, section_name, entries, n_entries);

    PARSE_CHECK_DUPLICATE_SECTION_EAL(p);

    for (i = 0; i < n_entries; i++) {
        struct rte_cfgfile_entry *entry = &entries[i];

        /* coremask */
        if (strcmp(entry->name, "c") == 0) {
            PARSE_WARNING_IGNORED(0, section_name, entry->name);
            continue;
        }

        /* corelist */
        if (strcmp(entry->name, "l") == 0) {
            PARSE_WARNING_IGNORED(0, section_name, entry->name);
            continue;
        }

        /* coremap */
        if (strcmp(entry->name, "lcores") == 0) {
            PARSE_ERROR_DUPLICATE((p->coremap == NULL), section_name, entry->name);
            p->coremap = strdup(entry->value);
            continue;
        }

        /* master_lcore */
        if (strcmp(entry->name, "master_lcore") == 0) {
            int status;

            PARSE_ERROR_DUPLICATE((p->master_lcore_present == 0), section_name, entry->name);
            p->master_lcore_present = 1;

            status = parser_read_uint32(&p->master_lcore, entry->value);
            PARSE_ERROR((status == 0), section_name, entry->name);
            continue;
        }

        /* channels */
        if (strcmp(entry->name, "n") == 0) {
            int status;

            PARSE_ERROR_DUPLICATE((p->channels_present == 0), section_name, entry->name);
            p->channels_present = 1;

            status = parser_read_uint32(&p->channels, entry->value);
            PARSE_ERROR((status == 0), section_name, entry->name);
            continue;
        }

        /* memory */
        if (strcmp(entry->name, "m") == 0) {
            int status;

            PARSE_ERROR_DUPLICATE((p->memory_present == 0), section_name, entry->name);
            p->memory_present = 1;

            status = parser_read_uint32(&p->memory, entry->value);
            PARSE_ERROR((status == 0), section_name, entry->name);
            continue;
        }

        /* ranks */
        if (strcmp(entry->name, "r") == 0) {
            int status;

            PARSE_ERROR_DUPLICATE((p->ranks_present == 0), section_name, entry->name);
            p->ranks_present = 1;

            status = parser_read_uint32(&p->ranks, entry->value);
            PARSE_ERROR((status == 0), section_name, entry->name);
            continue;
        }

        /* pci_blacklist */
        if ((strcmp(entry->name, "pci_blacklist") == 0) || (strcmp(entry->name, "b") == 0)) {
            uint32_t i;

            for (i = 0; i < APP_MAX_LINKS; i++) {
                if (p->pci_blacklist[i])
                    continue;

                p->pci_blacklist[i] = strdup(entry->value);
                PARSE_ERROR_MALLOC(p->pci_blacklist[i]);

                break;
            }

            PARSE_ERROR_MESSAGE((i < APP_MAX_LINKS), section_name, entry->name, "too many elements");
            continue;
        }

        /* pci_whitelist */
        if ((strcmp(entry->name, "pci_whitelist") == 0) || (strcmp(entry->name, "w") == 0)) {
            uint32_t i;

            PARSE_ERROR_MESSAGE((app->port_mask != 0),
                    section_name, entry->name, "entry to be generated by the application (port_mask not provided)");

            for (i = 0; i < APP_MAX_LINKS; i++) {
                if (p->pci_whitelist[i])
                    continue;

                p->pci_whitelist[i] = strdup(entry->value);
                PARSE_ERROR_MALLOC(p->pci_whitelist[i]);

                break;
            }

            PARSE_ERROR_MESSAGE((i < APP_MAX_LINKS), section_name, entry->name, "too many elements");
            continue;
        }

        /* vdev */
        if (strcmp(entry->name, "vdev") == 0) {
            uint32_t i;

            for (i = 0; i < APP_MAX_LINKS; i++) {
                if (p->vdev[i])
                    continue;

                p->vdev[i] = strdup(entry->value);
                PARSE_ERROR_MALLOC(p->vdev[i]);

                break;
            }

            PARSE_ERROR_MESSAGE((i < APP_MAX_LINKS), section_name, entry->name, "too many elements");
            continue;
        }

        /* vmware_tsc_map */
        if (strcmp(entry->name, "vmware_tsc_map") == 0) {
            int val;

            PARSE_ERROR_DUPLICATE((p->vmware_tsc_map_present == 0), section_name, entry->name);
            p->vmware_tsc_map_present = 1;

            val = parser_read_arg_bool(entry->value);
            PARSE_ERROR((val >= 0), section_name, entry->name);
            p->vmware_tsc_map = val;
            continue;
        }

        /* proc_type */
        if (strcmp(entry->name, "proc_type") == 0) {
            PARSE_ERROR_DUPLICATE((p->proc_type == NULL), section_name, entry->name);
            p->proc_type = strdup(entry->value);
            continue;
        }

        /* syslog */
        if (strcmp(entry->name, "syslog") == 0) {
            PARSE_ERROR_DUPLICATE((p->syslog == NULL), section_name, entry->name);
            p->syslog = strdup(entry->value);
            continue;
        }

        /* log_level */
        if (strcmp(entry->name, "log_level") == 0) {
            int status;

            PARSE_ERROR_DUPLICATE((p->log_level_present == 0),  section_name, entry->name);
            p->log_level_present = 1;

            status = parser_read_uint32(&p->log_level, entry->value);
            PARSE_ERROR((status == 0), section_name, entry->name);
            continue;
        }

        /* version */
        if (strcmp(entry->name, "v") == 0) {
            int val;

            PARSE_ERROR_DUPLICATE((p->version_present == 0), section_name, entry->name);
            p->version_present = 1;

            val = parser_read_arg_bool(entry->value);
            PARSE_ERROR((val >= 0), section_name, entry->name);
            p->version = val;
            continue;
        }

        /* help */
        if ((strcmp(entry->name, "help") == 0) ||
                (strcmp(entry->name, "h") == 0)) {
            int val;

            PARSE_ERROR_DUPLICATE((p->help_present == 0), section_name, entry->name);
            p->help_present = 1;

            val = parser_read_arg_bool(entry->value);
            PARSE_ERROR((val >= 0), section_name, entry->name);
            p->help = val;
            continue;
        }

        /* no_huge */
        if (strcmp(entry->name, "no_huge") == 0) {
            int val;

            PARSE_ERROR_DUPLICATE((p->no_huge_present == 0), section_name, entry->name);
            p->no_huge_present = 1;

            val = parser_read_arg_bool(entry->value);
            PARSE_ERROR((val >= 0), section_name, entry->name);
            p->no_huge = val;
            continue;
        }

        /* no_pci */
        if (strcmp(entry->name, "no_pci") == 0) {
            int val;

            PARSE_ERROR_DUPLICATE((p->no_pci_present == 0), section_name, entry->name);
            p->no_pci_present = 1;

            val = parser_read_arg_bool(entry->value);
            PARSE_ERROR((val >= 0), section_name, entry->name);
            p->no_pci = val;
            continue;
        }

        /* no_hpet */
        if (strcmp(entry->name, "no_hpet") == 0) {
            int val;

            PARSE_ERROR_DUPLICATE((p->no_hpet_present == 0), section_name, entry->name);
            p->no_hpet_present = 1;

            val = parser_read_arg_bool(entry->value);
            PARSE_ERROR((val >= 0), section_name, entry->name);
            p->no_hpet = val;
            continue;
        }

        /* no_shconf */
        if (strcmp(entry->name, "no_shconf") == 0) {
            int val;

            PARSE_ERROR_DUPLICATE((p->no_shconf_present == 0), section_name, entry->name);
            p->no_shconf_present = 1;

            val = parser_read_arg_bool(entry->value);
            PARSE_ERROR((val >= 0), section_name, entry->name);
            p->no_shconf = val;
            continue;
        }

        /* add_driver */
        if (strcmp(entry->name, "d") == 0) {
            PARSE_ERROR_DUPLICATE((p->add_driver == NULL), section_name, entry->name);
            p->add_driver = strdup(entry->value);
            continue;
        }

        /* socket_mem */
        if (strcmp(entry->name, "socket_mem") == 0) {
            PARSE_ERROR_DUPLICATE((p->socket_mem == NULL), section_name, entry->name);
            p->socket_mem = strdup(entry->value);
            continue;
        }

        /* huge_dir */
        if (strcmp(entry->name, "huge_dir") == 0) {
            PARSE_ERROR_DUPLICATE((p->huge_dir == NULL), section_name, entry->name);
            p->huge_dir = strdup(entry->value);
            continue;
        }

        /* file_prefix */
        if (strcmp(entry->name, "file_prefix") == 0) {
            PARSE_ERROR_DUPLICATE((p->file_prefix == NULL), section_name, entry->name);
            p->file_prefix = strdup(entry->value);
            continue;
        }

        /* base_virtaddr */
        if (strcmp(entry->name, "base_virtaddr") == 0) {
            PARSE_ERROR_DUPLICATE((p->base_virtaddr == NULL), section_name, entry->name);
            p->base_virtaddr = strdup(entry->value);
            continue;
        }

        /* create_uio_dev */
        if (strcmp(entry->name, "create_uio_dev") == 0) {
            int val;

            PARSE_ERROR_DUPLICATE((p->create_uio_dev_present == 0), section_name, entry->name);
            p->create_uio_dev_present = 1;

            val = parser_read_arg_bool(entry->value);
            PARSE_ERROR((val >= 0), section_name, entry->name);
            p->create_uio_dev = val;
            continue;
        }

        /* vfio_intr */
        if (strcmp(entry->name, "vfio_intr") == 0) {
            PARSE_ERROR_DUPLICATE((p->vfio_intr == NULL), section_name, entry->name);
            p->vfio_intr = strdup(entry->value);
            continue;
        }

        /* xen_dom0 */
        if (strcmp(entry->name, "xen_dom0") == 0) {
            int val;

            PARSE_ERROR_DUPLICATE((p->xen_dom0_present == 0), section_name, entry->name);
            p->xen_dom0_present = 1;

            val = parser_read_arg_bool(entry->value);
            PARSE_ERROR((val >= 0), section_name, entry->name);
            p->xen_dom0 = val;
            continue;
        }

        /* unrecognized */
        PARSE_ERROR_INVALID(0, section_name, entry->name);
    }

    free(entries);
}

static void
parse_mempool(struct app_params *app, const char *section_name, struct rte_cfgfile *cfg)
{
    struct app_mempool_params *param;
    struct rte_cfgfile_entry *entries;
    ssize_t param_idx;
    int n_entries, i;

    n_entries = rte_cfgfile_section_num_entries(cfg, section_name);
    PARSE_ERROR_SECTION_NO_ENTRIES((n_entries > 0), section_name);

    entries = malloc(n_entries * sizeof(struct rte_cfgfile_entry));
    PARSE_ERROR_MALLOC(entries != NULL);

    rte_cfgfile_section_entries(cfg, section_name, entries, n_entries);

    param_idx = APP_PARAM_ADD(app->mempool_params, section_name);
    param = &app->mempool_params[param_idx];
    PARSE_CHECK_DUPLICATE_SECTION(param);

    for (i = 0; i < n_entries; i++) {
        struct rte_cfgfile_entry *ent = &entries[i];

        if (strcmp(ent->name, "buffer_size") == 0) {
            int status = parser_read_uint32(&param->buffer_size, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "pool_size") == 0) {
            int status = parser_read_uint32(&param->pool_size, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "cache_size") == 0) {
            int status = parser_read_uint32(&param->cache_size, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "cpu") == 0) {
            int status = parser_read_uint32(&param->cpu_socket_id, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        /* unrecognized */
        PARSE_ERROR_INVALID(0, section_name, ent->name);
    }

    free(entries);
}


static int
parse_link_rss_qs(struct app_link_params *p, char *value)
{
    p->n_rss_qs = 0;

    while (1) {
        char *token = strtok_r(value, PARSE_DELIMITER, &value);

        if (token == NULL)
            break;

        if (p->n_rss_qs == RTE_DIM(p->rss_qs))
            return -ENOMEM;

        if (parser_read_uint32(&p->rss_qs[p->n_rss_qs++], token))
            return -EINVAL;
    }

    return 0;
}

static void
parse_link(struct app_params *app, const char *section_name, struct rte_cfgfile *cfg)
{
    struct app_link_params *param;
    struct rte_cfgfile_entry *entries;
    int n_entries, i;
    ssize_t param_idx;
    //int rss_qs_present = 0;

    n_entries = rte_cfgfile_section_num_entries(cfg, section_name);
    PARSE_ERROR_SECTION_NO_ENTRIES((n_entries > 0), section_name);

    entries = malloc(n_entries * sizeof(struct rte_cfgfile_entry));
    PARSE_ERROR_MALLOC(entries != NULL);

    rte_cfgfile_section_entries(cfg, section_name, entries, n_entries);

    param_idx = APP_PARAM_ADD(app->link_params, section_name);
    param = &app->link_params[param_idx];
    PARSE_CHECK_DUPLICATE_SECTION(param);

    for (i = 0; i < n_entries; i++) {
        struct rte_cfgfile_entry *ent = &entries[i];

        if (strcmp(ent->name, "promisc") == 0) {
            int status = parser_read_arg_bool(ent->value);

            PARSE_ERROR((status != -EINVAL), section_name, ent->name);
            param->promisc = status;
            continue;
        }

        if (strcmp(ent->name, "rss_qs") == 0) {
            int status = parse_link_rss_qs(param, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            //rss_qs_present = 1;
            continue;
        }

        if (strcmp(ent->name, "mac_addr") == 0) {
            int status = parse_mac_addr(ent->value, &param->mac_addr);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        /* unrecognized */
        PARSE_ERROR_INVALID(0, section_name, ent->name);
    }

    free(entries);
}


static void
parse_rxq(struct app_params *app, const char *section_name, struct rte_cfgfile *cfg)
{
    struct app_pktq_hwq_in_params *param;
    struct rte_cfgfile_entry *entries;
    int n_entries, i;
    ssize_t param_idx;

    n_entries = rte_cfgfile_section_num_entries(cfg, section_name);
    PARSE_ERROR_SECTION_NO_ENTRIES((n_entries > 0), section_name);

    entries = malloc(n_entries * sizeof(struct rte_cfgfile_entry));
    PARSE_ERROR_MALLOC(entries != NULL);

    rte_cfgfile_section_entries(cfg, section_name, entries, n_entries);

    param_idx = APP_PARAM_ADD(app->hwq_in_params, section_name);
    param = &app->hwq_in_params[param_idx];
    PARSE_CHECK_DUPLICATE_SECTION(param);

    APP_PARAM_ADD_LINK_FOR_RXQ(app, section_name);

    for (i = 0; i < n_entries; i++) {
        struct rte_cfgfile_entry *ent = &entries[i];

        if (strcmp(ent->name, "mempool") == 0) {
            int status = validate_name(ent->value, "MEMPOOL", 1);
            ssize_t idx;

            PARSE_ERROR((status == 0), section_name, ent->name);

            idx = APP_PARAM_ADD(app->mempool_params, ent->value);
            param->mempool_id = idx;
            continue;
        }

        if (strcmp(ent->name, "size") == 0) {
            int status = parser_read_uint32(&param->size, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "burst") == 0) {
            int status = parser_read_uint32(&param->burst, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        /* unrecognized */
        PARSE_ERROR_INVALID(0, section_name, ent->name);
    }

    free(entries);
}

static void
parse_txq(struct app_params *app, const char *section_name, struct rte_cfgfile *cfg)
{
    struct app_pktq_hwq_out_params *param;
    struct rte_cfgfile_entry *entries;
    int n_entries, i;
    ssize_t param_idx;

    n_entries = rte_cfgfile_section_num_entries(cfg, section_name);
    PARSE_ERROR_SECTION_NO_ENTRIES((n_entries > 0), section_name);

    entries = malloc(n_entries * sizeof(struct rte_cfgfile_entry));
    PARSE_ERROR_MALLOC(entries != NULL);

    rte_cfgfile_section_entries(cfg, section_name, entries, n_entries);

    param_idx = APP_PARAM_ADD(app->hwq_out_params, section_name);
    param = &app->hwq_out_params[param_idx];
    PARSE_CHECK_DUPLICATE_SECTION(param);

    APP_PARAM_ADD_LINK_FOR_TXQ(app, section_name);

    for (i = 0; i < n_entries; i++) {
        struct rte_cfgfile_entry *ent = &entries[i];

        if (strcmp(ent->name, "size") == 0) {
            int status = parser_read_uint32(&param->size, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "burst") == 0) {
            int status = parser_read_uint32(&param->burst, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "dropless") == 0) {
            int status = parser_read_arg_bool(ent->value);

            PARSE_ERROR((status != -EINVAL), section_name, ent->name);
            param->dropless = status;
            continue;
        }

        if (strcmp(ent->name, "n_retries") == 0) {
            int status = parser_read_uint64(&param->n_retries, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        /* unrecognized */
        PARSE_ERROR_INVALID(0, section_name, ent->name);
    }

    free(entries);
}

static void
parse_stat(struct app_params *app, const char *section_name, struct rte_cfgfile *cfg)
{
    struct app_stat_params *p = &app->stat_params;
    struct rte_cfgfile_entry *entries;
    int n_entries, i;

    n_entries = rte_cfgfile_section_num_entries(cfg, section_name);
    PARSE_ERROR_SECTION_NO_ENTRIES((n_entries > 0), section_name);

    entries = malloc(n_entries * sizeof(struct rte_cfgfile_entry));
    PARSE_ERROR_MALLOC(entries != NULL);

    rte_cfgfile_section_entries(cfg, section_name, entries, n_entries);

    PARSE_CHECK_DUPLICATE_SECTION_EAL(p);

    for (i = 0; i < n_entries; i++) {
        struct rte_cfgfile_entry *entry = &entries[i];

        if (strcmp(entry->name, "timer_period") == 0) {
            int status = parser_read_uint64(&p->timer_period, entry->value);
            PARSE_ERROR((status == 0), section_name, entry->name);
            continue;
        }

        if (strcmp(entry->name, "stats_level") == 0) {
            int status = parser_read_uint32(&p->stats_level,
                                            entry->value);
            PARSE_ERROR((status == 0), section_name, entry->name);
            continue;
        }

        if (strcmp(entry->name, "stats_refresh_period_global_ms") == 0) {
            int status = parser_read_uint32(&p->stats_refresh_period_global_ms,
                                            entry->value);
            PARSE_ERROR((status == 0), section_name, entry->name);
            continue;
        }

        if (strcmp(entry->name, "stats_print_period_ms") == 0) {
            int status = parser_read_uint32(&p->stats_print_period_ms,
                                            entry->value);
            PARSE_ERROR((status == 0), section_name, entry->name);
            continue;
        }

        /* unrecognized */
        PARSE_ERROR_INVALID(0, section_name, entry->name);
    }

    free(entries);
}

struct config_section {
    const char prefix[CFG_NAME_LEN];
    int numbers;
    config_section_load load;
};

static void
parse_pipeline_pktq_in(struct app_params *app, struct app_thread_params *p, char *value)
{
    p->n_pktq_in = 0;

    while (1) {
        enum app_pktq_in_type type;
        int id;
        char *name = strtok_r(value, PARSE_DELIMITER, &value);

        if (name == NULL)
            break;

        PARSE_ERROR_TOO_MANY_ELEMENTS((p->n_pktq_in < RTE_DIM(p->pktq_in)),
                                      p->name, "pktq_in",
                                      (uint32_t)RTE_DIM(p->pktq_in));

        if (validate_name(name, "RXQ", 2) == 0) {
            type = APP_PKTQ_IN_HWQ;
            id = APP_PARAM_ADD(app->hwq_in_params, name);
            APP_PARAM_ADD_LINK_FOR_RXQ(app, name);
        }
        else
            PARSE_ERROR_INVALID_ELEMENT(0, p->name, "pktq_in", name);

        p->pktq_in[p->n_pktq_in].type = type;
        p->pktq_in[p->n_pktq_in].id = (uint32_t) id;
        p->n_pktq_in++;
    }

    PARSE_ERROR_NO_ELEMENTS((p->n_pktq_in > 0), p->name, "pktq_in");
}

static void
parse_pipeline_pktq_out(struct app_params *app,
        struct app_thread_params *p,
        char *value)
{
    p->n_pktq_out = 0;

    while (1) {
        enum app_pktq_out_type type;
        int id;
        char *name = strtok_r(value, PARSE_DELIMITER, &value);

        if (name == NULL)
            break;

        PARSE_ERROR_TOO_MANY_ELEMENTS((p->n_pktq_out < RTE_DIM(p->pktq_out)),
                                      p->name, "pktq_out", (uint32_t)RTE_DIM(p->pktq_out));

        if (validate_name(name, "TXQ", 2) == 0) {
            type = APP_PKTQ_OUT_HWQ;
            id = APP_PARAM_ADD(app->hwq_out_params, name);
            APP_PARAM_ADD_LINK_FOR_TXQ(app, name);
        } else {
            PARSE_ERROR_INVALID_ELEMENT(0, p->name, "pktq_out", name);
        }

        p->pktq_out[p->n_pktq_out].type = type;
        p->pktq_out[p->n_pktq_out].id = id;
        p->n_pktq_out++;
    }

    PARSE_ERROR_NO_ELEMENTS((p->n_pktq_out > 0), p->name, "pktq_out");
}

static void
parse_thread(struct app_params *app, const char *section_name, struct rte_cfgfile *cfg)
{
    struct app_thread_params *param;
    struct rte_cfgfile_entry *entries;
    ssize_t param_idx;
    int n_entries, i;

    n_entries = rte_cfgfile_section_num_entries(cfg, section_name);
    PARSE_ERROR_SECTION_NO_ENTRIES((n_entries > 0), section_name);

    entries = malloc(n_entries * sizeof(struct rte_cfgfile_entry));
    PARSE_ERROR_MALLOC(entries != NULL);

    rte_cfgfile_section_entries(cfg, section_name, entries, n_entries);

    param_idx = APP_PARAM_ADD(app->thread_params, section_name);
    param = &app->thread_params[param_idx];
    PARSE_CHECK_DUPLICATE_SECTION(param);

    for (i = 0; i < n_entries; i++) {
        struct rte_cfgfile_entry *ent = &entries[i];

        if (strcmp(ent->name, "type") == 0) {
            int w_size = snprintf(param->type, RTE_DIM(param->type), "%s", ent->value);

            PARSE_ERROR(((w_size > 0) && (w_size < (int)RTE_DIM(param->type))), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "core") == 0) {
            int status = parse_thread_core(&param->socket_id, &param->core_id, &param->hyper_th_id, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "pktq_in") == 0) {
            parse_pipeline_pktq_in(app, param, ent->value);
            continue;
        }

        if (strcmp(ent->name, "pktq_out") == 0) {
            parse_pipeline_pktq_out(app, param, ent->value);
            continue;
        }

        if (strcmp(ent->name, "crypto_qp") == 0) {
            int status = parser_read_uint16(&param->crypto_qp, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        /* Thread type specific items */
        APP_CHECK((param->n_args < APP_MAX_THREAD_ARGS), "Parse error in section \"%s\": too many thread specified parameters", section_name);

        param->args_name[param->n_args] = strdup(ent->name);
        param->args_value[param->n_args] = strdup(ent->value);

        APP_CHECK((param->args_name[param->n_args] != NULL) && (param->args_value[param->n_args] != NULL), "Parse error: no free memory");

        param->n_args++;
    }

    free(entries);
}

static void
parse_addresses(struct app_params *app, const char *section_name, struct rte_cfgfile *cfg)
{
    struct app_addr_params *param = &app->addr_params;
    struct rte_cfgfile_entry *entries;
    int n_entries, i;

    n_entries = rte_cfgfile_section_num_entries(cfg, section_name);
    PARSE_ERROR_SECTION_NO_ENTRIES((n_entries > 0), section_name);

    entries = malloc(n_entries * sizeof(struct rte_cfgfile_entry));
    PARSE_ERROR_MALLOC(entries != NULL);

    rte_cfgfile_section_entries(cfg, section_name, entries, n_entries);

    for (i = 0; i < n_entries; i++) {
        struct rte_cfgfile_entry *ent = &entries[i];

        if (strcmp(ent->name, "vnfd_port_to_ap") == 0) {
            int status = parser_read_uint16(&param->vnfd_port_to_ap, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "vnfd_ip_to_ap") == 0) {
            int status = parse_ipv4_addr(ent->value, &param->vnfd_ip_to_ap);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "vnfd_ip_to_wag") == 0) {
            int status = parse_ipv4_addr(ent->value, &param->vnfd_ip_to_wag);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "vnfc_tls_ss_ip") == 0) {
            int status = parse_ipv4_addr(ent->value, &param->vnfc_tls_ss_ip);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "vnfc_tls_ss_port") == 0) {
            int status = parser_read_uint16(&param->vnfc_tls_ss_port, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "wag_tun_ip") == 0) {
            int status = parse_ipv4_addr(ent->value, &param->wag_tun_ip);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "wag_tun_mac") == 0) {
            int status = parse_mac_addr(ent->value, &param->wag_tun_mac);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "vap_tun_def_mac") == 0 ) {
            int status = parse_mac_addr(ent->value, &param->vap_tun_def_mac);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "vap_tun_def_ip") == 0 ) {
            int status = parse_ipv4_addr(ent->value, &param->vap_tun_def_ip);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "vap_tun_def_port") == 0) {
            int status = parser_read_uint16(&param->vap_tun_def_port, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "ap_conf") == 0) {
            int status = parse_string(ent->value, param->ap_config_file);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        /* unrecognized */
        PARSE_ERROR_INVALID(0, section_name, ent->name);
    }

     free(entries);
}

static void
parse_miscellaneous(struct app_params *app,
    const char *section_name,
    struct rte_cfgfile *cfg)
{
    struct app_misc_params *param = &app->misc_params;;
    struct rte_cfgfile_entry *entries;
    int n_entries, i;

    n_entries = rte_cfgfile_section_num_entries(cfg, section_name);
    PARSE_ERROR_SECTION_NO_ENTRIES((n_entries > 0), section_name);

    entries = malloc(n_entries * sizeof(struct rte_cfgfile_entry));
    PARSE_ERROR_MALLOC(entries != NULL);

    rte_cfgfile_section_entries(cfg, section_name, entries, n_entries);

    for (i = 0; i < n_entries; i++) {
        struct rte_cfgfile_entry *ent = &entries[i];

        if (strcmp(ent->name, "uplink_pmd_us") == 0) {
            int status = parser_read_uint32(&param->uplink_pmd_us, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "uplink_tls_us") == 0) {
            int status = parser_read_uint32(&param->uplink_tls_us, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "preload_key_store") == 0) {
            int status = parse_string(ent->value, param->preloaded_key_store);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "tls_certs_dir") == 0) {
            int status = parse_string(ent->value, param->certs_dir);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "certs_password") == 0) {
            int status = parse_string(ent->value, param->certs_password);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "max_vap_frag_sz") == 0) {
            int status = parser_read_uint32(&param->max_vap_frag_sz, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "frag_ttl_ms") == 0) {
            int status = parser_read_uint32(&param->frag_ttl_ms, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "no_wag") == 0) {
            int val = parser_read_arg_bool(ent->value);

            PARSE_ERROR((val >= 0), section_name, ent->name);
            param->no_wag = val;
            continue;
        }

        /* unrecognized */
        PARSE_ERROR_INVALID(0, section_name, ent->name);
    }

    free(entries);
}

static void
parse_crypto_params(struct app_params *app,
    const char *section_name,
    struct rte_cfgfile *cfg)
{
    struct app_crypto_params *param = &app->crypto_params;
    struct rte_cfgfile_entry *entries;
    int n_entries, i;

    n_entries = rte_cfgfile_section_num_entries(cfg, section_name);
    PARSE_ERROR_SECTION_NO_ENTRIES((n_entries > 0), section_name);

    entries = malloc(n_entries * sizeof(struct rte_cfgfile_entry));
    PARSE_ERROR_MALLOC(entries != NULL);

    rte_cfgfile_section_entries(cfg, section_name, entries, n_entries);

    for (i = 0; i < n_entries; i++) {
        struct rte_cfgfile_entry *ent = &entries[i];

        if (strcmp(ent->name, "mask") == 0) {
            int status = parser_read_uint64(&param->cryptodev_mask, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        if (strcmp(ent->name, "type") == 0) {
            parse_string(ent->value, param->cdev_type_string);
            if (strcmp(param->cdev_type_string, "SW") == 0)
                param->type = CDEV_TYPE_SW;
            else if (strcmp(param->cdev_type_string, "HW") == 0)
                param->type = CDEV_TYPE_HW;
            else
                param->type = CDEV_TYPE_ANY;

            continue;
        }

        if (strcmp(ent->name, "n_qp") == 0) {
            int status = parser_read_uint16(&param->n_qp, ent->value);

            PARSE_ERROR((status == 0), section_name, ent->name);
            continue;
        }

        /* unrecognized */
        PARSE_ERROR_INVALID(0, section_name, ent->name);
    }

    free(entries);
}

static const struct config_section cfg_file_scheme[] = {
    {"EAL", 0, parse_eal},
    {"THREAD", 1, parse_thread},
    {"MEMPOOL", 1, parse_mempool},
    {"LINK", 1, parse_link},
    {"RXQ", 2, parse_rxq},
    {"TXQ", 2, parse_txq},
    {"STAT", 0, parse_stat},
    {"ADDRESSES", 0, parse_addresses},
    {"CRYPTO", 0, parse_crypto_params},
    {"MISCELLANEOUS", 0, parse_miscellaneous},
};

static void
create_implicit_mempools(struct app_params *app)
{
    APP_PARAM_ADD(app->mempool_params, "MEMPOOL0");
}

static void
create_implicit_links_from_port_mask(struct app_params *app, uint64_t port_mask)
{
    uint32_t pmd_id, link_id;

    link_id = 0;
    for (pmd_id = 0; pmd_id < RTE_MAX_ETHPORTS; pmd_id++) {
        char name[APP_PARAM_NAME_SIZE];
        ssize_t idx;

        if ((port_mask & (1LLU << pmd_id)) == 0)
            continue;

        snprintf(name, sizeof(name), "LINK%" PRIu32, link_id);
        idx = APP_PARAM_ADD(app->link_params, name);

        app->link_params[idx].pmd_id = pmd_id;
        link_id++;
    }
}

int
app_config_parse(struct app_params *app, const char *file_name)
{
    struct rte_cfgfile *cfg;
    char **section_names;
    int i, j, sect_count;

    /* Implicit mempools */
    create_implicit_mempools(app);

    /* Port mask */
    if (app->port_mask)
        create_implicit_links_from_port_mask(app, app->port_mask);

    /* Load application configuration file */
    cfg = rte_cfgfile_load(file_name, 0);
    APP_CHECK((cfg != NULL), "Parse error: Unable to load config file %s", file_name);

    sect_count = rte_cfgfile_num_sections(cfg, NULL, 0);
    APP_CHECK((sect_count > 0), "Parse error: number of sections in file \"%s\" return %d", file_name, sect_count);

    section_names = malloc(sect_count * sizeof(char *));
    PARSE_ERROR_MALLOC(section_names != NULL);

    for (i = 0; i < sect_count; i++)
        section_names[i] = malloc(CFG_NAME_LEN);

    rte_cfgfile_sections(cfg, section_names, sect_count);

    for (i = 0; i < sect_count; i++) {
        const struct config_section *sch_s;
        int len, cfg_name_len;

        cfg_name_len = strlen(section_names[i]);

        /* Find section type */
        for (j = 0; j < (int)RTE_DIM(cfg_file_scheme); j++) {
            sch_s = &cfg_file_scheme[j];
            len = strlen(sch_s->prefix);

            if (cfg_name_len < len)
                continue;

            /*
             * After section name we expect only '\0' or digit or
             * digit dot digit, so protect against false matching,
             * for example: "ABC" should match section name
             * "ABC0.0", but it should not match section_name
             * "ABCDEF".
             */
            if ((section_names[i][len] != '\0') && !isdigit(section_names[i][len]))
                continue;

            if (strncmp(sch_s->prefix, section_names[i], len) == 0)
                break;
        }

        APP_CHECK(j < (int)RTE_DIM(cfg_file_scheme), "Parse error: unknown section %s", section_names[i]);

        APP_CHECK(validate_name(section_names[i], sch_s->prefix, sch_s->numbers) == 0,
                  "Parse error: invalid section name \"%s\"", section_names[i]);

        sch_s->load(app, section_names[i], cfg);
    }

    for (i = 0; i < sect_count; i++)
        free(section_names[i]);

    free(section_names);

    rte_cfgfile_close(cfg);

    APP_PARAM_COUNT(app->mempool_params, app->n_mempools);
    APP_PARAM_COUNT(app->link_params, app->n_links);
    APP_PARAM_COUNT(app->hwq_in_params, app->n_pktq_hwq_in);
    APP_PARAM_COUNT(app->hwq_out_params, app->n_pktq_hwq_out);
    APP_PARAM_COUNT(app->thread_params, app->n_threads);

    return 0;
}


int
app_config_init(struct app_params *app)
{
    size_t i;

    memcpy(app, &app_params_default, sizeof(struct app_params));

    for (i = 0; i < RTE_DIM(app->mempool_params); i++)
        memcpy(&app->mempool_params[i], &mempool_params_default, sizeof(struct app_mempool_params));

    for (i = 0; i < RTE_DIM(app->link_params); i++)
        memcpy(&app->link_params[i], &link_params_default, sizeof(struct app_link_params));

    for (i = 0; i < RTE_DIM(app->hwq_in_params); i++)
        memcpy(&app->hwq_in_params[i], &default_hwq_in_params, sizeof(default_hwq_in_params));

    for (i = 0; i < RTE_DIM(app->hwq_out_params); i++)
        memcpy(&app->hwq_out_params[i], &default_hwq_out_params, sizeof(default_hwq_out_params));

    for (i = 0; i < RTE_DIM(app->thread_params); i++)
        memcpy(&app->thread_params[i], &default_thread_params, sizeof(default_thread_params));

    memcpy(&app->stat_params, &default_stat_params, sizeof(default_stat_params));
    memcpy(&app->crypto_params, &default_crypto_params, sizeof(default_crypto_params));
    memcpy(&app->addr_params, &default_addr_params, sizeof(default_addr_params));
    memcpy(&app->misc_params, &default_misc_params, sizeof(default_misc_params));

    return 0;
}

int
app_config_args(struct app_params *app, int argc, char **argv)
{
    int opt, option_index;
    int f_present, p_present, l_present;
    int scaned = 0;

    static struct option lgopts[] = {
        {NULL, 0, 0, 0}
    };

    /* Copy application name */
    strncpy(app->app_name, argv[0], APP_APPNAME_SIZE - 1);

    f_present = 0;
    p_present = 0;
    l_present = 0;

    while ((opt = getopt_long(argc, argv, "f:p:l:v:", lgopts,  &option_index)) != EOF)
        switch (opt) {
            case 'f':
                if (f_present)
                    rte_panic("Error: Config file is provided more than once\n");
                f_present = 1;

                if (!strlen(optarg))
                    rte_panic("Error: Config file name is null\n");

                app->config_file = strdup(optarg);
                if (app->config_file == NULL)
                    rte_panic("Error: Memory allocation failure\n");

                break;

            case 'p':
                if (p_present)
                    rte_panic("Error: PORT_MASK is provided more than once\n");
                p_present = 1;

                if ((sscanf(optarg, "%" SCNx64 "%n", &app->port_mask, &scaned) != 1) ||
                        ((size_t) scaned != strlen(optarg)))
                    rte_panic("Error: PORT_MASK is not a hexadecimal integer\n");

                if (app->port_mask == 0)
                    rte_panic("Error: PORT_MASK is null\n");

                break;

            case 'l':
                if (l_present)
                    rte_panic("Error: LOG_LEVEL is provided more than once\n");
                l_present = 1;

                if ((sscanf(optarg, "%" SCNu32 "%n", &app->log_level, &scaned) != 1) ||
                        ((size_t) scaned != strlen(optarg)) ||
                        (app->log_level > RTE_LOG_DEBUG))
                    rte_panic("Error: LOG_LEVEL invalid value (%d)\n", app->log_level);

                /* Log level provided on the app command line has priority */
                app->log_level_override = 1;

                break;

            case 0:
                app_print_usage(argv[0]);
                break;

            default:
                app_print_usage(argv[0]);
        }

    optind = 0; /* reset getopt lib */

    return 0;
}

int
app_config_preproc(struct app_params *app)
{
    int status;

    status = access(app->config_file, F_OK | R_OK);
    APP_CHECK((status == 0), "Error: Unable to open file %s", app->config_file);

    return status;
}


static inline uint32_t
link_rxq_used(struct app_link_params *link, uint32_t q_id)
{
    uint32_t i;

    for (i = 0; i < link->n_rss_qs; i++)
        if (link->rss_qs[i] == q_id)
            return 1;

    return 0;
}

static void
check_links(struct app_params *app)
{
    unsigned i;

    /* Check that number of links matches the port mask */
    if (app->port_mask) {
        uint32_t n_links_port_mask = __builtin_popcountll(app->port_mask);

        APP_CHECK((app->n_links == n_links_port_mask), "Not enough links provided in the PORT_MASK\n");
    }

    for (i = 0; i < app->n_links; i++) {
        struct app_link_params *link = &app->link_params[i];
        uint32_t rxq_max, n_rxq, n_txq, link_id, i;

        APP_PARAM_GET_ID(link, "LINK", link_id);

        /* Check that link RXQs are contiguous */
        rxq_max = 0;
        for (i = 0; i < link->n_rss_qs; i++)
            if (link->rss_qs[i] > rxq_max)
                rxq_max = link->rss_qs[i];

        for (i = 1; i <= rxq_max; i++)
            APP_CHECK((link_rxq_used(link, i)), "%s RXQs are not contiguous (A)\n", link->name);

        n_rxq = app_link_get_n_rxq(app, link);

        APP_CHECK((n_rxq), "%s does not have any RXQ\n", link->name);

        APP_CHECK((n_rxq == rxq_max + 1), "%s RXQs are not contiguous (B)\n", link->name);

        for (i = 0; i < n_rxq; i++) {
            char name[APP_PARAM_NAME_SIZE];
            int pos;

            sprintf(name, "RXQ%" PRIu32 ".%" PRIu32, link_id, i);
            pos = APP_PARAM_FIND(app->hwq_in_params, name);
            APP_CHECK((pos >= 0), "%s RXQs are not contiguous (C)\n", link->name);
        }

        /* Check that link TXQs are contiguous */
        n_txq = app_link_get_n_txq(app, link);

        APP_CHECK((n_txq),  "%s does not have any TXQ\n", link->name);

        for (i = 0; i < n_txq; i++) {
            char name[APP_PARAM_NAME_SIZE];
            int pos;

            sprintf(name, "TXQ%" PRIu32 ".%" PRIu32, link_id, i);
            pos = APP_PARAM_FIND(app->hwq_out_params, name);
            APP_CHECK((pos >= 0), "%s TXQs are not contiguous\n", link->name);
        }
    }
}


static void
check_mempools(struct app_params *app)
{
    uint32_t i;

    for (i = 0; i < app->n_mempools; i++) {
        struct app_mempool_params *p = &app->mempool_params[i];

        APP_CHECK((p->pool_size > 0), "Mempool %s size is 0\n", p->name);

        APP_CHECK((p->cache_size > 0), "Mempool %s cache size is 0\n", p->name);

        APP_CHECK(rte_is_power_of_2(p->cache_size), "Mempool %s cache size not a power of 2\n", p->name);
    }
}

static void
check_rxqs(struct app_params *app)
{
    uint32_t i;

    for (i = 0; i < app->n_pktq_hwq_in; i++) {
        struct app_pktq_hwq_in_params *p = &app->hwq_in_params[i];
        uint32_t n_readers = app_rxq_get_readers(app, p);

        APP_CHECK((p->size > 0), "%s size is 0\n", p->name);

        APP_CHECK((rte_is_power_of_2(p->size)), "%s size is not a power of 2\n", p->name);

        APP_CHECK((p->burst > 0), "%s burst size is 0\n", p->name);

        APP_CHECK((p->burst <= p->size), "%s burst size is bigger than its size\n", p->name);

        APP_CHECK((n_readers != 0), "%s has no reader\n", p->name);

        APP_CHECK((n_readers == 1), "%s has more than one reader\n", p->name);
    }
}

static void
check_txqs(struct app_params *app)
{
    uint32_t i;

    for (i = 0; i < app->n_pktq_hwq_out; i++) {
        struct app_pktq_hwq_out_params *p = &app->hwq_out_params[i];
        uint32_t n_writers = app_txq_get_writers(app, p);

        APP_CHECK((p->size > 0), "%s size is 0\n", p->name);

        APP_CHECK((rte_is_power_of_2(p->size)), "%s size is not a power of 2\n", p->name);

        APP_CHECK((p->burst > 0), "%s burst size is 0\n", p->name);

        APP_CHECK((p->burst <= p->size), "%s burst size is bigger than its size\n", p->name);

        APP_CHECK((n_writers != 0), "%s has no writer\n", p->name);

        APP_CHECK((n_writers == 1), "%s has more than one writer\n", p->name);
    }
}

static void
check_crypto(struct app_params *app)
{
    struct app_crypto_params *p = &app->crypto_params;

    APP_CHECK((p->cryptodev_mask > 0), "No devices specified in crypto mask\n");

    APP_CHECK((p->n_qp > 0), "Crypto n_qp is 0\n");
}

static void
check_threads(struct app_params *app)
{
    uint32_t i;

    struct app_crypto_params *cp = &app->crypto_params;

    for (i = 0; i < app->n_threads; i++) {
        struct app_thread_params *tp = &app->thread_params[i];

        APP_CHECK((tp->crypto_qp < cp->n_qp),
                   "%s crypto qp is %d but only %d qp(s) configured\n",
                   tp->name, tp->crypto_qp, cp->n_qp);
    }
}

int
app_config_check(struct app_params *app)
{
    check_mempools(app);
    check_links(app);
    check_rxqs(app);
    check_txqs(app);
    check_crypto(app);
    check_threads(app);
    return 0;
}
