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

#ifndef __INCLUDE_APP_H__
#define __INCLUDE_APP_H__

#include <rte_ethdev.h>
#include <rte_timer.h>

#include "cpu_core_map.h"
#include "thread.h"

#ifndef APP_MAX_LINKS
#define APP_MAX_LINKS                        16
#endif

#ifndef APP_LINK_MAX_HWQ_IN
#define APP_LINK_MAX_HWQ_IN                  128
#endif

#ifndef APP_LINK_MAX_HWQ_OUT
#define APP_LINK_MAX_HWQ_OUT                 128
#endif

#ifndef APP_APPNAME_SIZE
#define APP_APPNAME_SIZE                     256
#endif

#ifndef APP_MAX_MEMPOOLS
#define APP_MAX_MEMPOOLS                     8
#endif

#define APP_MAX_HWQ_IN                       (APP_MAX_LINKS * APP_LINK_MAX_HWQ_IN)

#define APP_MAX_HWQ_OUT                      (APP_MAX_LINKS * APP_LINK_MAX_HWQ_OUT)

#ifndef APP_MAX_PKTQ_SWQ
#define APP_MAX_PKTQ_SWQ                     256
#endif

#ifndef APP_EAL_ARGC
#define APP_EAL_ARGC                         64
#endif

#ifndef MAX_RX_QUEUE_PER_LCORE
#define MAX_RX_QUEUE_PER_LCORE               16
#endif

#ifndef APP_PARAM_NAME_SIZE
#define APP_PARAM_NAME_SIZE                  64
#endif

#ifndef APP_MAX_THREAD_TYPES
#define APP_MAX_THREAD_TYPES                 64
#endif

#ifndef APP_MAX_THREADS
#define APP_MAX_THREADS                      4
#endif

enum cdev_type {
    CDEV_TYPE_ANY,
    CDEV_TYPE_HW,
    CDEV_TYPE_SW
};

enum rwpa_stats_lvl {
    RWPA_STS_LVL_OFF = 0,
    RWPA_STS_LVL_PORTS_ONLY,
    RWPA_STS_LVL_APP,
    RWPA_STS_LVL_DETAILED,
    RWPA_STS_LVL_DELIMITER  /* error case */
};

struct app_params;

struct app_mempool_params {
    char *name;
    uint32_t parsed;
    uint32_t buffer_size;
    uint32_t pool_size;
    uint32_t cache_size;
    uint32_t cpu_socket_id;
};

struct app_eal_params {
    /* Map lcore set to physical cpu set */
    char *coremap;

    /* Core ID that is used as master */
    uint32_t master_lcore_present;
    uint32_t master_lcore;

    /* Number of memory channels */
    uint32_t channels_present;
    uint32_t channels;

    /* Memory to allocate (see also --socket-mem) */
    uint32_t memory_present;
    uint32_t memory;

    /* Force number of memory ranks (don't detect) */
    uint32_t ranks_present;
    uint32_t ranks;

    /* Add a PCI device in black list. */
    char *pci_blacklist[APP_MAX_LINKS];

    /* Add a PCI device in white list. */
    char *pci_whitelist[APP_MAX_LINKS];

    /* Add a virtual device. */
    char *vdev[APP_MAX_LINKS];

    /* Use VMware TSC map instead of native RDTSC */
    uint32_t vmware_tsc_map_present;
    int vmware_tsc_map;

    /* Type of this process (primary|secondary|auto) */
    char *proc_type;

    /* Set syslog facility */
    char *syslog;

    /* Set default log level */
    uint32_t log_level_present;
    uint32_t log_level;

    /* Display version information on startup */
    uint32_t version_present;
    int version;

    /* This help */
    uint32_t help_present;
    int help;

    /* Use malloc instead of hugetlbfs */
    uint32_t no_huge_present;
    int no_huge;

    /* Disable PCI */
    uint32_t no_pci_present;
    int no_pci;

    /* Disable HPET */
    uint32_t no_hpet_present;
    int no_hpet;

    /* No shared config (mmap'd files) */
    uint32_t no_shconf_present;
    int no_shconf;

    /* Add driver */
    char *add_driver;

    /*  Memory to allocate on sockets (comma separated values)*/
    char *socket_mem;

    /* Directory where hugetlbfs is mounted */
    char *huge_dir;

    /* Prefix for hugepage filenames */
    char *file_prefix;

    /* Base virtual address */
    char *base_virtaddr;

    /* Create /dev/uioX (usually done by hotplug) */
    uint32_t create_uio_dev_present;
    int create_uio_dev;

    /* Interrupt mode for VFIO (legacy|msi|msix) */
    char *vfio_intr;

    /* Support running on Xen dom0 without hugetlbfs */
    uint32_t xen_dom0_present;
    int xen_dom0;

    uint32_t parsed;
};

struct app_link_params {
    char *name;
    uint32_t parsed;
    uint32_t pmd_id;   /* Generated based on port mask */
    uint32_t rss_qs[APP_LINK_MAX_HWQ_IN];
    uint32_t n_rss_qs;
    uint32_t promisc;
    uint32_t state;    /* DOWN = 0, UP = 1 */
    uint32_t ip;       /* 0 = Invalid */
    uint32_t depth;    /* Valid only when IP is valid */
    struct ether_addr mac_addr; /* Read from HW / write from config file */
    uint32_t vlan_id;
    struct rte_eth_conf conf;
};

struct app_pktq_hwq_in_params {
    char *name;
    uint32_t parsed;
    uint32_t mempool_id; /* Position in the app->mempool_params */
    uint32_t size;
    uint32_t burst;
    struct rte_eth_rxconf conf;
};

struct app_pktq_hwq_out_params {
    char *name;
    struct rte_eth_dev_tx_buffer *tx_buffer;
    uint32_t parsed;
    uint32_t size;
    uint32_t burst;
    uint32_t dropless;
    uint64_t n_retries;
    struct rte_eth_txconf conf;
};

struct app_stat_params {
    uint64_t timer_period;
    uint32_t parsed;
    uint32_t stats_level;
    uint32_t stats_refresh_period_global_ms;
    uint32_t stats_print_period_ms;
};

struct app_pktq_tm_params {
    char *name;
    uint32_t parsed;
    const char *file_name;
    uint32_t burst_read;
    uint32_t burst_write;
};

struct app_crypto_params {
    enum cdev_type type;
    char cdev_type_string[32];
    uint64_t cryptodev_mask;
    uint16_t n_qp;
};

struct app_addr_params {
    uint16_t vnfd_port_to_ap;
    uint32_t vnfd_ip_to_ap;
    uint32_t vnfd_ip_to_wag;
    uint32_t vnfc_tls_ss_ip;
    uint16_t vnfc_tls_ss_port;
    uint32_t wag_tun_ip;
    struct ether_addr wag_tun_mac;
    struct ether_addr vap_tun_def_mac;
    uint32_t vap_tun_def_ip;
    uint16_t vap_tun_def_port;
    char ap_config_file[100];
};

struct app_misc_params {
    uint32_t uplink_pmd_us;
    uint32_t uplink_tls_us;
    char preloaded_key_store[100];
    char certs_dir[100];
    char certs_password[100];
    uint32_t max_vap_frag_sz;
    uint32_t frag_ttl_ms;
    int no_wag;
};

typedef void (*app_link_op)(struct app_params *app,
    uint32_t link_id,
    uint32_t up,
    void *arg);

struct app_link_data {
    app_link_op f_link;
    void *arg;
};

#define APP_CORE_MASK_SIZE  (RTE_MAX_LCORE / 64 + ((RTE_MAX_LCORE % 64) ? 1 : 0))

struct app_params {
    /* config */
    char app_name[APP_APPNAME_SIZE];
    const char *config_file;

    uint64_t port_mask;
    uint32_t log_level;
    uint32_t log_level_override;
    struct app_eal_params          eal_params;
    struct app_mempool_params      mempool_params[APP_MAX_MEMPOOLS];
    struct app_link_params         link_params[APP_MAX_LINKS];
    struct app_pktq_hwq_in_params  hwq_in_params[APP_MAX_HWQ_IN];
    struct app_pktq_hwq_out_params hwq_out_params[APP_MAX_HWQ_OUT];
    struct app_thread_params       thread_params[APP_MAX_THREADS];
    struct app_pktq_tm_params      tm_params;
    struct app_stat_params         stat_params;
    struct app_addr_params         addr_params;
    struct app_misc_params         misc_params;
    struct app_crypto_params       crypto_params;
    uint32_t n_mempools;
    uint32_t n_links;
    uint32_t n_pktq_hwq_in;
    uint32_t n_pktq_hwq_out;
    uint32_t n_pktq_swq;
    uint32_t n_threads;
    uint32_t n_thread_types;

    /* init */
    char *eal_argv[1 + APP_EAL_ARGC];
    struct cpu_core_map *core_map;
    uint64_t core_mask[APP_CORE_MASK_SIZE];
    struct rte_mempool *mempool[APP_MAX_MEMPOOLS];
    struct app_link_data link_data[APP_MAX_LINKS];
    struct thread_type thread_type[APP_MAX_THREAD_TYPES];
    int eal_argc;
};

#define APP_PARAM_VALID(obj) ((obj)->name != NULL)

#define APP_PARAM_COUNT(obj_array, n_objs)                \
{                                                         \
    size_t i;                                             \
                                                          \
    n_objs = 0;                                           \
    for (i = 0; i < RTE_DIM(obj_array); i++)              \
        if (APP_PARAM_VALID(&((obj_array)[i])))           \
            n_objs++;                                     \
}

#define APP_PARAM_FIND(obj_array, key)                    \
({                                                        \
     ssize_t obj_idx;                                     \
     const ssize_t obj_count = RTE_DIM(obj_array);        \
                                                          \
     for (obj_idx = 0; obj_idx < obj_count; obj_idx++) {  \
         if (!APP_PARAM_VALID(&((obj_array)[obj_idx])))   \
             continue;                                    \
                                                          \
         if (strcmp(key, (obj_array)[obj_idx].name) == 0) \
             break;                                       \
     }                                                    \
     obj_idx < obj_count ? obj_idx : -ENOENT;             \
})

#define APP_PARAM_FIND_BY_ID(obj_array, prefix, id, obj)  \
    do {                                                  \
        char name[APP_PARAM_NAME_SIZE];                   \
        ssize_t pos;                                      \
                                                          \
        sprintf(name, prefix "%" PRIu32, id);             \
        pos = APP_PARAM_FIND(obj_array, name);            \
        obj = (pos < 0) ? NULL : &((obj_array)[pos]);     \
    } while (0)

#define APP_PARAM_GET_ID(obj, prefix, id)                 \
    do                                                    \
        sscanf(obj->name, prefix "%" SCNu32, &id);        \
    while (0)

#define  APP_CHECK(exp, fmt, ...)                         \
    do {                                                  \
        if (!(exp)) {                                     \
            fprintf(stderr, fmt "\n", ## __VA_ARGS__);    \
            abort();                                      \
        }                                                 \
    } while (0)


static inline uint32_t
app_link_get_n_rxq(struct app_params *app, struct app_link_params *link)
{
    uint32_t n_rxq = 0, link_id, i;
    uint32_t n_pktq_hwq_in = RTE_MIN(app->n_pktq_hwq_in, RTE_DIM(app->hwq_in_params));

    APP_PARAM_GET_ID(link, "LINK", link_id);

    for (i = 0; i < n_pktq_hwq_in; i++) {
        struct app_pktq_hwq_in_params *p = &app->hwq_in_params[i];
        uint32_t rxq_link_id, rxq_queue_id;

        sscanf(p->name, "RXQ%" SCNu32 ".%" SCNu32, &rxq_link_id, &rxq_queue_id);
        if (rxq_link_id == link_id)
            n_rxq++;
    }

    return n_rxq;
}

static inline uint32_t
app_link_get_n_txq(struct app_params *app, struct app_link_params *link)
{
    uint32_t n_txq = 0, link_id, i;
    uint32_t n_pktq_hwq_out = RTE_MIN(app->n_pktq_hwq_out, RTE_DIM(app->hwq_out_params));

    APP_PARAM_GET_ID(link, "LINK", link_id);

    for (i = 0; i < n_pktq_hwq_out; i++) {
        struct app_pktq_hwq_out_params *p = &app->hwq_out_params[i];
        uint32_t txq_link_id, txq_queue_id;

        sscanf(p->name, "TXQ%" SCNu32 ".%" SCNu32, &txq_link_id, &txq_queue_id);
        if (txq_link_id == link_id)
            n_txq++;
    }

    return n_txq;
}

static inline struct app_link_params *
app_get_link_for_rxq(struct app_params *app, struct app_pktq_hwq_in_params *p)
{
    char link_name[APP_PARAM_NAME_SIZE];
    ssize_t link_param_idx;
    uint32_t rxq_link_id, rxq_queue_id;

    sscanf(p->name, "RXQ%" SCNu32 ".%" SCNu32, &rxq_link_id, &rxq_queue_id);
    sprintf(link_name, "LINK%" PRIu32, rxq_link_id);
    link_param_idx = APP_PARAM_FIND(app->link_params, link_name);
    APP_CHECK((link_param_idx >= 0),
            "Cannot find %s for %s", link_name, p->name);

    return &app->link_params[link_param_idx];
}

static inline struct app_link_params *
app_get_link_for_txq(struct app_params *app, struct app_pktq_hwq_out_params *p)
{
    char link_name[APP_PARAM_NAME_SIZE];
    ssize_t link_param_idx;
    uint32_t txq_link_id, txq_queue_id;

    sscanf(p->name, "TXQ%" SCNu32 ".%" SCNu32, &txq_link_id, &txq_queue_id);
    sprintf(link_name, "LINK%" PRIu32, txq_link_id);
    link_param_idx = APP_PARAM_FIND(app->link_params, link_name);
    APP_CHECK((link_param_idx >= 0),
            "Cannot find %s for %s", link_name, p->name);

    return &app->link_params[link_param_idx];
}

static inline uint32_t
app_rxq_get_readers(struct app_params *app, struct app_pktq_hwq_in_params *rxq)
{
    uint32_t pos = rxq - app->hwq_in_params;
    uint32_t n_threads = RTE_MIN(app->n_threads, RTE_DIM(app->thread_params));
    uint32_t n_readers = 0, i;

    for (i = 0; i < n_threads; i++) {
        struct app_thread_params *p = &app->thread_params[i];
        uint32_t n_pktq_in = RTE_MIN(p->n_pktq_in, RTE_DIM(p->pktq_in));
        uint32_t j;

        for (j = 0; j < n_pktq_in; j++) {
            struct app_pktq_in_params *pktq = &p->pktq_in[j];

            if ((pktq->type == APP_PKTQ_IN_HWQ) && (pktq->id == pos))
                n_readers++;
        }
    }

    return n_readers;
}


static inline uint32_t
app_txq_get_writers(struct app_params *app, struct app_pktq_hwq_out_params *txq)
{
    uint32_t pos = txq - app->hwq_out_params;
    uint32_t n_threads = RTE_MIN(app->n_threads, RTE_DIM(app->thread_params));
    uint32_t n_writers = 0, i;

    for (i = 0; i < n_threads; i++) {
        struct app_thread_params *p = &app->thread_params[i];
        uint32_t n_pktq_out = RTE_MIN(p->n_pktq_out, RTE_DIM(p->pktq_out));
        uint32_t j;

        for (j = 0; j < n_pktq_out; j++) {
            struct app_pktq_out_params *pktq = &p->pktq_out[j];

            if ((pktq->type == APP_PKTQ_OUT_HWQ) && (pktq->id == pos))
                n_writers++;
        }
    }

    return n_writers;
}

static inline uint32_t
app_core_is_enabled(struct app_params *app, uint32_t lcore_id)
{
    return(app->core_mask[lcore_id / 64] &
        (1LLU << (lcore_id % 64)));
}

static inline void
app_core_enable_in_core_mask(struct app_params *app, int lcore_id)
{
    app->core_mask[lcore_id / 64] |= 1LLU << (lcore_id % 64);

}

static inline void
app_core_build_core_mask_string(struct app_params *app, char *mask_buffer)
{
    int i;

    mask_buffer[0] = '\0';
    for (i = (int)RTE_DIM(app->core_mask); i > 0; i--) {
        /* For Hex representation of bits in uint64_t */
        char buffer[(64 / 8) * 2 + 1];
        memset(buffer, 0, sizeof(buffer));
        snprintf(buffer, sizeof(buffer), "%016" PRIx64,
             app->core_mask[i-1]);
        strcat(mask_buffer, buffer);
    }
}

int
app_config_init(struct app_params *app);

int
app_config_args(struct app_params *app,  int argc, char **argv);

int
app_config_parse(struct app_params *app, const char *file_name);

int
app_config_preproc(struct app_params *app);

int
app_config_check(struct app_params *app);

int
app_init(struct app_params *app);

int
app_thread_init(void *arg);

int
app_thread_run(void *arg);

int
app_thread_free(void *arg);

void
app_link_up_internal(struct app_params *app, struct app_link_params *cp);

void
app_link_down_internal(struct app_params *app, struct app_link_params *cp);

struct thread_type *
app_thread_type_find(struct app_params *app, char *name);

void
app_thread_params_set(struct app_params *app, struct app_thread_params *p);

int
app_thread_type_register(struct app_params *app, struct thread_type *ptype);

#endif // __INCLUDE_APP_H__
