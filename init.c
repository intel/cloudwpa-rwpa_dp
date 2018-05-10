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

#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_eal.h>
#include <rte_malloc.h>

#include "app.h"
#include "r-wpa_global_vars.h"
#include "downlink_thread.h"
#include "uplink_thread.h"
#ifdef RWPA_STATS_CAPTURE
#include "thread_statistics_handler.h"
#endif
#include "ring.h"

#include <rte_ethdev.h>

#define APP_RETA_SIZE_MAX (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)

static void
app_init_core_map(struct app_params *app)
{
    if (app->log_level >= RTE_LOG_INFO)
        RTE_LOG(INFO, RWPA_INIT, "Initializing CPU core map ...\n");

    app->core_map = cpu_core_map_init(4, 32, 4, 0);

    if (app->core_map == NULL)
        rte_panic("Cannot create CPU core map\n");

    if (app->log_level >= RTE_LOG_INFO)
        cpu_core_map_print(app->core_map);
}

/* Core Mask String in Hex Representation */
#define APP_CORE_MASK_STRING_SIZE ((64 * APP_CORE_MASK_SIZE) / 8 * 2 + 1)

static void
app_init_core_mask(struct app_params *app)
{
    uint32_t i;
    char core_mask_str[APP_CORE_MASK_STRING_SIZE];

    for (i = 0; i < app->n_threads; i++) {
        struct app_thread_params *p = &app->thread_params[i];
        int lcore_id;

        lcore_id = cpu_core_map_get_lcore_id(app->core_map,
          p->socket_id,
          p->core_id,
          p->hyper_th_id);

        if (lcore_id < 0)
            rte_panic("Cannot create CPU core mask\n");

        app_core_enable_in_core_mask(app, lcore_id);
    }

    app_core_build_core_mask_string(app, core_mask_str);

    if (app->log_level >= RTE_LOG_INFO)
        RTE_LOG(INFO, RWPA_INIT, "CPU core mask = 0x%s\n", core_mask_str);
}

static void
app_init_eal(struct app_params *app)
{
    char buffer[256];
    char core_mask_str[APP_CORE_MASK_STRING_SIZE];
    struct app_eal_params *p = &app->eal_params;
    uint32_t n_args = 0;
    uint32_t i;
    int status;

    app->eal_argv[n_args++] = strdup(app->app_name);

    app_core_build_core_mask_string(app, core_mask_str);
    snprintf(buffer, sizeof(buffer), "-c%s", core_mask_str);
    app->eal_argv[n_args++] = strdup(buffer);

    if (p->coremap) {
        snprintf(buffer, sizeof(buffer), "--lcores=%s", p->coremap);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (p->master_lcore_present) {
        snprintf(buffer,
                sizeof(buffer),
                "--master-lcore=%" PRIu32,
                p->master_lcore);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    snprintf(buffer, sizeof(buffer), "-n%" PRIu32, p->channels);
    app->eal_argv[n_args++] = strdup(buffer);

    if (p->memory_present) {
        snprintf(buffer, sizeof(buffer), "-m%" PRIu32, p->memory);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (p->ranks_present) {
        snprintf(buffer, sizeof(buffer), "-r%" PRIu32, p->ranks);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    for (i = 0; i < APP_MAX_LINKS; i++) {
        if (p->pci_blacklist[i] == NULL)
            break;

        snprintf(buffer,
                sizeof(buffer),
                "--pci-blacklist=%s",
                p->pci_blacklist[i]);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (app->port_mask != 0) {
        for (i = 0; i < APP_MAX_LINKS; i++) {
            if (p->pci_whitelist[i] == NULL)
                break;

            snprintf(buffer,
                    sizeof(buffer),
                    "--pci-whitelist=%s",
                    p->pci_whitelist[i]);
            app->eal_argv[n_args++] = strdup(buffer);
        }
    }

    for (i = 0; i < APP_MAX_LINKS; i++) {
        if (p->vdev[i] == NULL)
            break;

        snprintf(buffer, sizeof(buffer),
             "--vdev=%s", p->vdev[i]);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if ((p->vmware_tsc_map_present) && p->vmware_tsc_map) {
        snprintf(buffer, sizeof(buffer), "--vmware-tsc-map");
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (p->proc_type) {
        snprintf(buffer, sizeof(buffer),
                 "--proc-type=%s", p->proc_type);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (p->syslog) {
        snprintf(buffer, sizeof(buffer), "--syslog=%s", p->syslog);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (p->log_level_present) {
        /* If log level specified in cfg file and on the command line,
         * command line has priority */
        if (app->log_level_override) {
            snprintf(buffer, sizeof(buffer), "--log-level=%" PRIu32, app->log_level);
        } else {
            snprintf(buffer, sizeof(buffer), "--log-level=%" PRIu32, p->log_level);
            app->log_level = p->log_level;
        }
        app->eal_argv[n_args++] = strdup(buffer);
    } else {
        /* If log level not specified in cfg file use default or
         * log level specified on the command line */
        snprintf(buffer, sizeof(buffer), "--log-level=%" PRIu32, app->log_level);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if ((p->version_present) && p->version) {
        snprintf(buffer, sizeof(buffer), "-v");
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if ((p->help_present) && p->help) {
        snprintf(buffer, sizeof(buffer), "--help");
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if ((p->no_huge_present) && p->no_huge) {
        snprintf(buffer, sizeof(buffer), "--no-huge");
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if ((p->no_pci_present) && p->no_pci) {
        snprintf(buffer, sizeof(buffer), "--no-pci");
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if ((p->no_hpet_present) && p->no_hpet) {
        snprintf(buffer, sizeof(buffer), "--no-hpet");
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if ((p->no_shconf_present) && p->no_shconf) {
        snprintf(buffer, sizeof(buffer), "--no-shconf");
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (p->add_driver) {
        snprintf(buffer, sizeof(buffer), "-d=%s", p->add_driver);
        RWPA_CHECK_ARRAY_OFFSET(n_args + 1, 1 + APP_EAL_ARGC);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (p->socket_mem) {
        snprintf(buffer, sizeof(buffer),
                 "--socket-mem=%s", p->socket_mem);
        RWPA_CHECK_ARRAY_OFFSET(n_args + 1, 1 + APP_EAL_ARGC);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (p->huge_dir) {
        snprintf(buffer, sizeof(buffer), "--huge-dir=%s", p->huge_dir);
        RWPA_CHECK_ARRAY_OFFSET(n_args + 1, 1 + APP_EAL_ARGC);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (p->file_prefix) {
        snprintf(buffer, sizeof(buffer),
                 "--file-prefix=%s", p->file_prefix);
        RWPA_CHECK_ARRAY_OFFSET(n_args + 1, 1 + APP_EAL_ARGC);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (p->base_virtaddr) {
        snprintf(buffer, sizeof(buffer),
                 "--base-virtaddr=%s", p->base_virtaddr);
        RWPA_CHECK_ARRAY_OFFSET(n_args + 1, 1 + APP_EAL_ARGC);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if ((p->create_uio_dev_present) && p->create_uio_dev) {
        snprintf(buffer, sizeof(buffer), "--create-uio-dev");
        RWPA_CHECK_ARRAY_OFFSET(n_args + 1, 1 + APP_EAL_ARGC);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if (p->vfio_intr) {
        snprintf(buffer, sizeof(buffer),
                 "--vfio-intr=%s", p->vfio_intr);
        RWPA_CHECK_ARRAY_OFFSET(n_args + 1, 1 + APP_EAL_ARGC);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    if ((p->xen_dom0_present) && (p->xen_dom0)) {
        snprintf(buffer, sizeof(buffer), "--xen-dom0");
        RWPA_CHECK_ARRAY_OFFSET(n_args + 1, 1 + APP_EAL_ARGC);
        app->eal_argv[n_args++] = strdup(buffer);
    }

    snprintf(buffer, sizeof(buffer), "--");

    RWPA_CHECK_ARRAY_OFFSET(n_args + 1, 1 + APP_EAL_ARGC);

    app->eal_argv[n_args++] = strdup(buffer);

    app->eal_argc = n_args;

    if (app->log_level >= RTE_LOG_INFO) {
        int i;
        RTE_LOG(INFO, RWPA_INIT, "Initializing EAL...\n");
        fprintf(stdout, "EAL arguments: \"");
        for (i = 1; i < app->eal_argc; i++)
            fprintf(stdout, "%s ", app->eal_argv[i]);
        fprintf(stdout, "\"\n");
    }

    status = rte_eal_init(app->eal_argc, app->eal_argv);
    if (status < 0)
        rte_panic("EAL init error\n");
}

static void
app_init_mempool(struct app_params *app)
{
    uint32_t i;

    for (i = 0; i < app->n_mempools; i++) {
        struct app_mempool_params *p = &app->mempool_params[i];

        RTE_LOG(INFO, RWPA_INIT, "Initializing %s ...\n", p->name);
        app->mempool[i] =
            rte_mempool_create(
                p->name,
                p->pool_size,
                p->buffer_size,
                p->cache_size,
                sizeof(struct rte_pktmbuf_pool_private),
                rte_pktmbuf_pool_init,
                NULL,
                rte_pktmbuf_init,
                NULL,
                p->cpu_socket_id,
                0);

        if (app->mempool[i] == NULL)
            rte_panic("%s init error\n", p->name);
    }
}

static inline int
app_get_cpu_socket_id(uint32_t pmd_id)
{
    int status = rte_eth_dev_socket_id(pmd_id);

    return (status != SOCKET_ID_ANY) ? status : 0;
}

static inline int
app_link_rss_enabled(struct app_link_params *cp)
{
    return (cp->n_rss_qs) ? 1 : 0;
}

static void
app_link_rss_setup(struct app_link_params *cp)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rss_reta_entry64 reta_conf[APP_RETA_SIZE_MAX];
    uint32_t i;
    int status;

    /* Get RETA size */
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(cp->pmd_id, &dev_info);

    if (dev_info.reta_size == 0)
        rte_panic("%s (%u): RSS setup error (null RETA size)\n",
                cp->name, cp->pmd_id);

    if (dev_info.reta_size > ETH_RSS_RETA_SIZE_512)
        rte_panic("%s (%u): RSS setup error (RETA size too big)\n",
                cp->name, cp->pmd_id);

    /* Setup RETA contents */
    memset(reta_conf, 0, sizeof(reta_conf));

    for (i = 0; i < dev_info.reta_size; i++)
        reta_conf[i / RTE_RETA_GROUP_SIZE].mask = UINT64_MAX;

    for (i = 0; i < dev_info.reta_size; i++) {
        uint32_t reta_id = i / RTE_RETA_GROUP_SIZE;
        uint32_t reta_pos = i % RTE_RETA_GROUP_SIZE;
        uint32_t rss_qs_pos = i % cp->n_rss_qs;

        reta_conf[reta_id].reta[reta_pos] =
                                     (uint16_t) cp->rss_qs[rss_qs_pos];
    }

    /* RETA update */
    status = rte_eth_dev_rss_reta_update(cp->pmd_id,
                                         reta_conf,
                                         dev_info.reta_size);
    if (status != 0)
        rte_panic("%s (%u): RSS setup error (RETA update failed)\n",
                  cp->name, cp->pmd_id);
}

static void
app_init_link_set_config(struct app_link_params *p)
{
    if (p->n_rss_qs) {
        p->conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    }
}

static void
app_check_link(struct app_params *app)
{
    uint32_t all_links_up, i;

    all_links_up = 1;

    for (i = 0; i < app->n_links; i++) {
        struct app_link_params *p = &app->link_params[i];
        struct rte_eth_link link_params;

        memset(&link_params, 0, sizeof(link_params));
        rte_eth_link_get(p->pmd_id, &link_params);

        RTE_LOG(INFO, RWPA_INIT, "%s (%" PRIu32 ") (%" PRIu32 " Gbps) %s",
            p->name,
            p->pmd_id,
            link_params.link_speed / 1000,
            link_params.link_status ? "UP\n" : "DOWN\n");

        if (link_params.link_status == ETH_LINK_DOWN)
            all_links_up = 0;
    }

    if (all_links_up == 0)
        rte_panic("Some links are DOWN\n");
}


static void
app_init_link(struct app_params *app)
{
    uint32_t i;

    for (i = 0; i < app->n_links; i++) {
        struct app_link_params *p_link = &app->link_params[i];
        uint32_t link_id, n_hwq_in, n_hwq_out, j;
        int status;

        sscanf(p_link->name, "LINK%" PRIu32, &link_id);
        n_hwq_in = app_link_get_n_rxq(app, p_link);
        n_hwq_out = app_link_get_n_txq(app, p_link);
        app_init_link_set_config(p_link);

        RTE_LOG(INFO, RWPA_INIT, "Initializing %s (%" PRIu32") "
            "(%" PRIu32 " RXQ, %" PRIu32 " TXQ) ...\n",
            p_link->name,
            p_link->pmd_id,
            n_hwq_in,
            n_hwq_out);

	/* Set device mac addresses from config/default.cfg if entry present */
	struct ether_addr tmp = { .addr_bytes={0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
	if (!is_same_ether_addr(&p_link->mac_addr, &tmp))
		rte_eth_dev_default_mac_addr_set(p_link->pmd_id, &p_link->mac_addr);

        /* LINK */
        status = rte_eth_dev_configure(
                p_link->pmd_id,
                n_hwq_in,
                n_hwq_out,
                &p_link->conf);
        if (status < 0)
            rte_exit(EXIT_FAILURE, "%s (%" PRId32 "): "
                      "init error (%" PRId32 ")\n",
                      p_link->name, p_link->pmd_id, status);

        rte_eth_macaddr_get(p_link->pmd_id, &p_link->mac_addr);

        RTE_LOG(INFO, RWPA_INIT,
                "Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                (unsigned) p_link->pmd_id,
                p_link->mac_addr.addr_bytes[0],
                p_link->mac_addr.addr_bytes[1],
                p_link->mac_addr.addr_bytes[2],
                p_link->mac_addr.addr_bytes[3],
                p_link->mac_addr.addr_bytes[4],
                p_link->mac_addr.addr_bytes[5]);

        if (p_link->promisc)
            rte_eth_promiscuous_enable(p_link->pmd_id);

        /* RXQ */
        for (j = 0; j < app->n_pktq_hwq_in; j++) {
            struct app_pktq_hwq_in_params *p_rxq =
                &app->hwq_in_params[j];
            uint32_t rxq_link_id, rxq_queue_id;

            sscanf(p_rxq->name, "RXQ%" PRIu32 ".%" PRIu32,
                    &rxq_link_id, &rxq_queue_id);
            if (rxq_link_id != link_id)
                continue;

            status = rte_eth_rx_queue_setup(
                    p_link->pmd_id,
                    rxq_queue_id,
                    p_rxq->size,
                    app_get_cpu_socket_id(p_link->pmd_id),
                    &p_rxq->conf,
                    app->mempool[p_rxq->mempool_id]);

            if (status < 0) {
                rte_exit(EXIT_FAILURE, "%s (%" PRIu32 "): "
                    "%s init error (%" PRId32 ")\n",
                    p_link->name,
                    p_link->pmd_id,
                    p_rxq->name,
                    status);
            }
        }

        /* TXQ */
        for (j = 0; j < app->n_pktq_hwq_out; j++) {
            struct app_pktq_hwq_out_params *p_txq =
                &app->hwq_out_params[j];
            uint32_t txq_link_id, txq_queue_id;

            sscanf(p_txq->name, "TXQ%" PRIu32 ".%" PRIu32,
                   &txq_link_id, &txq_queue_id);
            if (txq_link_id != link_id)
                continue;

            RTE_LOG(INFO, RWPA_INIT, "Multisegment tx enabling\n");
            p_txq->conf.txq_flags = 0;

            status = rte_eth_tx_queue_setup(
                        p_link->pmd_id,
                        txq_queue_id,
                        p_txq->size,
                        app_get_cpu_socket_id(p_link->pmd_id),
                        &p_txq->conf);
            if (status < 0)
                rte_exit(EXIT_FAILURE, "%s (%" PRIu32 "): "
                          "%s init error (%" PRId32 ")\n",
                          p_link->name,
                          p_link->pmd_id,
                          p_txq->name,
                          status);

            /* Initialize TX buffers */
            p_txq->tx_buffer = rte_zmalloc_socket("tx_buffer",
                                                  RTE_ETH_TX_BUFFER_SIZE(p_txq->burst),
                                                  0,
                                                  app_get_cpu_socket_id(p_link->pmd_id));

            if (p_txq->tx_buffer == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u - bye\n",
                          (unsigned) p_link->pmd_id);
            }

            rte_eth_tx_buffer_init(p_txq->tx_buffer, p_txq->burst);
        }

        /* LINK START */
        status = rte_eth_dev_start(p_link->pmd_id);
        if (status < 0)
            rte_exit(EXIT_FAILURE, "Cannot start %s (error %" PRId32 ")\n",
                      p_link->name, status);

        if (app_link_rss_enabled(p_link))
            app_link_rss_setup(p_link);

        /* LINK UP */
        p_link->state = 1;
    }

    app_check_link(app);
}

struct thread_type *app_thread_type_find(struct app_params *app, char *name)
{
    uint32_t i;

    for (i = 0; i < app->n_thread_types; i++)
        if (strcmp(app->thread_type[i].name, name) == 0)
            return &app->thread_type[i];

    return NULL;
}

void app_thread_params_set(struct app_params *app, struct app_thread_params *p) {
    uint32_t i;

    /* pktq_in */
    p->n_ports_in = p->n_pktq_in;

    for (i = 0; i < p->n_pktq_in; i++) {
        struct app_pktq_in_params *in = &p->pktq_in[i];
        struct thread_port_in_params *out = &p->port_in[i];

        switch (in->type) {
        case APP_PKTQ_IN_HWQ:
        {
            struct app_pktq_hwq_in_params *p_hwq_in = &app->hwq_in_params[in->id];
            struct app_link_params *p_link = app_get_link_for_rxq(app, p_hwq_in);
            uint32_t rxq_link_id, rxq_queue_id;

            sscanf(p_hwq_in->name, "RXQ%" SCNu32 ".%" SCNu32, &rxq_link_id,
                   &rxq_queue_id);

            out->type = THREAD_PORT_IN_ETHDEV_READER;
            out->params.ethdev.port_id = p_link->pmd_id;
            out->params.ethdev.queue_id = rxq_queue_id;
            out->burst_size = p_hwq_in->burst;
            break;
        }
        default:
            break;
        }
    }

    /* pktq_out */
    p->n_ports_out = p->n_pktq_out;

    for (i = 0; i < p->n_pktq_out; i++) {
        struct app_pktq_out_params *in = &p->pktq_out[i];
        struct thread_port_out_params *out = &p->port_out[i];

        switch (in->type) {
        case APP_PKTQ_OUT_HWQ:
        {
            struct app_pktq_hwq_out_params *p_hwq_out =  &app->hwq_out_params[in->id];
            struct app_link_params *p_link = app_get_link_for_txq(app, p_hwq_out);
            uint32_t txq_link_id, txq_queue_id;

            sscanf(p_hwq_out->name, "TXQ%" SCNu32 ".%" SCNu32,&txq_link_id,
                   &txq_queue_id);

            if (p_hwq_out->dropless == 0) {
                struct rte_port_ethdev_writer_params *params =
                                                     &out->params.ethdev;

                out->type = THREAD_PORT_OUT_ETHDEV_WRITER;
                out->tx_buffer = p_hwq_out->tx_buffer;
                out->burst_size = p_hwq_out->burst;
                params->port_id = p_link->pmd_id;
                params->queue_id = txq_queue_id;
                params->tx_burst_sz = app->hwq_out_params[in->id].burst;
            } else {
                struct rte_port_ethdev_writer_nodrop_params  *params =
                                                      &out->params.ethdev_nodrop;

                out->type =  THREAD_PORT_OUT_ETHDEV_WRITER_NODROP;
                out->tx_buffer = p_hwq_out->tx_buffer;
                out->burst_size = p_hwq_out->burst;
                params->port_id = p_link->pmd_id;
                params->queue_id = txq_queue_id;
                params->tx_burst_sz = p_hwq_out->burst;
                params->n_retries = p_hwq_out->n_retries;
            }
        }
            break;
        default:
            break;
        }
    }
}

static void
app_init_threads(struct app_params *app)
{
    uint32_t t_id;
    int lcore_id;

    /* initialise ring lock for ring creation */
    int retval = initialise_ring_lock();
    if (retval < 0) {
        rte_exit(EXIT_FAILURE,
                 "Could not initialise ring creation lock\n");
    }

    for (t_id = 0; t_id < app->n_threads; t_id++) {
        struct app_thread_params *params = &app->thread_params[t_id];
        struct thread_type *ttype;

        RTE_LOG(INFO, RWPA_INIT,
                "Initializing %s (%s)\n",
                params->name, params->type);

        ttype = app_thread_type_find(app, params->type);
        if (ttype == NULL) {
            RTE_LOG(WARNING, RWPA_INIT,
                    "Warning: %s not registered\n",
                    params->type);
            continue;
        }

        app_thread_params_set(app, params);

        lcore_id = cpu_core_map_get_lcore_id(app->core_map,  params->socket_id,
                                             params->core_id, params->hyper_th_id);

        if (lcore_id < 0) {
            rte_exit(EXIT_FAILURE,
                     "Invalid core s%" PRIu32 "c%" PRIu32 "%s\n",
                     params->socket_id, params->core_id, (params->hyper_th_id) ? "h" : "");
        }

        params->lcore_id = lcore_id;

        if (!ttype->thread_ops->f_init) {
            rte_exit(EXIT_FAILURE,
                     "Thread's %s init() function undefined - exiting", params->type);
        }

        if (!ttype->thread_ops->f_run) {
            rte_exit(EXIT_FAILURE,
                     "Thread's %s run() function undefined - exiting", params->type);
        }

        if (!ttype->thread_ops->f_free) {
            rte_exit(EXIT_FAILURE,
                     "Thread's %s free() function undefined - exiting", params->type);
        }
    }
}

int
app_thread_type_register(struct app_params *app, struct thread_type *ttype)
{
    uint32_t i;

    /* Check input arguments */
    if ((app == NULL) ||
        (ttype == NULL) ||
        (ttype->name == NULL) ||
        (strlen(ttype->name) == 0) ||
        (ttype->thread_ops->f_init == NULL))
        return -EINVAL;

    /* Check for duplicate entry */
    for (i = 0; i < app->n_thread_types; i++)
        if (strcmp(app->thread_type[i].name, ttype->name) == 0)
            return -EEXIST;

    /* Check for resource availability */
    if (app->n_thread_types == APP_MAX_THREAD_TYPES)
        return -ENOMEM;

    /* Copy thread type */
    rte_memcpy(&app->thread_type[app->n_thread_types++],
               ttype,
               sizeof(struct thread_type));

    return 0;
}

int
app_init(struct app_params *app)
{
    app_init_core_map(app);
    app_init_core_mask(app);
    app_init_eal(app);
    app_init_mempool(app);
    app_init_link(app);
    app_thread_type_register(app, &thread_uplink);
    app_thread_type_register(app, &thread_downlink);
#ifdef RWPA_STATS_CAPTURE
    app_thread_type_register(app, &thread_statistics_handler);
#endif
    app_init_threads(app);

    return 0;
}
