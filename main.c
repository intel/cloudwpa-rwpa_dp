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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include <rte_memory.h>

#include "r-wpa_global_vars.h"
#include "app.h"
#include "thread.h"
#include "key.h"
#include "counter.h"
#include "seq_num.h"
#include "meta.h"
#include "ccmp_sa.h"
#include "crypto.h"
#include "ap_config.h"
#include "store.h"
#include "vap_frag.h"
#include "cycle_capture.h"
#ifdef RWPA_STATS_CAPTURE
#include "statistics_capture.h"
#endif
#ifdef RWPA_PRELOAD_STORE
#include "store_load.h"
#endif

#if RTE_LOG_DP_LEVEL >= RTE_LOG_DEBUG
#define DO_RFC_1812_CHECKS
#endif

static struct app_params app;

volatile int force_quit = 0;

static void
signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM || signum == SIGUSR1) {
        printf("\n\nSignal %d received, preparing to exit...\n\n", signum);
        force_quit = 1;
    }
}

int
app_thread_init(void *arg) {
    uint32_t t_id;
    unsigned lcore_id;
    struct app_params *app = (struct app_params*)arg;

    lcore_id = rte_lcore_id();

    for (t_id = 0; t_id < app->n_threads; t_id++) {
        struct app_thread_params *params = &app->thread_params[t_id];
        struct thread_type *ttype;

        ttype = app_thread_type_find(app, params->type);
        if (ttype == NULL)
            continue;

        if (lcore_id == params->lcore_id) {
            ttype->thread_ops->f_init(params, (void*)app);
        }
    }

    return 0;
}

int
app_thread_run(void *arg) {
    uint32_t t_id;
    unsigned lcore_id;
    struct app_params *app = (struct app_params*)arg;

    lcore_id = rte_lcore_id();

    for (t_id = 0; t_id < app->n_threads; t_id++) {
        struct app_thread_params *params = &app->thread_params[t_id];
        struct thread_type *ttype;

        ttype = app_thread_type_find(app, params->type);
        if (ttype == NULL)
            continue;

        if (lcore_id == params->lcore_id) {
            ttype->thread_ops->f_run((void*)app);
        }
    }

    return 0;
}

int
app_thread_free(void *arg) {
    uint32_t t_id;
    unsigned lcore_id;
    struct app_params *app = (struct app_params*)arg;

    lcore_id = rte_lcore_id();

    for (t_id = 0; t_id < app->n_threads; t_id++) {
        struct app_thread_params *params = &app->thread_params[t_id];
        struct thread_type *ttype;

        ttype = app_thread_type_find(app, params->type);
        if (ttype == NULL)
            continue;

        if (lcore_id == params->lcore_id) {
            ttype->thread_ops->f_free((void*)app);
        }
    }

    return 0;
}

/* Run function fun on each logical core */
static int
app_launch_thread(struct app_params *app, void *fun) {
    int ret;
    unsigned lcoreid;
    /* Launch per-lcore init on every lcore */
    ret = 0;

    rte_eal_mp_remote_launch(fun, (void*)app, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcoreid) {
        if (rte_eal_wait_lcore(lcoreid) < 0) {
            ret = -1;
            break;
        }
    }

    return ret;
}

/* Run function fun on each logical core without waiting for threads to finish */
static int
app_launch_thread_no_wait(struct app_params *app, void *fun) {
    rte_eal_mp_remote_launch(fun, (void*)app, CALL_MASTER);
    return 0;
}

int
main(int argc, char **argv) {
    int lcoreid;

    memset(&app, 0, sizeof(struct app_params));

    rte_openlog_stream(stderr);

    /* Config */
    app_config_init(&app);

    /* Here parse command line */
    app_config_args(&app, argc, argv);

    /* Check if config file exists etc. */
    app_config_preproc(&app);

    /* Here parse cfg file given on the command line with -f (mandatory)*/
    app_config_parse(&app, app.config_file);

    /* Make sure the configuration makes sense */
    app_config_check(&app);

    /* Init EAL and other stuff (signals, memory, ports, TX/RX queues, stats) */
    app_init(&app);

    rte_log_set_global_level(app.log_level);

    rte_log_set_level(RTE_LOGTYPE_RWPA_INIT,       app.log_level); // USER 1
    rte_log_set_level(RTE_LOGTYPE_RWPA_UL,         app.log_level); // USER 2
    rte_log_set_level(RTE_LOGTYPE_RWPA_DL,         app.log_level); // USER 3
    rte_log_set_level(RTE_LOGTYPE_RWPA_TLS,        app.log_level); // USER 4
    rte_log_set_level(RTE_LOGTYPE_RWPA_STORE,      app.log_level); // USER 5
#ifdef RWPA_PRELOAD_STORE
    rte_log_set_level(RTE_LOGTYPE_RWPA_STORE_LOAD, app.log_level); // USER 5
#endif
    rte_log_set_level(RTE_LOGTYPE_RWPA_CRYPTO,     app.log_level); // USER 6
    rte_log_set_level(RTE_LOGTYPE_RWPA_CCMP,       app.log_level); // USER 6
    rte_log_set_level(RTE_LOGTYPE_RWPA_STATS,      app.log_level); // USER 7

    /* Signal handler for exiting */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGUSR1, signal_handler);

    /* Initialize vAP and station store */
    store_init(rte_socket_id(), &app.addr_params);

    /* Initialize store for static AP address configuration */
    ap_config_init(rte_socket_id(), &app.addr_params);

    /* Initialize crypto library */
    crypto_init(&app.crypto_params, CCMP_MAX_SESSIONS);

    /* Initialize vAP native fragmentation library */
    vap_frag_init(NUM_STA_MAX, app.misc_params.frag_ttl_ms,
                  app.misc_params.max_vap_frag_sz);

#ifdef RWPA_STATS_CAPTURE
    stats_capture_init_all(&app);
#endif

    CYCLE_CAPTURE_INIT();

#ifdef RWPA_PRELOAD_STORE
    store_load(app.misc_params.preloaded_key_store);
#endif

    /* Launch threads init() functions on chosen cores */
    app_launch_thread(&app, app_thread_init);

    /*
     * Threads have been initialized so it's OK to launch run() functions;
     * Run() functions may or may not return. If run() function returns,
     * app_launch_thread() busy waits for other run() functions to exit.
     * However, busy waiting may be detected as soft lockup.
     * Therefore, use "no wait" variant of the function
     */
    app_launch_thread_no_wait(&app, app_thread_run);

    /* ..and wait and sleep here */
    while (!force_quit)
        sleep(1);

    /*
     * If we are here the program received quit signal, wait for
     * threads to finish
     */
    RTE_LCORE_FOREACH_SLAVE(lcoreid) {
        if (rte_eal_wait_lcore(lcoreid) < 0) {
            return -1;
        }
    }
    /* Launch threads free() functions on chosen cores */
    app_launch_thread(&app, app_thread_free);

    /* Global data cleanup */
    vap_frag_destroy();
    crypto_destroy();
    ap_config_cleanup();
    store_cleanup();
#ifdef RWPA_STATS_CAPTURE
    stats_capture_free_all();
#endif

    printf("Bye...\n");

    return 0;
}
