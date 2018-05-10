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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_malloc.h>

#include "app.h"
#include "thread.h"
#include "r-wpa_global_vars.h"
#include "thread_statistics_handler.h"
#include "statistics_capture.h"
#include "statistics_handler_ports.h"
#include "statistics_handler_sta_lookup.h"
#include "statistics_handler_crypto.h"
#include "statistics_handler_uplink.h"
#include "statistics_handler_downlink.h"
#include "statistics_handler_control.h"
#include "statistics_handler_cycles.h"

extern volatile int force_quit;

static struct app_params *g_app = NULL;
static struct app_thread_params *tp_stats = NULL;

static enum rwpa_stats_lvl current_stats_print_lvl;
struct rte_timer stats_print_timer, stats_refresh_timer;

/* a tsc-based timer responsible for triggering statistics printout */
#define TIMER_MILLISECOND 1
#define MAX_TIMER_PERIOD  86400 /* 1 day max */

#define INJECT_DUMMY_INTERFACES() { \
    .init              = sts_hdlr_generic_init_dummy,  \
    .free              = sts_hdlr_generic_dummy,       \
    .capture           = sts_hdlr_generic_dummy,       \
    .update_shadow_sts = sts_hdlr_generic_dummy,       \
    .update_parsed_sts = sts_hdlr_generic_dummy,       \
    .clear_sts         = sts_hdlr_generic_dummy,       \
    .print_log         = sts_hdlr_generic_print_dummy, \
}

#ifndef RWPA_STATS_CAPTURE_PORTS_OFF
struct sts_hdlr_generic_ops sts_hdlr_ops_ports = {
    .init              = sts_hdlr_ports_init,
    .free              = sts_hdlr_ports_free,
    .capture           = sts_hdlr_ports_capture,
    .update_shadow_sts = sts_hdlr_ports_update_shadow_stats,
    .update_parsed_sts = sts_hdlr_ports_update_parsed_stats,
    .clear_sts         = sts_hdlr_ports_clear_stats,
    .print_log         = sts_hdlr_ports_print,
};
#else
struct sts_hdlr_generic_ops sts_hdlr_ops_ports = INJECT_DUMMY_INTERFACES();
#endif

#ifndef RWPA_STATS_CAPTURE_STA_LOOKUP_OFF
struct sts_hdlr_generic_ops sts_hdlr_ops_sta_lookup = {
    .init              = sts_hdlr_sta_lookup_init,
    .free              = sts_hdlr_sta_lookup_free,
    .capture           = sts_hdlr_generic_dummy,
    .update_shadow_sts = sts_hdlr_sta_lookup_update_shadow_stats,
    .update_parsed_sts = sts_hdlr_sta_lookup_update_parsed_stats,
    .clear_sts         = sts_hdlr_sta_lookup_clear_stats,
    .print_log         = sts_hdlr_sta_lookup_print,
};
#else
struct sts_hdlr_generic_ops sts_hdlr_ops_sta_lookup = INJECT_DUMMY_INTERFACES();
#endif

#ifndef RWPA_STATS_CAPTURE_CRYPTO_OFF
struct sts_hdlr_generic_ops sts_hdlr_ops_crypto = {
    .init              = sts_hdlr_crypto_init,
    .free              = sts_hdlr_crypto_free,
    .capture           = sts_hdlr_generic_dummy,
    .update_shadow_sts = sts_hdlr_crypto_update_shadow_stats,
    .update_parsed_sts = sts_hdlr_crypto_update_parsed_stats,
    .clear_sts         = sts_hdlr_crypto_clear_stats,
    .print_log         = sts_hdlr_crypto_print,
};
#else
struct sts_hdlr_generic_ops sts_hdlr_ops_crypto = INJECT_DUMMY_INTERFACES();
#endif

#ifndef RWPA_STATS_CAPTURE_UPLINK_OFF
struct sts_hdlr_generic_ops sts_hdlr_ops_uplink = {
    .init              = sts_hdlr_uplink_init,
    .free              = sts_hdlr_uplink_free,
    .capture           = sts_hdlr_generic_dummy,
    .update_shadow_sts = sts_hdlr_uplink_update_shadow_stats,
    .update_parsed_sts = sts_hdlr_uplink_update_parsed_stats,
    .clear_sts         = sts_hdlr_uplink_clear_stats,
    .print_log         = sts_hdlr_uplink_print,
};
#else
struct sts_hdlr_generic_ops sts_hdlr_ops_uplink = INJECT_DUMMY_INTERFACES();
#endif

#ifndef RWPA_STATS_CAPTURE_DOWNLINK_OFF
struct sts_hdlr_generic_ops sts_hdlr_ops_downlink = {
    .init              = sts_hdlr_downlink_init,
    .free              = sts_hdlr_downlink_free,
    .capture           = sts_hdlr_generic_dummy,
    .update_shadow_sts = sts_hdlr_downlink_update_shadow_stats,
    .update_parsed_sts = sts_hdlr_downlink_update_parsed_stats,
    .clear_sts         = sts_hdlr_downlink_clear_stats,
    .print_log         = sts_hdlr_downlink_print,
};
#else
struct sts_hdlr_generic_ops sts_hdlr_ops_downlink = INJECT_DUMMY_INTERFACES();
#endif

#ifndef RWPA_STATS_CAPTURE_CONTROL_OFF
struct sts_hdlr_generic_ops sts_hdlr_ops_control = {
    .init              = sts_hdlr_control_init,
    .free              = sts_hdlr_control_free,
    .capture           = sts_hdlr_generic_dummy,
    .update_shadow_sts = sts_hdlr_control_update_shadow_stats,
    .update_parsed_sts = sts_hdlr_control_update_parsed_stats,
    .clear_sts         = sts_hdlr_control_clear_stats,
    .print_log         = sts_hdlr_control_print,
};
#else
struct sts_hdlr_generic_ops sts_hdlr_ops_control = INJECT_DUMMY_INTERFACES();
#endif

#ifdef RWPA_CYCLE_CAPTURE
struct sts_hdlr_generic_ops sts_hdlr_ops_cycle = {
    .init              = sts_hdlr_cycle_init,
    .free              = sts_hdlr_cycle_free,
    .capture           = sts_hdlr_generic_dummy,
    .update_shadow_sts = sts_hdlr_cycle_update_shadow_stats,
    .update_parsed_sts = sts_hdlr_cycle_update_parsed_stats,
    .clear_sts         = sts_hdlr_cycle_clear_stats,
    .print_log         = sts_hdlr_cycle_print,
};
#else
struct sts_hdlr_generic_ops sts_hdlr_ops_cycle = INJECT_DUMMY_INTERFACES();
#endif

static void
update_shadow_stats_all(void)
{
    sts_hdlr_ops_ports.update_shadow_sts();
    sts_hdlr_ops_sta_lookup.update_shadow_sts();
    sts_hdlr_ops_crypto.update_shadow_sts();
    sts_hdlr_ops_uplink.update_shadow_sts();
    sts_hdlr_ops_downlink.update_shadow_sts();
    sts_hdlr_ops_control.update_shadow_sts();

    /* needs to be always last as it depends on other stats */
    sts_hdlr_ops_cycle.update_shadow_sts();
}

static void
update_parsed_stats_all(void)
{
    sts_hdlr_ops_ports.update_parsed_sts();
    sts_hdlr_ops_sta_lookup.update_parsed_sts();
    sts_hdlr_ops_crypto.update_parsed_sts();
    sts_hdlr_ops_uplink.update_parsed_sts();
    sts_hdlr_ops_downlink.update_parsed_sts();
    sts_hdlr_ops_control.update_parsed_sts();

    /* needs to be always last as it depends on other stats */
    sts_hdlr_ops_cycle.update_parsed_sts();
}

static void
print_log_all(void)
{
    const char clr[] = { 27, '[', '2', 'J', '\0' };
    const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };
    time_t current_time = time(NULL);
    char *time = ctime(&current_time);

    /* clear screen and move to top left */
    printf("%s%s"
           "========================================= "
           "%.*s"
           " =========================================\n\n",
           clr, topLeft, (int)strlen(time)-1, time);

    sts_hdlr_ops_ports.print_log(current_stats_print_lvl);
    sts_hdlr_ops_sta_lookup.print_log(current_stats_print_lvl);
    sts_hdlr_ops_crypto.print_log(current_stats_print_lvl);
    sts_hdlr_ops_uplink.print_log(current_stats_print_lvl);
    sts_hdlr_ops_downlink.print_log(current_stats_print_lvl);
    sts_hdlr_ops_control.print_log(current_stats_print_lvl);

    /* needs to be always last as it depends on other stats */
    sts_hdlr_ops_cycle.print_log(current_stats_print_lvl);
}

static void
init_sts_hdlr_all(struct app_params *app)
{
    sts_hdlr_ops_ports.init(app);
    sts_hdlr_ops_sta_lookup.init(app);
    sts_hdlr_ops_crypto.init(app);
    sts_hdlr_ops_uplink.init(app);
    sts_hdlr_ops_downlink.init(app);
    sts_hdlr_ops_control.init(app);

    /* needs to be always last as it depends on other stats */
    sts_hdlr_ops_cycle.init(app);
}

static void
free_sts_hdlr_all(void)
{
    sts_hdlr_ops_ports.free();
    sts_hdlr_ops_sta_lookup.free();
    sts_hdlr_ops_crypto.free();
    sts_hdlr_ops_uplink.free();
    sts_hdlr_ops_downlink.free();
    sts_hdlr_ops_control.free();

    /* needs to be always last as it depends on other stats */
    sts_hdlr_ops_cycle.free();
}

static void
capture_stats_all(void)
{
    sts_hdlr_ops_ports.capture();
    sts_hdlr_ops_sta_lookup.capture();
    sts_hdlr_ops_crypto.capture();
    sts_hdlr_ops_uplink.capture();
    sts_hdlr_ops_downlink.capture();
    sts_hdlr_ops_control.capture();

    /* needs to be always last as it depends on other stats */
    sts_hdlr_ops_cycle.capture();
}

static void
clear_stats_all(void)
{
    sts_hdlr_ops_ports.clear_sts();
    sts_hdlr_ops_sta_lookup.clear_sts();
    sts_hdlr_ops_crypto.clear_sts();
    sts_hdlr_ops_uplink.clear_sts();
    sts_hdlr_ops_downlink.clear_sts();
    sts_hdlr_ops_control.clear_sts();

    /* needs to be always last as it depends on other stats */
    sts_hdlr_ops_cycle.clear_sts();
}

static void
clear_stats_on_user_input(void)
{
    int clear_sts = 0;
    FILE *filestream;

    filestream = fopen(RWPA_CLEAR_STATS_FILENAME, "r");
    if (filestream) {
        int c;
        while ((c = fgetc(filestream)) != EOF) {
            if (c == '1') {
                clear_sts = 1;
                break;
            } else if (c == '0') {
                /* file already created and 0 - nothing to do */
                fclose(filestream);
                return;
            } else {
                /* file exists but with garbage, clear it later on */
                break;
            }
        }

        fclose(filestream);
    }

    filestream = fopen(RWPA_CLEAR_STATS_FILENAME, "w");
    if (filestream) {
        ftruncate(fileno(filestream), 1);
        fputs("0\n\0", filestream);
        fclose(filestream);

        if (clear_sts) {
            clear_stats_all();
            rte_delay_ms(10); /* wait a bit for some stats to trickle in */
        }
    }
}

static void
statistic_handler_refresh(__attribute__((unused)) struct rte_timer *ptr_timer,
                          __attribute__((unused)) void *ptr_data)
{
    clear_stats_on_user_input();

    capture_stats_all();
    update_shadow_stats_all();
    update_parsed_stats_all();
}

static void
statistic_handler_print(__attribute__((unused)) struct rte_timer *ptr_timer,
                        __attribute__((unused)) void *ptr_data)
{
    print_log_all();
}

static void *
thread_statistics_handler_init(struct app_thread_params *p, void *arg)
{
    struct app_params *app = (struct app_params *)arg;
    unsigned lcore_id, socket_id;
    uint8_t init_retries;

    g_app = app;
    tp_stats = p;

    lcore_id  = rte_lcore_id();
    socket_id = rte_socket_id();

    rte_timer_subsystem_init();

    rte_timer_init(&stats_print_timer);
    rte_timer_init(&stats_refresh_timer);

    /* check the stats verbosity level */
    switch (g_app->stat_params.stats_level) {
    case RWPA_STS_LVL_OFF:
        RTE_LOG(CRIT, RWPA_STATS,
                "All Statistics Capture Disabled\n");
        break;
    case RWPA_STS_LVL_PORTS_ONLY:
        RTE_LOG(CRIT, RWPA_STATS,
                "Statistics Capture Ports and Rings only\n");
        break;
    case RWPA_STS_LVL_APP:
        RTE_LOG(CRIT, RWPA_STATS,
                "Statistics Capture General Totals for all Components\n");
        break;
    case RWPA_STS_LVL_DETAILED:
        RTE_LOG(CRIT, RWPA_STATS,
                "Statistics Capture Detailed for all Components\n");
        break;
    default:
        rte_exit(EXIT_FAILURE,
                 "Incorrect Stats Level [%d], max supported [%d]\n",
                 g_app->stat_params.stats_level, RWPA_STS_LVL_DELIMITER -1);
        break;
    }

    /* set verbosity level for printing out stats */
    current_stats_print_lvl = g_app->stat_params.stats_level;

    init_retries = 5;
    do {
        /*
         * check if all enabled stats capture classes
         * finished initialisation
         */
        if (stats_capture_are_all_classes_inited()) {
            init_sts_hdlr_all(g_app);
            break;
        }
        RTE_LOG(INFO, RWPA_STATS,
                "%s - still waiting for stats to be initialised\n",
                tp_stats->name);
        rte_delay_ms(1000);
    } while (--init_retries);

    if (0  == init_retries)
        rte_exit(EXIT_FAILURE,
                 "Unable to init %s - stats not initialised\n",
                 tp_stats->name);

    RTE_LOG(INFO, RWPA_STATS,
            "%s (%s): Initializing on lcore %u (socket %u)\n",
            tp_stats->name, tp_stats->type, lcore_id, socket_id);

    return NULL;
}

static int
thread_statistics_handler_run(__attribute__((unused)) void *arg)
{
    unsigned lcore_id, socket_id;
    uint32_t print_period;
    uint32_t refresh_period;

    lcore_id = rte_lcore_id();
    socket_id = rte_socket_id();

    RTE_LOG(INFO, RWPA_STATS,
            "%s (%s): Entering main loop on lcore %u (socket %u)\n",
            tp_stats->name, tp_stats->type, lcore_id, socket_id);

    print_period = g_app->stat_params.stats_print_period_ms;
    refresh_period = g_app->stat_params.stats_refresh_period_global_ms;

    if (refresh_period > 0) {
        if (rte_timer_reset(&stats_refresh_timer,
                            (refresh_period * rte_get_timer_hz()) / 1000,
                            PERIODICAL,
                            rte_lcore_id(),
                            (void(*)(struct rte_timer*, void*))
                            &statistic_handler_refresh,
                            NULL) != 0)
            rte_exit(EXIT_FAILURE,
                     "%s - stats refresh timer setup failure\n",
                     tp_stats->name);

        /* only print stats if they are refreshed */
        if (print_period > 0) {
            if (rte_timer_reset(&stats_print_timer,
                                (print_period * rte_get_timer_hz()) / 1000,
                                PERIODICAL,
                                rte_lcore_id(),
                                (void(*)(struct rte_timer*, void*))
                                &statistic_handler_print,
                                NULL) != 0)
                rte_exit(EXIT_FAILURE,
                         "%s - stats print timer setup failure\n",
                         tp_stats->name);
        }
    }

    while (!force_quit) {
        rte_timer_manage();
        rte_delay_ms(5);
    }

    return 0;
}

static int
thread_statistics_handler_free(__attribute__((unused)) void *arg)
{
    unsigned lcore_id, socket_id;

    lcore_id = rte_lcore_id();
    socket_id = rte_socket_id();

    RTE_LOG(INFO, RWPA_STATS,
            "%s (%s): Freeing on lcore %u (socket %u)\n",
            tp_stats->name, tp_stats->type, lcore_id, socket_id);

    free_sts_hdlr_all();

    return 0;
}

static struct thread_ops_s thread_statistics_handler_ops = {
    .f_init = thread_statistics_handler_init,
    .f_free = thread_statistics_handler_free,
    .f_run  = thread_statistics_handler_run,
};

struct thread_type thread_statistics_handler = {
    .name = "STATISTICS_HANDLER_THREAD",
    .thread_ops = &thread_statistics_handler_ops,
};
