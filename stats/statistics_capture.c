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

#include <stdint.h>
#include <stdio.h>

#include "statistics_capture.h"

#ifndef RWPA_STATS_CAPTURE_PORTS_OFF
static struct stats_generic_ops stats_ports_ops = {
    .f_init = stats_capture_ports_init,
    .f_free = stats_capture_ports_free,
};
#else
static struct stats_generic_ops stats_ports_ops = {
    .f_init = stats_generic_init_dummy,
    .f_free = stats_generic_free_dummy,
};
#endif

#ifndef RWPA_STATS_CAPTURE_STA_LOOKUP_OFF
static struct stats_generic_ops stats_sta_lookup_ops = {
    .f_init = stats_capture_sta_lookup_init,
    .f_free = stats_capture_sta_lookup_free,
};
#else
static struct stats_generic_ops stats_sta_lookup_ops = {
    .f_init = stats_generic_init_dummy,
    .f_free = stats_generic_free_dummy,
};
#endif

#ifndef RWPA_STATS_CAPTURE_CRYPTO_OFF
static struct stats_generic_ops stats_crypto_ops = {
    .f_init = stats_capture_crypto_init,
    .f_free = stats_capture_crypto_free,
};
#else
static struct stats_generic_ops stats_crypto_ops = {
    .f_init = stats_generic_init_dummy,
    .f_free = stats_generic_free_dummy,
};
#endif

#ifndef RWPA_STATS_CAPTURE_UPLINK_OFF
static struct stats_generic_ops stats_uplink_ops = {
    .f_init = stats_capture_uplink_init,
    .f_free = stats_capture_uplink_free,
};
#else
static struct stats_generic_ops stats_uplink_ops = {
    .f_init = stats_generic_init_dummy,
    .f_free = stats_generic_free_dummy,
};
#endif

#ifndef RWPA_STATS_CAPTURE_DOWNLINK_OFF
static struct stats_generic_ops stats_downlink_ops = {
    .f_init = stats_capture_downlink_init,
    .f_free = stats_capture_downlink_free,
};
#else
static struct stats_generic_ops stats_downlink_ops = {
    .f_init = stats_generic_init_dummy,
    .f_free = stats_generic_free_dummy,
};
#endif

#ifndef RWPA_STATS_CAPTURE_CONTROL_OFF
static struct stats_generic_ops stats_control_ops = {
    .f_init = stats_capture_control_init,
    .f_free = stats_capture_control_free,
};
#else
static struct stats_generic_ops stats_control_ops = {
    .f_init = stats_generic_init_dummy,
    .f_free = stats_generic_free_dummy,
};
#endif

static uint8_t are_all_classes_inited = 0;

uint8_t stats_capture_are_all_classes_inited(void)
{
    return are_all_classes_inited;
}

void stats_capture_init_all(struct app_params *app)
{
    stats_ports_ops.f_init(app);
    stats_sta_lookup_ops.f_init(app);
    stats_crypto_ops.f_init(app);
    stats_uplink_ops.f_init(app);
    stats_downlink_ops.f_init(app);
    stats_control_ops.f_init(app);

    are_all_classes_inited = 1;
}

void stats_capture_free_all(void)
{
    are_all_classes_inited = 0;

    stats_control_ops.f_free();
    stats_downlink_ops.f_free();
    stats_uplink_ops.f_free();
    stats_crypto_ops.f_free();
    stats_sta_lookup_ops.f_free();
    stats_ports_ops.f_free();
}
