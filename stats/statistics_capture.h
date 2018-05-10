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

#ifndef __INCLUDE_STATISTICS_CAPTURE_H__
#define __INCLUDE_STATISTICS_CAPTURE_H__

#include "app.h"
#include "statistics_capture_common.h"
#include "statistics_capture_ports.h"
#include "statistics_capture_sta_lookup.h"
#include "statistics_capture_crypto.h"
#include "statistics_capture_uplink.h"
#include "statistics_capture_downlink.h"
#include "statistics_capture_control.h"

static inline void
stats_generic_free_dummy(void)
{
}

static inline void
stats_generic_init_dummy(__attribute__((unused)) struct app_params *app)
{
}

typedef void (*stats_generic_ops_init)(struct app_params *app);
typedef void (*stats_generic_ops_free)(void);

struct stats_generic_ops {
    stats_generic_ops_init f_init;
    stats_generic_ops_free f_free;
};

void
stats_capture_init_all(struct app_params *app);

uint8_t
stats_capture_are_all_classes_inited(void);

void
stats_capture_free_all(void);

#endif // __INCLUDE_STATISTICS_CAPTURE_H__

