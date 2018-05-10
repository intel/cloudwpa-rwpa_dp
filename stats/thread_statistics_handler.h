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

#ifndef __INCLUDE_THREAD_STATISTICS_HANDLER_H__
#define __INCLUDE_THREAD_STATISTICS_HANDLER_H__

#ifndef RWPA_CLEAR_STATS_FILENAME
#define RWPA_CLEAR_STATS_FILENAME "/root/clear_rwpa_stats_control_file.txt"
#endif

typedef void (*sts_hdlr_generic_ops_init)(struct app_params *app);
typedef void (*sts_hdlr_generic_ops_free)(void);
typedef void (*sts_hdlr_generic_ops_capture)(void);
typedef void (*sts_hdlr_generic_ops_update_shadow_sts)(void);
typedef void (*sts_hdlr_generic_ops_update_parsed_sts)(void);
typedef void (*sts_hdlr_generic_ops_clear_sts)(void);
typedef void (*sts_hdlr_generic_ops_print_log)(enum rwpa_stats_lvl);

struct sts_hdlr_generic_ops {
    sts_hdlr_generic_ops_init               init;
    sts_hdlr_generic_ops_free               free;
    sts_hdlr_generic_ops_capture            capture;
    sts_hdlr_generic_ops_update_shadow_sts  update_shadow_sts;
    sts_hdlr_generic_ops_update_parsed_sts  update_parsed_sts;
    sts_hdlr_generic_ops_clear_sts          clear_sts;
    sts_hdlr_generic_ops_print_log          print_log;
};

static inline void
sts_hdlr_generic_dummy(void)
{
}

static inline void
sts_hdlr_generic_init_dummy(__attribute__((unused)) struct app_params *app)
{
}

static inline void
sts_hdlr_generic_print_dummy(__attribute__((unused)) enum rwpa_stats_lvl unused)
{
}

extern struct thread_type thread_statistics_handler;

#endif // __INCLUDE_THREAD_STATISTICS_HANDLER_H__
