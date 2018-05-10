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

#ifndef __INCLUDE_STATISTICS_CAPTURE_DOWNLINK_H__
#define __INCLUDE_STATISTICS_CAPTURE_DOWNLINK_H__

enum stats_downlink_drops_type {
    STATS_DL_DROPS_TYPE_PACKET_DECAP_ERROR = 0,
    STATS_DL_DROPS_TYPE_STATION_NOT_FOUND,
    STATS_DL_DROPS_TYPE_NO_STATION_KEY,
    STATS_DL_DROPS_TYPE_WIFI_CONVERT_ERROR,
    STATS_DL_DROPS_TYPE_ENCRYPTION_ERROR,
    STATS_DL_DROPS_TYPE_FRAGMENTATION_ERROR,
    STATS_DL_DROPS_TYPE_PACKET_ENCAP_ERROR,
    STATS_DL_DROPS_TYPE_BROAD_MULTI_CAST_PACKET,
    STATS_DL_DROPS_TYPE_UNEXPECTED_PACKET_TYPE,

    /* add new types before this one */
    STATS_DL_DROPS_TYPE_DELIM
};

struct stats_downlink_drops {
    uint64_t packet_decap_error;
    uint64_t station_not_found;
    uint64_t no_station_key;
    uint64_t wifi_convert_error;
    uint64_t encryption_error;
    uint64_t fragmentation_error;
    uint64_t packet_encap_error;
    uint64_t broad_multi_cast_packet;
    uint64_t unexpected_packet_type;
};

void
stats_capture_downlink_init(struct app_params *app);

void
stats_capture_downlink_free(void);

uint8_t
stats_capture_downlink_is_inited(void);

struct stats_downlink_drops *
stats_capture_downlink_drops_get_mem_info(void);

size_t
stats_capture_downlink_drops_get_mem_info_size(void);

void
stats_capture_downlink_drops_inc(enum stats_downlink_drops_type type,
                                 uint64_t amt);

struct stats_pmd_reads *
stats_capture_downlink_pmd_reads_get_mem_info(void);

void
stats_capture_downlink_pmd_reads_inc(enum stats_pmd_reads_type type,
                                     uint64_t amt);

#endif // __INCLUDE_STATISTICS_CAPTURE_DOWNLINK_H__
