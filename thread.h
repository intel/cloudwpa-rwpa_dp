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

#ifndef __INCLUDE_THREAD_H__
#define __INCLUDE_THREAD_H__

#ifndef APP_THREAD_TYPE_SIZE
#define APP_THREAD_TYPE_SIZE                 64
#endif

#ifndef APP_MAX_THREAD_ARGS
#define APP_MAX_THREAD_ARGS                  64
#endif

#define APP_MAX_THREAD_PKTQ_IN                2
#define APP_MAX_THREAD_PKTQ_OUT               2

#ifndef THREAD_MAX_PORT_IN
#define THREAD_MAX_PORT_IN                   64
#endif

#ifndef THREAD_MAX_PORT_OUT
#define THREAD_MAX_PORT_OUT                  64
#endif

#include <rte_common.h>
#include <rte_port_ethdev.h>

struct app_thread_params;

typedef void* (*thread_ops_init)(struct app_thread_params *params, void *arg);

typedef int (*thread_ops_free)(void *arg);

typedef int (*thread_ops_run)(void *arg);

struct thread_ops_s {
    thread_ops_init f_init;
    thread_ops_free f_free;
    thread_ops_run  f_run;
};

struct thread_type {
    const char *name;
    struct thread_ops_s *thread_ops;
};

enum app_pktq_in_type {
    APP_PKTQ_IN_HWQ,
};

struct app_pktq_in_params {
    enum app_pktq_in_type type;
    uint32_t id; /* Position in the appropriate app array */
};

enum app_pktq_out_type {
    APP_PKTQ_OUT_HWQ,
};

struct app_pktq_out_params {
    enum app_pktq_out_type type;
    uint32_t id; /* Position in the appropriate app array */
};

enum thread_port_in_type {
    THREAD_PORT_IN_ETHDEV_READER,
};

enum thread_port_out_type {
    THREAD_PORT_OUT_ETHDEV_WRITER,
    THREAD_PORT_OUT_ETHDEV_WRITER_NODROP,
};

struct thread_port_in_params {
    enum thread_port_in_type type;
    union {
        struct rte_port_ethdev_reader_params ethdev;
    } params;
    uint32_t burst_size;
};

struct thread_port_out_params {
    enum thread_port_out_type type;
    struct rte_eth_dev_tx_buffer *tx_buffer;
    union {
        struct rte_port_ethdev_writer_params ethdev;
        struct rte_port_ethdev_writer_nodrop_params ethdev_nodrop;
    } params;
    uint32_t burst_size;
};

static inline void *
thread_port_in_params_convert(struct thread_port_in_params *p)
{
    switch (p->type) {
        case THREAD_PORT_IN_ETHDEV_READER:
            return (void *) &p->params.ethdev;
        default:
            return NULL;
    }
}

static inline int
thread_port_in_get_id(struct thread_port_in_params *p)
{
    switch (p->type) {
        case THREAD_PORT_IN_ETHDEV_READER:
            return p->params.ethdev.port_id;
        default:
            return -1;
    }
}

static inline void *
thread_port_out_params_convert(struct thread_port_out_params *p)
{
    switch (p->type) {
        case THREAD_PORT_OUT_ETHDEV_WRITER:
            return (void *) &p->params.ethdev;
        case THREAD_PORT_OUT_ETHDEV_WRITER_NODROP:
            return (void *) &p->params.ethdev_nodrop;
        default:
            return NULL;
    }
}

static inline int
thread_port_out_get_id(struct thread_port_out_params *p)
{
    switch (p->type) {
        case THREAD_PORT_OUT_ETHDEV_WRITER:
            return p->params.ethdev.port_id;
        case THREAD_PORT_OUT_ETHDEV_WRITER_NODROP:
            return p->params.ethdev_nodrop.port_id;
        default:
            return -1;
    }
}

static inline void*
thread_port_out_get_tx_buffer(struct thread_port_out_params *p)
{
    switch (p->type) {
        case THREAD_PORT_OUT_ETHDEV_WRITER:
        case THREAD_PORT_OUT_ETHDEV_WRITER_NODROP:
            return p->tx_buffer;
        default:
            return NULL;
    }
}

static inline int
thread_port_out_get_queue_id(struct thread_port_out_params *p)
{
    switch (p->type) {
        case THREAD_PORT_OUT_ETHDEV_WRITER:
            return p->params.ethdev.queue_id;
        case THREAD_PORT_OUT_ETHDEV_WRITER_NODROP:
            return p->params.ethdev_nodrop.queue_id;
        default:
            return -1;
    }
}

struct app_thread_params {
    char *name;
    char type[APP_THREAD_TYPE_SIZE];
    uint8_t parsed;
    uint32_t socket_id;
    uint32_t core_id;
    uint32_t hyper_th_id;
    uint32_t lcore_id;
    char *args_name[APP_MAX_THREAD_ARGS];
    char *args_value[APP_MAX_THREAD_ARGS];
    struct thread_type *ttype;
    uint32_t enabled;
    struct app_pktq_in_params pktq_in[APP_MAX_THREAD_PKTQ_IN];
    struct app_pktq_out_params pktq_out[APP_MAX_THREAD_PKTQ_OUT];
    uint32_t n_args;
    uint32_t n_pktq_in;
    uint32_t n_pktq_out;
    struct thread_port_in_params port_in[THREAD_MAX_PORT_IN];
    struct thread_port_out_params port_out[THREAD_MAX_PORT_OUT];
    uint32_t n_ports_in;
    uint32_t n_ports_out;
    uint16_t crypto_qp;
};

#endif // __INCLUDE_THREAD_H__
