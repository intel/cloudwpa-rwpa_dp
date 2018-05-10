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

#ifndef __INCLUDE_SEQ_NUM_H__
#define __INCLUDE_SEQ_NUM_H__

#include <rte_atomic.h>

typedef rte_atomic16_t      seq_num_t;
typedef uint8_t             seq_num_val_t;

#define SEQ_NUM_DEFAULT_VAL (0)

/*
 * Set Sequence Number
 */
static inline void
seq_num_set(seq_num_t *seq_num, seq_num_val_t val)
{
    rte_atomic16_set(seq_num, val);
}

/*
 * Get Sequence Number
 */
static inline seq_num_val_t
seq_num_get(seq_num_t *seq_num)
{
    return (seq_num_val_t)rte_atomic16_read(seq_num);
}

/*
 * Increment Sequence Number
 */
static inline seq_num_val_t
seq_num_increment(seq_num_t *seq_num)
{
    return (seq_num_val_t)rte_atomic16_add_return(seq_num, 1);
}

#endif // __INCLUDE_SEQ_NUM_H__
