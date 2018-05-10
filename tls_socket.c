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

#include "tls_socket.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <rte_mbuf.h>

#include "wpapt_cdi.h"
#include "r-wpa_global_vars.h"

static struct rte_mempool *mp;

static void
set_nonblock(int socket) {
    int flags;
    flags = fcntl(socket,F_GETFL,0);
    fcntl(socket, F_SETFL, flags | O_NONBLOCK);
}

#ifndef RWPA_NO_TLS
static void
openssl_init(void)
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

static void
openssl_cleanup(void)
{
    EVP_cleanup();
}

static SSL_CTX *
openssl_create_context(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        rte_panic("Unable to create ssl context\n");
    }

    return ctx;
}

static void
openssl_configure_context(SSL_CTX *ctx, char *certs_dir, char *passwd)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);
    char cert[100];

    /* load certificate files */
    sprintf(cert, "%sroot.crt", certs_dir);
    if (SSL_CTX_load_verify_locations(ctx, cert, NULL) <=0) {
        SSL_CTX_free(ctx);
        rte_panic("Could not verify ssl cert location\n");
    }

    /* set the server cert */
    sprintf(cert, "%sdvnf.crt", certs_dir);
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        rte_panic("Unable to use ssl cert\n");
    }

    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)passwd);

    /* set private key */
    sprintf(cert, "%sdvnf.key", certs_dir);
    if (SSL_CTX_use_PrivateKey_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 ) {
        SSL_CTX_free(ctx);
        rte_panic("Unable to use ssl private key\n");
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        SSL_CTX_free(ctx);
        rte_panic("Could not verify private key against public cert\n");
    }
}
#endif

static int
create_tcp_sock(uint32_t server_inet_addr, uint16_t port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == -1) {
        RTE_LOG(ERR, RWPA_TLS, "Could not create socket\n");
        return sock;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = server_inet_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if(connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        RTE_LOG(ERR, RWPA_TLS, "Could not connect to HostAPD server: %d\n", errno);
        close(sock);
        return -1;
    }

    set_nonblock(sock);

    return sock;
}

void
tls_socket_init(struct tls_socket *socket,
                tls_handler_ctx_t *ctx,
                struct rte_mempool *mempool,
                uint32_t tls_socket_server_ip,
                uint32_t tls_ss_portid,
                struct app_misc_params *misc_params)
{
    socket->s_server = -1;
    socket->ctx = ctx;
    mp = mempool;

#ifndef RWPA_NO_TLS
    openssl_init();
    socket->ssl_ctx = openssl_create_context();
    openssl_configure_context(socket->ssl_ctx, misc_params->certs_dir, misc_params->certs_password);
#else
    UNUSED(misc_params);
#endif
    socket->s_server = create_tcp_sock(tls_socket_server_ip, tls_ss_portid);

    if(socket->s_server == -1) {
        rte_panic("Could not connect to tls socket\n");
    }
#ifndef RWPA_NO_TLS
    socket->ssl = SSL_new(socket->ssl_ctx);

    SSL_set_fd(socket->ssl, socket->s_server);

    int ssl_success = -1;
    while (ssl_success != 1) {
        ssl_success = SSL_connect(socket->ssl);
    }
#endif
}

void
tls_socket_free(void)
{
#ifndef RWPA_NO_TLS
    openssl_cleanup();
#endif
}

int
tls_socket_write(struct tls_socket *socket, struct rte_mbuf *mbuf)
{
    void *data = rte_pktmbuf_mtod(mbuf, void *);
#ifdef RWPA_NO_TLS
    int ret = write(socket->s_server, data, mbuf->data_len);
#else
    int ret = SSL_write(socket->ssl, data, mbuf->data_len);
#endif
    return ret;
}

uint32_t
poll_sock(struct tls_socket *tls, struct rte_mbuf **pkts_burst, uint16_t nb_pkts)
{
    uint32_t nb_rx = 0;
    uint16_t rlen = 0;
    int activity;
    unsigned int read_bytes = 0;

    fd_set readfds;

    struct timeval tv = {0,0};

    unsigned int new_mbuf_needed = TRUE;
    struct rte_mbuf *mbuf = NULL;

    while(nb_rx < nb_pkts) {
        if (new_mbuf_needed) {
            mbuf = rte_pktmbuf_alloc(mp);
            if (mbuf == NULL) {
                break;
            }
            new_mbuf_needed = FALSE;
        }

        FD_ZERO(&readfds);
        FD_SET(tls->s_server, &readfds);

        activity = select(tls->s_server + 1, &readfds, NULL, NULL, &tv);

        if (activity > 0 && FD_ISSET(tls->s_server, &readfds)) {
            struct wpapt_cdi_msg_header *data = rte_pktmbuf_mtod(mbuf, struct wpapt_cdi_msg_header *);
#ifdef RWPA_NO_TLS
            rlen = read(tls->s_server, (uint8_t *)data + read_bytes, WPAPT_CDI_MAX_MSG - read_bytes);
#else
            rlen = SSL_read(tls->ssl, (uint8_t *)data + read_bytes, WPAPT_CDI_MAX_MSG - read_bytes);
#endif

            /* no more data */
            if (unlikely(rlen < 1 || errno)) {
                rte_pktmbuf_free(mbuf);
                break;
            }

            read_bytes += rlen;

            /* check if a full header has been received */
            if (read_bytes < sizeof(struct wpapt_cdi_msg_header)) {
                continue;
            }

            /* check validity of message  */
#ifdef RWPA_NO_TLS
            data->magic = ntohl(data->magic);
            data->message_id = ntohs(data->message_id);
            data->payload_len = ntohs(data->payload_len);
#endif
            if (data->magic != WPAPT_CDI_MAGIC ||
                data->message_id < 1 ||
                data->payload_len > WPAPT_CDI_MAX_MSG) {
                read_bytes = 0;
                continue;
            }

            /* check if all data from message has been received */
            if ((read_bytes - sizeof(struct wpapt_cdi_msg_header)) < data->payload_len) {
                continue;
            }

            mbuf->data_len = read_bytes;
            mbuf->pkt_len = read_bytes;
            pkts_burst[nb_rx++] = mbuf;

            new_mbuf_needed = TRUE;
            read_bytes = 0;
        } else {
            rte_pktmbuf_free(mbuf);
            break;
        }
    }

    return nb_rx;
}
