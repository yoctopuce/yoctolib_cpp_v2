/*********************************************************************
 *
 * $Id: yssl.c 44777 2021-04-30 09:02:57Z web $
 *
 * Implementation of a client TCP stack with SSL
 *
 * - - - - - - - - - License information: - - - - - - - - -
 *
 *  Copyright (C) 2011 and beyond by Yoctopuce Sarl, Switzerland.
 *
 *  Yoctopuce Sarl (hereafter Licensor) grants to you a perpetual
 *  non-exclusive license to use, modify, copy and integrate this
 *  file into your software for the sole purpose of interfacing
 *  with Yoctopuce products.
 *
 *  You may reproduce and distribute copies of this file in
 *  source or object form, as long as the sole purpose of this
 *  code is to interface with Yoctopuce products. You must retain
 *  this notice in the distributed source file.
 *
 *  You should refer to Yoctopuce General Terms and Conditions
 *  for additional information regarding your rights and
 *  obligations.
 *
 *  THE SOFTWARE AND DOCUMENTATION ARE PROVIDED "AS IS" WITHOUT
 *  WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 *  WITHOUT LIMITATION, ANY WARRANTY OF MERCHANTABILITY, FITNESS
 *  FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO
 *  EVENT SHALL LICENSOR BE LIABLE FOR ANY INCIDENTAL, SPECIAL,
 *  INDIRECT OR CONSEQUENTIAL DAMAGES, LOST PROFITS OR LOST DATA,
 *  COST OF PROCUREMENT OF SUBSTITUTE GOODS, TECHNOLOGY OR
 *  SERVICES, ANY CLAIMS BY THIRD PARTIES (INCLUDING BUT NOT
 *  LIMITED TO ANY DEFENSE THEREOF), ANY CLAIMS FOR INDEMNITY OR
 *  CONTRIBUTION, OR OTHER SIMILAR COSTS, WHETHER ASSERTED ON THE
 *  BASIS OF CONTRACT, TORT (INCLUDING NEGLIGENCE), BREACH OF
 *  WARRANTY, OR OTHERWISE.
 *
 *********************************************************************/

#define __FILE_ID__  "yssl"

#ifndef NO_YSSL
#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"

#endif


#include "ydef.h"
#include "yproto.h"
#include "ytcp.h"
#include "yssl.h"


#ifndef NO_YSSL

#ifdef WINDOWS_API
#define SOCK_ERR    (WSAGetLastError())
#else
#define SOCK_ERR    (errno)
#endif
#define REPORT_ERR(msg) if(errmsg){ YSPRINTF(errmsg,YOCTO_ERRMSG_LEN,"%s (%s:%d / errno=%d)",(msg), __FILE_ID__, __LINE__, SOCK_ERR);errmsg[YOCTO_ERRMSG_LEN-1]='\0';}


#define FMT_MBEDTLS_ERR(errno) format_mbedtls_err(__FILE_ID__, __LINE__, errno, errmsg)

static int format_mbedtls_err(const char* fileid, int lineno, int err, char* errmsg)
{
    int ofs = YSPRINTF(errmsg, YOCTO_ERRMSG_LEN, "%s:%d:", fileid, lineno);
    mbedtls_strerror(err, errmsg + ofs, YOCTO_ERRMSG_LEN - ofs);
#ifdef DEBUG_SSL
    dbglogf(fileid, lineno, "mbedtls error %d (%s)\n", err, errmsg);
#endif
    return YAPI_SSL_ERROR;
}

static mbedtls_x509_crt cachain, srvcert;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;
static mbedtls_pk_context pkey;

#ifdef DEBUG_SSL

static void my_debug(void* ctx, int level, const char* file, int line, const char* str)
{
    //dbglog("%s:%04d: %s", file, line, str );
}

#endif


int yssl_generate_private_key(const char* keyfile, char* errmsg)
{
    int ret;
    mbedtls_pk_context key;
    FILE* fd;
    unsigned char output_buf[16000];
    unsigned char* c = output_buf;
    size_t len = 0;

    mbedtls_pk_init(&key);
    ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
        return FMT_MBEDTLS_ERR(ret);
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, 4096, 65537);
    if (ret != 0) {
        return FMT_MBEDTLS_ERR(ret);
    }


    memset(output_buf, 0, 16000);
    if ((ret = mbedtls_pk_write_key_pem(&key, output_buf, 16000)) != 0)
        return (ret);

    len = strlen((char*)output_buf);

    if (YFOPEN(&fd, keyfile, "wb") != 0) {
        YSPRINTF(errmsg, YOCTO_ERRMSG_LEN, "Unable to save private key to file %s", keyfile);
        return YAPI_IO_ERROR;
    }

    if (fwrite(c, 1, len, fd) != len) {
        fclose(fd);
        YSPRINTF(errmsg, YOCTO_ERRMSG_LEN, "Unable to write private in file %s", keyfile);
        return YAPI_IO_ERROR;
    }

    fclose(fd);

    return YAPI_SUCCESS;
}


int yssl_write_certificate(void* crt_void, const char* certfilename, char* errmsg)
{
    int ret;
    FILE* fd;
    unsigned char buffer[4096];
    size_t len = 0;
    mbedtls_x509write_cert* crt = crt_void;

    memset(buffer, 0, 4096);
    ret = mbedtls_x509write_crt_pem(crt, buffer, 4096, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret < 0) {
        return FMT_MBEDTLS_ERR(ret);
    }

    len = strlen((char*)buffer);

    if (YFOPEN(&fd, certfilename, "w") != 0) {
        YSPRINTF(errmsg, YOCTO_ERRMSG_LEN, "Unable to save certificate in file %s", certfilename);
        return YAPI_IO_ERROR;
    }

    if (fwrite(buffer, 1, len, fd) != len) {
        fclose(fd);
        YSPRINTF(errmsg, YOCTO_ERRMSG_LEN, "Unable to write certificate in file %s", certfilename);
        return YAPI_IO_ERROR;
    }
    fclose(fd);
    return YAPI_SUCCESS;
}


int yssl_generate_certificate(const char* keyfile, const char* certfile,
                              const char* country, const char* state,
                              const char* organisation, const char* common_name,
                              time_t expiration, char* errmsg)
{
    mbedtls_pk_context key;
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    char subject_name[1024];
    uint8_t rand_serial[20];
    struct tm timeinfo;
    time_t rawtime;
    char from[16];
    char to[16];
    const char* fmt = "%Y%m%d%H%M%S";


    mbedtls_pk_init(&key);
    mbedtls_x509write_crt_init(&crt);

    int ret = mbedtls_pk_parse_keyfile(&key, keyfile, NULL);
    if (ret != 0) {
        return FMT_MBEDTLS_ERR(ret);
    }

    mbedtls_mpi_init(&serial);
    mbedtls_ctr_drbg_random(&ctr_drbg, rand_serial, 20);
    ret = mbedtls_mpi_read_binary(&serial, rand_serial, 20);
    if (ret != 0) {
        return FMT_MBEDTLS_ERR(ret);
    }

    // self signed certificate use same key for subject and issuer
    mbedtls_x509write_crt_set_subject_key(&crt, &key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &key);

    YSPRINTF(subject_name, 1024, "C=%s,ST=%s,O=%s",
             country, state, organisation, common_name
    );

    if (common_name) {
        YSTRCAT(subject_name, 1024, ",CN=");
        YSTRCAT(subject_name, 1024, common_name);
    }
    ret = mbedtls_x509write_crt_set_subject_name(&crt, subject_name);
    if (ret != 0) {
        return FMT_MBEDTLS_ERR(ret);
    }
    ret = mbedtls_x509write_crt_set_issuer_name(&crt, subject_name);
    if (ret != 0) {
        return FMT_MBEDTLS_ERR(ret);
    }
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
    if (ret != 0) {
        return FMT_MBEDTLS_ERR(ret);
    }
    // compute time string
    time(&rawtime);
    ygmtime(&timeinfo, &rawtime);
    strftime(from, sizeof(from), fmt, &timeinfo);
    rawtime += expiration;
    ygmtime(&timeinfo, &rawtime);
    strftime(to, sizeof(to), fmt, &timeinfo);

    ret = mbedtls_x509write_crt_set_validity(&crt, from, to);
    if (ret != 0) {
        return FMT_MBEDTLS_ERR(ret);
    }
    ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 1, -1);
    if (ret < 0) {
        return FMT_MBEDTLS_ERR(ret);
    }
    ret = mbedtls_x509write_crt_set_subject_key_identifier(&crt);
    if (ret != 0) {
        return FMT_MBEDTLS_ERR(ret);
    }
    ret = yssl_write_certificate(&crt, certfile, errmsg);
    mbedtls_pk_free(&pkey);
    return ret;
}


int yTcpInitSSL(char* errmsg)
{
    int ret;
    const char* pers = "ssl_client1"; //fixme use real stuff
    SSLLOG("Init OpenSSL\n");

    mbedtls_x509_crt_init(&cachain);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pkey);

    dbglog("Seeding the random number generator...\n");
    //fixme implement something better.
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy, (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        return FMT_MBEDTLS_ERR(ret);
    }

    mbedtls_debug_set_threshold(1);
    return YAPI_SUCCESS;
}


// must be called aftery TcpInitSSL
int yTcpSetCertificateSSL(const char* certfile, const char* keyfile, char* errmsg)
{
    int ret;
    FILE* fd;

    /* Load certificate and private key files, and check consistency */
    if (keyfile) {
        if (YFOPEN(&fd, keyfile, "r") != 0) {
            return YERRMSG(YAPI_SSL_ERROR, "Private key file does not exist!");
        }
        fclose(fd);

        mbedtls_pk_free(&pkey);
        ret = mbedtls_pk_parse_keyfile(&pkey, keyfile, NULL);
        if (ret < 0) {
            return FMT_MBEDTLS_ERR(ret);
        }
        SSLLOG("certificate and private key loaded and verified\n");
    } else {
        mbedtls_pk_free(&pkey);
        mbedtls_pk_init(&pkey);
    }

    if (certfile) {
        // load settings file
        if (YFOPEN(&fd, certfile, "r") != 0) {
            return YERRMSG(YAPI_SSL_ERROR, "SSL certificate file does not exist!");
        }
        fclose(fd);
        mbedtls_x509_crt_free(&srvcert);
        ret = mbedtls_x509_crt_parse_file(&srvcert, certfile);
        if (ret < 0) {
            return FMT_MBEDTLS_ERR(ret);
        }
        SSLLOG("certificate and private key loaded and verified\n");
    } else {
        mbedtls_x509_crt_free(&srvcert);
        mbedtls_x509_crt_init(&srvcert);
    }

    return YAPI_SUCCESS;
}

void yTcpShutdownSSL(void)
{
    SSLLOG("YSSL: shutdown\n");

    mbedtls_x509_crt_free(&cachain);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}


static int mbedtls_ysend(void* ctx, const unsigned char* buf, size_t tosend)
{
    char errmsg[YOCTO_ERRMSG_LEN];
    YSSL_SOCKET yssl = ctx;
    //dbglog("need to send %d bytes encrypted\n", tosend);
    int res = yTcpWriteBasic(yssl->tcpskt, buf, (int)tosend, errmsg);
    if (res < 0) {
        dbglog("Unable to send encrypted data(%s)\n", errmsg);
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    //dbglog("sent %d bytes encrypted on socket %d\n", res, yssl->tcpskt);
    return res;
}


// The callback must return the number of bytes received, or a non-zero error code.
// If performing non-blocking I/O, MBEDTLS_ERR_SSL_WANT_READ must be returned when the operation would block.

static int mbedtls_yread(void* ctx, unsigned char* buf, size_t avail)
{
    char errmsg[YOCTO_ERRMSG_LEN];
    YSSL_SOCKET yssl = ctx;
    //dbglog("try to read %d bytes encrypted on socket %d\n", avail, yssl->tcpskt);
    int readed = yTcpReadBasic(yssl->tcpskt, buf, (int)avail, errmsg);
    //dbglog("readed %d bytes encrypted on socket %d\n", readed, yssl->tcpskt);
    if (readed == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else if (readed == YAPI_NO_MORE_DATA) {
        return 0;
    } else if (readed < 0) {
        dbglog("Unable to read encrypted data(%s)\n", errmsg);
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    return readed;
}


static int do_ssl_handshake(YSSL_SOCKET yssl, char* errmsg)
{
    int ret;

    while ((ret = mbedtls_ssl_handshake(yssl->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return FMT_MBEDTLS_ERR(ret);
        }
    }
    SSLLOG("SSL handshake done\n");
    return YAPI_SUCCESS;
}


static int setup_ssl(yssl_socket_st* yssl, int server_mode, char* errmsg)
{
    int res;

    // we cannot share mbedtls config can be between multiples context
    // since some of our socket work as client and other work as server.
    yssl->ssl_conf = yMalloc(sizeof(mbedtls_ssl_config));
    mbedtls_ssl_config_init(yssl->ssl_conf);
    res = mbedtls_ssl_config_defaults(yssl->ssl_conf,
                                      server_mode ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);

    if (res != 0) {
        yFree(yssl->ssl_conf);
        return FMT_MBEDTLS_ERR(res);
    }

    mbedtls_ssl_conf_ca_chain(yssl->ssl_conf, &cachain, NULL);
    mbedtls_ssl_conf_rng(yssl->ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);


    //mbedtls_ssl_conf_authmode( yssl->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    if (server_mode) {
        res = mbedtls_ssl_conf_own_cert(yssl->ssl_conf, &srvcert, &pkey);
        if (res != 0) {
            yFree(yssl->ssl_conf);
            return FMT_MBEDTLS_ERR(res);
        }
    } else {
        mbedtls_ssl_conf_authmode(yssl->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    }


#ifdef DEBUG_SSL
    // activate debug logs
    mbedtls_ssl_conf_dbg(yssl->ssl_conf, my_debug, yssl);
#endif

    // create SSL context
    yssl->ssl = yMalloc(sizeof(mbedtls_ssl_context));
    mbedtls_ssl_init(yssl->ssl);
    if ((res = mbedtls_ssl_setup(yssl->ssl, yssl->ssl_conf)) != 0) {
        yFree(yssl->ssl_conf);
        yFree(yssl->ssl);
        return FMT_MBEDTLS_ERR(res);
    }

    mbedtls_ssl_set_bio(yssl->ssl, yssl, mbedtls_ysend, mbedtls_yread, NULL);

    // do handshake
    res = do_ssl_handshake(yssl, errmsg);
    if (res < 0) {
        yFree(yssl->ssl_conf);
        yFree(yssl->ssl);
        return res;
    }
    return YAPI_SUCCESS;
}


int yTcpOpenSSL(YSSL_SOCKET* newskt, IPvX_ADDR* ip, u16 port, u64 mstimeout, char* errmsg)
{
    int res;
    yssl_socket_st* yssl;

    SSLLOG("YSSL: openssl %p [dst=%d:%d %dms]\n", newskt, ip, port, mstimeout);
    yssl = yMalloc(sizeof(yssl_socket_st));
    memset(yssl, 0, sizeof(yssl_socket_st));

    res = yTcpOpenBasic(&yssl->tcpskt, ip, port, mstimeout, errmsg);
    if (res < 0) {
        return res;
    }

    res = setup_ssl(yssl, 0, errmsg);
    if (res < 0) {
        yFree(yssl);
        return res;
    }

    SSLLOG("SSL socket opened\n");
    *newskt = yssl;
    return YAPI_SUCCESS;
}

int yTcpAcceptSSL(YSSL_SOCKET* newskt, YSOCKET sock, char* errmsg)
{
    int res;
    yssl_socket_st* yssl;
    SSLLOG("YSSL: accept %p [skt=%d]\n", newskt, sock);
    yssl = yMalloc(sizeof(yssl_socket_st));
    memset(yssl, 0, sizeof(yssl_socket_st));
    yssl->tcpskt = sock;
    res = setup_ssl(yssl, 1, errmsg);
    if (res < 0) {
        yFree(yssl);
        return res;
    }
    SSLLOG("SSL socket opened\n");
    *newskt = yssl;
    return YAPI_SUCCESS;
}


void yTcpCloseSSL(YSSL_SOCKET yssl)
{
    SSLLOG("YSSL: close (sock=%p)\n", yssl);
    yTcpCloseBasic(yssl->tcpskt);
    mbedtls_ssl_free(yssl->ssl);
    mbedtls_ssl_config_free(yssl->ssl_conf);
    yFree(yssl->ssl);
    yFree(yssl->ssl_conf);
    yFree(yssl);
}

YSOCKET yTcpFdSetSSL(YSSL_SOCKET yssl, void* set, YSOCKET sktmax)
{
#if 0
    //SSLLOG("SSL: FD_SET %p\n", yssl);
    char errmsg[YOCTO_ERRMSG_LEN];
    int res = ssl_flush_on_socket(yssl, 0, errmsg);
    if (res < 0) {
        dbglog("SSL err %d:%s\n", res, errmsg);
    }

#endif
    FD_SET(yssl->tcpskt, (fd_set*)set);
    if (yssl->tcpskt > sktmax) {
        sktmax = yssl->tcpskt;
    }
    //int pending = mbedtls_ssl_check_pending(yssl->ssl);
    //SSLLOG("YSSL: %d bytes pending on setfd\n", pending);
    return sktmax;
}

int yTcpFdIsSetSSL(YSSL_SOCKET yssl, void* set)
{
    int res = FD_ISSET(yssl->tcpskt, (fd_set*)set);
    //dbglog("YSSL: socket is_set -> %d\n", res);
    if (!res) {
        int peek_res = mbedtls_ssl_check_pending(yssl->ssl);
        //dbglog("YSSL: fd_isset=%d peek returned %d -> %d\n", res, peek_res);
        if (peek_res > 0) {
            res = 1;
        }
    }
    //SSLLOG("SSL: FD_ISSET %p->%d\n", yssl, res);
    return res;
}


// check it a socket is still valid and empty (ie: nothing to read and writable)
// return 1 if the socket is valid or a error code
int yTcpCheckSocketStillValidSSL(YSSL_SOCKET yssl, char* errmsg)
{
    SSLLOG("YSSL: check validity (sock=%p)\n", yssl);
    if (yssl->flags & YSSL_TCP_SOCK_CLOSED) {
        return 0;
    }
    return yTcpCheckSocketStillValidBasic(yssl->tcpskt, errmsg);;
}


int yTcpWriteSSL(YSSL_SOCKET yssl, const u8* buffer, int len, char* errmsg)
{
    SSLLOG("YSSL: write %d  bytes (sock=%p)\n", len, yssl);

    int consumed = mbedtls_ssl_write(yssl->ssl, buffer, len);
    if (consumed <= 0) {
        if (consumed == MBEDTLS_ERR_SSL_WANT_WRITE || consumed == MBEDTLS_ERR_SSL_WANT_READ) {
            return 0;
        } else {
            return FMT_MBEDTLS_ERR(consumed);
        }
    }

    return consumed;
}


int yTcpReadSSL(YSSL_SOCKET yssl, u8* buffer, int len, char* errmsg)
{
    int res;
    int readed = 0;
    u8* ptr = buffer;
    SSLLOG("YSSL: look for data on sock %p (buflen=%d)\n", yssl, len);

    if (yssl->flags & YSSL_TCP_SOCK_CLOSED) {
        // previous call may have ended with connection close
        return YERR(YAPI_NO_MORE_DATA);
    }

    do {
        int decrypted = 0;
        res = mbedtls_ssl_read(yssl->ssl, ptr, len);
        if (res == 0) {
            yssl->flags |= YSSL_TCP_SOCK_CLOSED;
        } else if (res < 0) {
            if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) {
                return FMT_MBEDTLS_ERR(res);
            }
        } else {
            decrypted = res;
        }
        ptr += decrypted;
        len -= decrypted;
        readed += decrypted;
    } while (len > 0 && res > 0);

    if (readed == 0 && yssl->flags & YSSL_TCP_SOCK_CLOSED) {
        return YERR(YAPI_NO_MORE_DATA);
    }

    SSLLOG("YSSL: readed %d  bytes (sock=%p)\n", readed, yssl);
    return readed;
}


u32 yTcpGetRcvBufSizeSSL(YSSL_SOCKET skt)
{
    //fixme: look if we have some limitaiton due to SSL
    return yTcpGetRcvBufSizeBasic(skt->tcpskt);
}

#endif
