/**
 * \file sc_mbedtls_md.c
 *
 * \brief Generic message digest wrapper for mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if (defined(CONFIG_SEC_CRYPTO_SHA_SW) || defined(CONFIG_SEC_CRYPTO_RSA_SW))

#include "crypto_config.h"
#include "crypto_md.h"
#include "crypto_md_internal.h"
#include <stdlib.h>
#include <string.h>

#define mbedtls_calloc calloc
#define mbedtls_free free

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize(void *v, size_t n)
{
    volatile unsigned char *p = v;
    while (n--)
        *p++ = 0;
}

/*
 * Reminder: update profiles in x509_crt.c when adding a new hash!
 */
static const int supported_digests[] = {

#if defined(MBEDTLS_SHA512_C)
    SC_MBEDTLS_MD_SHA512,    SC_MBEDTLS_MD_SHA384,
#endif

#if defined(MBEDTLS_SHA256_C)
    SC_MBEDTLS_MD_SHA256,    SC_MBEDTLS_MD_SHA224,
#endif

#if defined(MBEDTLS_SHA1_C)
    SC_MBEDTLS_MD_SHA1,
#endif

#if defined(MBEDTLS_RIPEMD160_C)
    SC_MBEDTLS_MD_RIPEMD160,
#endif

#if (defined(SC_MBEDTLS_MD5_C) && defined(SC_MBEDTLS_MD5_WRAP))
    SC_MBEDTLS_MD_MD5,
#endif

#if defined(SC_MBEDTLS_MD4_C)
    SC_MBEDTLS_MD_MD4,
#endif

#if defined(SC_MBEDTLS_MD2_C)
    SC_MBEDTLS_MD_MD2,
#endif

    SC_MBEDTLS_MD_NONE};

const int *sc_mbedtls_md_list(void)
{
    return (supported_digests);
}

const sc_mbedtls_md_info_t *sc_mbedtls_md_info_from_string(const char *md_name)
{
    if (NULL == md_name)
        return (NULL);

    if (!strcmp("SHA1", md_name) || !strcmp("SHA", md_name))
        return sc_mbedtls_md_info_from_type(SC_MBEDTLS_MD_SHA1);
    if (!strcmp("SHA224", md_name))
        return sc_mbedtls_md_info_from_type(SC_MBEDTLS_MD_SHA224);
    if (!strcmp("SHA256", md_name))
        return sc_mbedtls_md_info_from_type(SC_MBEDTLS_MD_SHA256);
    return (NULL);
}

const sc_mbedtls_md_info_t *sc_mbedtls_md_info_from_type(sc_mbedtls_md_type_t md_type)
{
    switch (md_type) {

        case SC_MBEDTLS_MD_SHA1:
            return (&sc_mbedtls_sha1_info);

#if defined(CONFIG_SEC_CRYPTO_SHA_SW)
        case SC_MBEDTLS_MD_SHA224:
            return (&sc_mbedtls_sha224_info);
        case SC_MBEDTLS_MD_SHA256:
            return (&sc_mbedtls_sha256_info);
#endif
        default:
            return (NULL);
    }
}

void sc_mbedtls_md_init(sc_mbedtls_md_context_t *ctx)
{
    memset(ctx, 0, sizeof(sc_mbedtls_md_context_t));
}

void sc_mbedtls_md_free(sc_mbedtls_md_context_t *ctx)
{
    if (ctx == NULL || ctx->md_info == NULL)
        return;

    if (ctx->md_ctx != NULL)
        ctx->md_info->ctx_free_func(ctx->md_ctx);

    if (ctx->hmac_ctx != NULL) {
        mbedtls_zeroize(ctx->hmac_ctx, 2 * ctx->md_info->block_size);
        mbedtls_free(ctx->hmac_ctx);
    }

    mbedtls_zeroize(ctx, sizeof(sc_mbedtls_md_context_t));
}

int sc_mbedtls_md_clone(sc_mbedtls_md_context_t *dst, const sc_mbedtls_md_context_t *src)
{
    if (dst == NULL || dst->md_info == NULL || src == NULL || src->md_info == NULL ||
        dst->md_info != src->md_info) {
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);
    }

    dst->md_info->clone_func(dst->md_ctx, src->md_ctx);

    return (0);
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int sc_mbedtls_md_init_ctx(sc_mbedtls_md_context_t *ctx, const sc_mbedtls_md_info_t *md_info)
{
    return sc_mbedtls_md_setup(ctx, md_info, 1);
}
#endif

int sc_mbedtls_md_setup(sc_mbedtls_md_context_t *ctx, const sc_mbedtls_md_info_t *md_info, int hmac)
{
    if (md_info == NULL || ctx == NULL)
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    if ((ctx->md_ctx = md_info->ctx_alloc_func()) == NULL)
        return (SC_MBEDTLS_ERR_MD_ALLOC_FAILED);

    if (hmac != 0) {
        ctx->hmac_ctx = mbedtls_calloc(2, md_info->block_size);
        if (ctx->hmac_ctx == NULL) {
            md_info->ctx_free_func(ctx->md_ctx);
            return (SC_MBEDTLS_ERR_MD_ALLOC_FAILED);
        }
    }

    ctx->md_info = md_info;

    return (0);
}

int sc_mbedtls_md_starts(sc_mbedtls_md_context_t *ctx)
{
    if (ctx == NULL || ctx->md_info == NULL)
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    ctx->md_info->starts_func(ctx->md_ctx);

    return (0);
}

int sc_mbedtls_md_update(sc_mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen)
{
    if (ctx == NULL || ctx->md_info == NULL)
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    ctx->md_info->update_func(ctx->md_ctx, input, ilen);

    return (0);
}

int sc_mbedtls_md_finish(sc_mbedtls_md_context_t *ctx, unsigned char *output)
{
    if (ctx == NULL || ctx->md_info == NULL)
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    ctx->md_info->finish_func(ctx->md_ctx, output);

    return (0);
}

int sc_mbedtls_md(const sc_mbedtls_md_info_t *md_info, const unsigned char *input, size_t ilen,
                  unsigned char *output)
{
    if (md_info == NULL)
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    md_info->digest_func(input, ilen, output);

    return (0);
}

int sc_mbedtls_md_hmac_starts(sc_mbedtls_md_context_t *ctx, const unsigned char *key, size_t keylen)
{
    unsigned char  sum[SC_MBEDTLS_MD_MAX_SIZE];
    unsigned char *ipad, *opad;
    size_t         i;

    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL)
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    if (keylen > (size_t)ctx->md_info->block_size) {
        ctx->md_info->starts_func(ctx->md_ctx);
        ctx->md_info->update_func(ctx->md_ctx, key, keylen);
        ctx->md_info->finish_func(ctx->md_ctx, sum);

        keylen = ctx->md_info->size;
        key    = sum;
    }

    ipad = (unsigned char *)ctx->hmac_ctx;
    opad = (unsigned char *)ctx->hmac_ctx + ctx->md_info->block_size;

    memset(ipad, 0x36, ctx->md_info->block_size);
    memset(opad, 0x5C, ctx->md_info->block_size);

    for (i = 0; i < keylen; i++) {
        ipad[i] = (unsigned char)(ipad[i] ^ key[i]);
        opad[i] = (unsigned char)(opad[i] ^ key[i]);
    }

    mbedtls_zeroize(sum, sizeof(sum));

    ctx->md_info->starts_func(ctx->md_ctx);
    ctx->md_info->update_func(ctx->md_ctx, ipad, ctx->md_info->block_size);

    return (0);
}

int sc_mbedtls_md_hmac_update(sc_mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen)
{
    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL)
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    ctx->md_info->update_func(ctx->md_ctx, input, ilen);

    return (0);
}

int sc_mbedtls_md_hmac_finish(sc_mbedtls_md_context_t *ctx, unsigned char *output)
{
    unsigned char  tmp[SC_MBEDTLS_MD_MAX_SIZE];
    unsigned char *opad;

    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL)
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    opad = (unsigned char *)ctx->hmac_ctx + ctx->md_info->block_size;

    ctx->md_info->finish_func(ctx->md_ctx, tmp);
    ctx->md_info->starts_func(ctx->md_ctx);
    ctx->md_info->update_func(ctx->md_ctx, opad, ctx->md_info->block_size);
    ctx->md_info->update_func(ctx->md_ctx, tmp, ctx->md_info->size);
    ctx->md_info->finish_func(ctx->md_ctx, output);

    return (0);
}

int sc_mbedtls_md_hmac_reset(sc_mbedtls_md_context_t *ctx)
{
    unsigned char *ipad;

    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL)
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    ipad = (unsigned char *)ctx->hmac_ctx;

    ctx->md_info->starts_func(ctx->md_ctx);
    ctx->md_info->update_func(ctx->md_ctx, ipad, ctx->md_info->block_size);

    return (0);
}

int sc_mbedtls_md_hmac(const sc_mbedtls_md_info_t *md_info, const unsigned char *key, size_t keylen,
                       const unsigned char *input, size_t ilen, unsigned char *output)
{
    sc_mbedtls_md_context_t ctx;
    int                     ret;

    if (md_info == NULL)
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    sc_mbedtls_md_init(&ctx);

    if ((ret = sc_mbedtls_md_setup(&ctx, md_info, 1)) != 0)
        return (ret);

    sc_mbedtls_md_hmac_starts(&ctx, key, keylen);
    sc_mbedtls_md_hmac_update(&ctx, input, ilen);
    sc_mbedtls_md_hmac_finish(&ctx, output);

    sc_mbedtls_md_free(&ctx);

    return (0);
}

int sc_mbedtls_md_process(sc_mbedtls_md_context_t *ctx, const unsigned char *data)
{
    if (ctx == NULL || ctx->md_info == NULL)
        return (SC_MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    ctx->md_info->process_func(ctx->md_ctx, data);

    return (0);
}

unsigned char sc_mbedtls_md_get_size(const sc_mbedtls_md_info_t *md_info)
{
    if (md_info == NULL)
        return (0);

    return md_info->size;
}

sc_mbedtls_md_type_t sc_mbedtls_md_get_type(const sc_mbedtls_md_info_t *md_info)
{
    if (md_info == NULL)
        return (SC_MBEDTLS_MD_NONE);

    return md_info->type;
}

const char *sc_mbedtls_md_get_name(const sc_mbedtls_md_info_t *md_info)
{
    if (md_info == NULL)
        return (NULL);

    return md_info->name;
}
#endif