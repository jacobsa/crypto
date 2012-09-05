// Copyright 2012 Aaron Jacobs. All Rights Reserved.
// Author: aaronjjacobs@gmail.com (Aaron Jacobs)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The C code in this file was pulled on 2012-09-04 from the proposed SIV
// implementation for OpenSSL hosted on lounge.org:
//
//     http://www.lounge.org/siv_for_openssl.tgz
//
// It was modified by Aaron Jacobs to suit the gencases tool. These
// modifications and the Go code are copyright Aaron Jacobs. The original
// copyright notice is below.

package main

/*
 * Copyright (c) The Industrial Lounge, 2007
 *
 *  Copyright holder grants permission for redistribution and use in source 
 *  and binary forms, with or without modification, provided that the 
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *     3. All advertising materials and documentation mentioning features
 *	  or use of this software must display the following acknowledgement:
 *
 *        "This product includes software written by
 *         Dan Harkins (dharkins at lounge dot org)"
 *
 *  "DISCLAIMER OF LIABILITY
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE INDUSTRIAL LOUNGE ``AS IS'' 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under another distribution
 * license (including the GNU public license).
 */

/*
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "siv.h"
#include "aes_locl.h"

#define Rb		0x87

static void
xor (unsigned char *output, const unsigned char *input)
{
    int i;

    i = AES_BLOCK_SIZE - 1;
    do {
	output[i] ^= input[i];
	i--;
    } while (i >= 0);
    return;
}

static void
times_two (unsigned char *output, unsigned char *input)
{
    int i;
    unsigned char *out = output, *in = input;
    unsigned char carry = 0;

    out = output + AES_BLOCK_SIZE - 1;
    in = input + AES_BLOCK_SIZE - 1;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
	*(out--) = (*in << 1) | carry;
	carry = (*(in--) & 0x80) ? 1 : 0;
    }

    if (carry) {
	output[AES_BLOCK_SIZE-1] ^= Rb;
    }
    return;
}

static void
pad (unsigned char *buf, int len)
{
    int i;

    i = len;
    buf[i++] = 0x80;
    if (i < AES_BLOCK_SIZE) {
	memset(buf + i, 0, AES_BLOCK_SIZE - i);
    }
}

void
aes_cmac (siv_ctx *ctx, const unsigned char *msg, int mlen, unsigned char *C)
{
    int n, i, slop;
    unsigned char Mn[AES_BLOCK_SIZE], *ptr;

    // NOTE(jacobsa): For some reason, weird things happen when when `zero` is
    // a global, as in the original program.
    unsigned char zero[AES_BLOCK_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    memcpy(C, zero, AES_BLOCK_SIZE);

    n = (mlen+(AES_BLOCK_SIZE-1))/AES_BLOCK_SIZE;

    ptr = (unsigned char *)msg;
    for (i = 0; i < (n-1); i++) {
	xor(C, ptr);
	AES_ecb_encrypt(C, C, &ctx->s2v_sched, AES_ENCRYPT);
	ptr += AES_BLOCK_SIZE;
    }

    memset(Mn, 0, AES_BLOCK_SIZE);
    if ((slop = (mlen % AES_BLOCK_SIZE)) != 0) {
	memcpy(Mn, ptr, slop);
	pad(Mn, slop);
	xor(Mn, ctx->K2);
    } else {
	if (msg != NULL && mlen != 0) {
	    memcpy(Mn, ptr, AES_BLOCK_SIZE);
	    xor(Mn, ctx->K1);
	} else {
	    pad(Mn, 0);
	    xor(Mn, ctx->K2);
	}
    }
    xor(C, Mn);
    AES_ecb_encrypt(C, C, &ctx->s2v_sched, AES_ENCRYPT);
    return;
}

int
s2v_final (siv_ctx *ctx, const unsigned char *X, int xlen, unsigned char *digest)
{
    unsigned char T[AES_BLOCK_SIZE], C[AES_BLOCK_SIZE];
    unsigned char padX[AES_BLOCK_SIZE], *ptr;
    int blocks, i, slop;

    // NOTE(jacobsa): For some reason, weird things happen when when `zero` is
    // a global, as in the original program.
    unsigned char zero[AES_BLOCK_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    if (xlen < AES_BLOCK_SIZE) {
	memcpy(padX, X, xlen);
	pad(padX, xlen);

	times_two(T, ctx->T);
	xor(T, padX);
	aes_cmac(ctx, T, AES_BLOCK_SIZE, digest);
    } else {
        if (xlen == AES_BLOCK_SIZE) {
            memcpy(T, X, AES_BLOCK_SIZE);
            xor(T, ctx->T);
            aes_cmac(ctx, T, AES_BLOCK_SIZE, digest);
        } else {
            blocks = (xlen+(AES_BLOCK_SIZE-1))/AES_BLOCK_SIZE - 1;
            ptr = (unsigned char *)X;
            memcpy(C, zero, AES_BLOCK_SIZE);
            if (blocks > 1) {
                for (i = 0; i < (blocks-1); i++) {
                    xor(C, ptr);
                    AES_ecb_encrypt(C, C, &ctx->s2v_sched, AES_ENCRYPT);
                    ptr += AES_BLOCK_SIZE;
                }
            }
            memcpy(T, ptr, AES_BLOCK_SIZE);
            slop = xlen % AES_BLOCK_SIZE;
            if (slop) {
                for (i = 0; i < AES_BLOCK_SIZE - slop; i++) {
                    T[i + slop] ^= ctx->T[i];
                }
                xor(C, T);
                AES_ecb_encrypt(C, C, &ctx->s2v_sched, AES_ENCRYPT);
                ptr += AES_BLOCK_SIZE;
                memset(T, 0, AES_BLOCK_SIZE);
                memcpy(T, ptr, slop);
                for (i = 0; i < slop; i++) {
                    T[i] ^= ctx->T[(AES_BLOCK_SIZE-slop)+i];
                }
                pad(T, slop);
                xor(T, ctx->K2);
            } else {
                xor(C, ptr);
                AES_ecb_encrypt(C, C, &ctx->s2v_sched, AES_ENCRYPT);
                ptr += AES_BLOCK_SIZE;
                memcpy(T, ptr, AES_BLOCK_SIZE);
                xor(T, ctx->T);
                xor(T, ctx->K1);
            }
            xor(C, T);
            AES_ecb_encrypt(C, digest, &ctx->s2v_sched, AES_ENCRYPT);
        }

    }
    return 0;
}

void
s2v_add (siv_ctx *ctx, const unsigned char *Y)
{
    unsigned char T[AES_BLOCK_SIZE];

    memcpy(T, ctx->T, AES_BLOCK_SIZE);
    times_two(ctx->T, T);
    xor(ctx->T, Y);
}

void
s2v_update (siv_ctx *ctx, const unsigned char *X, int xlen)
{
    unsigned char Y[AES_BLOCK_SIZE];

    aes_cmac(ctx, X, xlen, Y);
    s2v_add(ctx, Y);
}

int
siv_init (siv_ctx *ctx, const unsigned char *key, int keylen)
{
    unsigned char L[AES_BLOCK_SIZE];

    // NOTE(jacobsa): For some reason, weird things happen when when `zero` is
    // a global, as in the original program.
    unsigned char zero[AES_BLOCK_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    memset((char *)ctx, 0, sizeof(siv_ctx));
    switch (keylen) {
        case SIV_512:
            AES_set_encrypt_key(key, 256, &ctx->s2v_sched);
            AES_set_encrypt_key(key+AES_256_BYTES, 256, &ctx->ctr_sched);
            break;
        case SIV_384:
            AES_set_encrypt_key(key, 192, &ctx->s2v_sched);
            AES_set_encrypt_key(key+AES_192_BYTES, 192, &ctx->ctr_sched);
            break;
        case SIV_256:
            AES_set_encrypt_key(key, 128, &ctx->s2v_sched);
            AES_set_encrypt_key(key+AES_128_BYTES, 128, &ctx->ctr_sched);
            break;
        default:
            return -1;
    }

    AES_ecb_encrypt(zero, L, &ctx->s2v_sched, AES_ENCRYPT);
    times_two(ctx->K1, L);
    times_two(ctx->K2, ctx->K1);

    memset(ctx->benchmark, 0, AES_BLOCK_SIZE);
    aes_cmac(ctx, zero, AES_BLOCK_SIZE, ctx->T);
    return 1;
}    

void
siv_restart (siv_ctx *ctx)
{
    // NOTE(jacobsa): For some reason, weird things happen when when `zero` is
    // a global, as in the original program.
    unsigned char zero[AES_BLOCK_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    memset(ctx->benchmark, 0, AES_BLOCK_SIZE);
    memset(ctx->T, 0, AES_BLOCK_SIZE);
    aes_cmac(ctx, zero, AES_BLOCK_SIZE, ctx->T);
}

void
s2v_benchmark (siv_ctx *ctx)
{
    memcpy(ctx->benchmark, ctx->T, AES_BLOCK_SIZE);
}

void
s2v_reset (siv_ctx *ctx)
{
    memcpy(ctx->T, ctx->benchmark, AES_BLOCK_SIZE);
}

void
siv_aes_ctr (siv_ctx *ctx, const unsigned char *p, const int lenp,
             unsigned char *c, const unsigned char *iv)
{
    int i, j;
    unsigned char ctr[AES_BLOCK_SIZE], ecr[AES_BLOCK_SIZE];
    unsigned long inc;

    memcpy(ctr, iv, AES_BLOCK_SIZE);
    ctr[12] &= 0x7f; ctr[8] &= 0x7f;
    inc = GETU32(ctr + 12);
    for (i = 0; i < lenp; i+=AES_BLOCK_SIZE) {
        AES_ecb_encrypt(ctr, ecr, &ctx->ctr_sched, AES_ENCRYPT);
        for (j = 0; j < AES_BLOCK_SIZE; j++) {
            if ((i + j) == lenp) {
                return;
            }
            c[i+j] = p[i+j] ^ ecr[j];
        }
        inc++; inc &= 0xffffffff;
        PUTU32(ctr + 12, inc);
    }
}

int
siv_encrypt (siv_ctx *ctx, const unsigned char *p, unsigned char *c,
             const int len, unsigned char *counter, 
             const int nad, const int* adlens, const unsigned char** ads)
{
    const unsigned char *ad;
    int adlen;
    int i;
    unsigned char ctr[AES_BLOCK_SIZE];

		for (i = 0; i < nad; ++i) {
				ad = ads[i];
				adlen = adlens[i];
				s2v_update(ctx, ad, adlen);
		}

    s2v_final(ctx, p, len, ctr);
    memcpy(counter, ctr, AES_BLOCK_SIZE);
    siv_aes_ctr(ctx, p, len, c, ctr);
    siv_restart(ctx);
    return 1;
}

int
siv_decrypt (siv_ctx *ctx, const unsigned char *c, unsigned char *p,
             const int len, unsigned char *counter, 
             const int nad, ...)
{
    va_list ap;
    unsigned char *ad;
    int adlen, numad = nad;
    unsigned char ctr[AES_BLOCK_SIZE];

    memcpy(ctr, counter, AES_BLOCK_SIZE);
    siv_aes_ctr(ctx, c, len, p, ctr);
    if (numad) {
        va_start(ap, nad);
        while (numad) {
            ad = va_arg(ap, unsigned char *);
            adlen = va_arg(ap, int);
            s2v_update(ctx, ad, adlen);
            numad--;
        }
    }
    s2v_final(ctx, p, len, ctr);

    siv_restart(ctx);
    if (memcmp(ctr, counter, AES_BLOCK_SIZE)) {
        memset(p, 0, len);
        return -1;
    } else {
        return 1;
    }
}
*/
import "C"

import (
	"unsafe"
)

func dbl(buf []byte) []byte {
	if len(buf) != 16 {
		panic("Invalid length.")
	}

	cOutput := (*C.uchar)(C.malloc(16))
	defer C.free(unsafe.Pointer(cOutput))

	C.times_two(cOutput, (*C.uchar)(&buf[0]))

	return C.GoBytes(unsafe.Pointer(cOutput), 16)
}

func s2v(key []byte, strings [][]byte) []byte {
	if len(key) == 0 {
		panic("Key must be non-empty.")
	}

	// RFC 5297 defines S2V to handle an empty array, but never actually uses it
	// that way for encryption or decryption. Additionally, the s2v_* reference
	// functions don't handle that case. So don't handle it here.
	if len(strings) == 0 {
		panic("strings must be non-empty.")
	}

	// siv_init requires a full SIV key, i.e. twice the length of the key used by
	// S2V. It uses the first half for the S2V key.
	tmpKey := make([]byte, 2*len(key))
	copy(tmpKey, key)
	key = tmpKey

	// Initialize the context struct.
	var ctx C.siv_ctx
	callResult := C.siv_init(&ctx, (*C.uchar)(&key[0]), C.int(8*len(key)))
	if callResult < 0 {
		panic("Error from siv_init.")
	}

	// Call s2v_update the requisite number of times.
	for i := 0; i < len(strings)-1; i++ {
		data := strings[i]
		dataLen := len(data)

		// Avoid indexing into an empty slice.
		if dataLen == 0 {
			data = make([]byte, 1)
		}

		C.s2v_update(&ctx, (*C.uchar)(&data[0]), C.int(dataLen))
	}

	// Now finalize with the last string. Avoid indexing into an empty slice.
	lastString := strings[len(strings)-1]
	lastStringLen := len(lastString)
	if lastStringLen == 0 {
		lastString = make([]byte, 1)
	}

	cDigest := (*C.uchar)(C.malloc(16))
	defer C.free(unsafe.Pointer(cDigest))

	callResult = C.s2v_final(
		&ctx,
		(*C.uchar)(&lastString[0]),
		C.int(lastStringLen),
		cDigest)

	if callResult < 0 {
		panic("Error from s2v_final.")
	}

	return C.GoBytes(unsafe.Pointer(cDigest), 16)
}

func encrypt(key, plaintext []byte, associated [][]byte) []byte {
	if len(key) == 0 {
		panic("Key must be non-empty.")
	}

	// Initialize the context struct.
	var ctx C.siv_ctx
	callResult := C.siv_init(&ctx, (*C.uchar)(&key[0]), C.int(8*len(key)))
	if callResult < 0 {
		panic("Error from siv_init.")
	}

	// Grab the right pointer for the plaintext, taking care not to index an
	// empty slice.
	var cPlaintext *C.uchar
	cPlaintextLen := C.int(len(plaintext))
	if cPlaintextLen > 0 {
		cPlaintext = (*C.uchar)(&plaintext[0])
	}

	// Create a buffer to store the SIV.
	cCounter := (*C.uchar)(C.malloc(16))
	defer C.free(unsafe.Pointer(cCounter))

	// Create associated data-related arguments. Take care not to index empty
	// slices.
	cNumAssociated := C.int(len(associated))

	adLens := make([]C.int, cNumAssociated)
	ads := make([]*C.uchar, cNumAssociated)
	if cNumAssociated == 0 {
		adLens = make([]C.int, 1)
		ads = make([]*C.uchar, 1)
	}

	for i, _ := range associated {
		aLen := len(associated[i])
		adLens[i] = C.int(aLen)

		if aLen > 0 {
			ads[i] = (*C.uchar)(&associated[i][0])
		}
	}

	cAdLens := (*C.int)(&adLens[0])
	cAds := (**C.uchar)(&ads[0])

	// Call siv_encrypt.
	cCiphertext := (*C.uchar)(C.malloc(C.size_t(cPlaintextLen)))
	defer C.free(unsafe.Pointer(cCiphertext))

	callResult = C.siv_encrypt(
		&ctx,
		cPlaintext,
		cCiphertext,
		cPlaintextLen,
		cCounter,
		cNumAssociated,
		cAdLens,
		cAds)

	if callResult < 0 {
		panic("Error from siv_encrypt.")
	}

	iv := C.GoBytes(unsafe.Pointer(cCounter), 16)
	ciphertext := C.GoBytes(unsafe.Pointer(cCiphertext), cPlaintextLen)

	return append(iv, ciphertext...)
}
