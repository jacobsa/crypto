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

// The C code in this file was pulled from Appendix A of RFC 4493 and modified
// by Aaron Jacobs, adding an implementation of the missing AES_128 function
// that uses OpenSSL and changing the formatting slightly. These modifications
// and the Go code is copyright Aaron Jacobs.

package main

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -lcrypto

#include <assert.h>
#include <openssl/aes.h>
#include <stdlib.h>

unsigned char const_Rb[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};
unsigned char const_Zero[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void AES_128(const unsigned char *key, const unsigned char *in, unsigned char *out) {
	AES_KEY key_struct;
	assert(AES_set_encrypt_key(key, 128, &key_struct) == 0);

	AES_encrypt(in, out, &key_struct);
}

void xor_128(unsigned char *a, unsigned char *b, unsigned char *out)
{
    int i;
    for (i=0;i<16; i++)
    {
        out[i] = a[i] ^ b[i];
    }
}

void leftshift_onebit(unsigned char *input,unsigned char *output)
{
    int         i;
    unsigned char overflow = 0;

    for ( i=15; i>=0; i-- ) {
        output[i] = input[i] << 1;
        output[i] |= overflow;
        overflow = (input[i] & 0x80)?1:0;
    }
    return;
}

void generate_subkey(unsigned char *key, unsigned char *K1, unsigned
                     char *K2)
{
    unsigned char L[16];
    unsigned char Z[16];
    unsigned char tmp[16];
    int i;

    for ( i=0; i<16; i++ ) Z[i] = 0;

    AES_128(key,Z,L);

    if ( (L[0] & 0x80) == 0 ) {
        leftshift_onebit(L,K1);
    } else {
        leftshift_onebit(L,tmp);
        xor_128(tmp,const_Rb,K1);
    }

    if ( (K1[0] & 0x80) == 0 ) {
        leftshift_onebit(K1,K2);
    } else {
        leftshift_onebit(K1,tmp);
        xor_128(tmp,const_Rb,K2);
    }
    return;
}

void padding ( unsigned char *lastb, unsigned char *pad, int length )
{
    int         j;

    for ( j=0; j<16; j++ ) {
        if ( j < length ) {
            pad[j] = lastb[j];
        } else if ( j == length ) {
            pad[j] = 0x80;
        } else {
            pad[j] = 0x00;
        }
    }
}

void AES_CMAC ( unsigned char *key, unsigned char *input, int length,
                unsigned char *mac )
{
    unsigned char       X[16],Y[16], M_last[16], padded[16];
    unsigned char       K1[16], K2[16];
    int         n, i, flag;
    generate_subkey(key,K1,K2);

    n = (length+15) / 16;

    if ( n == 0 ) {
        n = 1;
        flag = 0;
    } else {
        if ( (length%16) == 0 ) {
            flag = 1;
        } else {
            flag = 0;
        }
    }

    if ( flag ) {
        xor_128(&input[16*(n-1)],K1,M_last);
    } else {
        padding(&input[16*(n-1)],padded,length%16);
        xor_128(padded,K2,M_last);
    }

    for ( i=0; i<16; i++ ) X[i] = 0;
    for ( i=0; i<n-1; i++ ) {
        xor_128(X,&input[16*i],Y);
        AES_128(key,Y,X);
    }

    xor_128(X,M_last,Y);
    AES_128(key,Y,X);

    for ( i=0; i<16; i++ ) {
        mac[i] = X[i];
    }
}
*/
import "C"

import (
	"unsafe"
)

func generateSubkey(key []byte) (k1 []byte, k2 []byte) {
	if len(key) != 16 {
		panic("Invalid length.")
	}

	cK1 := (*C.uchar)(C.malloc(16))
	defer C.free(unsafe.Pointer(cK1))

	cK2 := (*C.uchar)(C.malloc(16))
	defer C.free(unsafe.Pointer(cK2))

	C.generate_subkey((*C.uchar)(&key[0]), cK1, cK2)

	return C.GoBytes(unsafe.Pointer(cK1), 16), C.GoBytes(unsafe.Pointer(cK2), 16)
}
