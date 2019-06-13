// Copyright (c) 2019, The CCLib Developers
//
// Please see the included LICENSE file for more information.

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "blake2/blake2.h"


#define HASH_BYTES      32                 // hash length in bytes
#define CACHE_ROUNDS    1                  // number of rounds in cache production
#define EPOCH_LENGTH    1                  // blocks per epoch
#define DATASET_PARENTS 16                 // number of hashes before calculating dataset entry
#define ACCESSES        64
// Assuming 4 blocks per second, an epoch estimates 15 minutes


void error_exit(uint8_t code){
	printf("Error, exiting program. Code: %u\n", code);
	if(code==1) printf("Memory could not be initialised, insufficient RAM?\n");
	exit(-1);
}

#if (!defined(__aarch64__) || !defined(__ARM_FEATURE_CRYPTO)) && (!defined(__x86_64__) || !defined(__AES__))
static uint8_t SBOX[256] = {
	 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static uint8_t shifts[16] = {
	 0,  5, 10, 15,
	 4,  9, 14,  3,
	 8, 13,  2,  7,
	12,  1,  6, 11
};

static void add_round_key(uint8_t * state, uint8_t * rkey) {
	uint8_t i;
	for (i = 0; i < 16; i++)
		state[i] ^= rkey[i];
}

static void sub_bytes(uint8_t * state) {
	uint8_t i;
	for (i = 0; i < 16; i++)
		state[i] = SBOX[state[i]];
}

static void shift_rows(uint8_t * state) {
	uint8_t temp[16];
	uint8_t i;

	for (i = 0; i < 16; i++) {
		temp[i] = state[shifts[i]];
	}

	for (i = 0; i < 16; i++) {
		state[i] = temp[i];
	}
}

static void mix_columns(uint8_t * state) {
	uint8_t a[4];
	uint8_t b[4];
	uint8_t h, i, k;

	for (k = 0; k < 4; k++) {
		for (i = 0; i < 4; i++) {
			a[i] = state[i + 4 * k];
			h = state[i + 4 * k] & 0x80; /* hi bit */
			b[i] = state[i + 4 * k] << 1;

			if (h == 0x80) {
				b[i] ^= 0x1b; /* Rijndael's Galois field */
			}
		}

		state[4 * k]	 = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
		state[1 + 4 * k] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
		state[2 + 4 * k] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
		state[3 + 4 * k] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
	}
}
#endif // (!defined(__aarch64__) || !defined(__ARM_FEATURE_CRYPTO)) && (!defined(__x86_64__) || !defined(__AES__))

void aes(uint8_t* state, uint8_t* key) {
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
	__asm__ volatile(
	"ld1   {v0.16b,v1.16b},[%0]     \n"
	"ld1   {v2.16b,v3.16b},[%1]     \n"
	"aese  v0.16b,v2.16b		\n" // round1: add_round_key,sub_bytes,shift_rows
	"aesmc v0.16b,v0.16b		\n" // round1: mix_columns
	"aese  v1.16b,v3.16b		\n" // round1: add_round_key,sub_bytes,shift_rows
	"aesmc v1.16b,v1.16b		\n" // round1: mix_columns
	"st1   {v0.16b},[%0]		\n"
	:
	: "r"(state), "r"(key)
	: "v0", "v1", "v2", "v3", "cc", "memory");

#elif defined(__x86_64__) && defined(__AES__)
	__asm__ volatile(
	"movups (%0),  %%xmm0	 \n"
	"movups (%1),  %%xmm1	 \n"
	"movups 16(%0),%%xmm2	 \n"
	"movups 16(%1),%%xmm3	 \n"
	"pxor   %%xmm1,%%xmm0	 \n" // add_round_key(state, key)
	"pxor   %%xmm2,%%xmm3	 \n" // add_round_key(state, key)
	"aesenc %%xmm1,%%xmm0	 \n" // first round
	"aesenc %%xmm3,%%xmm2	 \n" // first round
	"movups %%xmm0, (%0)     \n"
	:
	: "r"(state), "r" (key)
	: "xmm0", "xmm1", "xmm2", "cc", "memory");

#else
	uint8_t* state_2 = &state[16];
	uint8_t* key_2 = &key[16];
	add_round_key(state, key);
	sub_bytes(state);
	shift_rows(state);
	mix_columns(state);
	add_round_key(state_2, key_2);
	sub_bytes(state_2);
	shift_rows(state_2);
	mix_columns(state_2);
#endif
}



uint32_t crc32c_table[256] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

void crc32p(uint32_t* in, uint32_t* out) { // CRC32-Pointer
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRC32)
	__asm__("crc32w %w0,%w0,%w1\n":"+r"(*out):"r"(*in));
#else
	*out=crc32c_table[(*in )&0xff]^((*in )>>8);
	*out=crc32c_table[(*out)&0xff]^((*out)>>8);
	*out=crc32c_table[(*out)&0xff]^((*out)>>8);
	*out=crc32c_table[(*out)&0xff]^((*out)>>8);
#endif
}

void crc32i(uint32_t* in) { // CRC32-Inplace
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRC32)
	__asm__("crc32w %w0,%w0,%w1\n":"+r"(*in):"r"(*in));
#else
	*in=crc32c_table[(*in)&0xff]^((*in)>>8);
	*in=crc32c_table[(*in)&0xff]^((*in)>>8);
	*in=crc32c_table[(*in)&0xff]^((*in)>>8);
	*in=crc32c_table[(*in)&0xff]^((*in)>>8);
#endif
}


void reverse(uint32_t* x){
#if defined(__aarch64__) && !defined(__x86_64__)
	  __asm__("rbit %0":"+r"(*x));
#else
	*x = ((*x & 0x55555555) << 1)  | ((*x & 0xAAAAAAAA) >> 1);
	*x = ((*x & 0x33333333) << 2)  | ((*x & 0xCCCCCCCC) >> 2);
	*x = ((*x & 0x0F0F0F0F) << 4)  | ((*x & 0xF0F0F0F0) >> 4);
	*x = ((*x & 0x00FF00FF) << 8)  | ((*x & 0xFF00FF00) >> 8);
	*x = ((*x & 0x0000FFFF) << 16) | ((*x & 0xFFFF0000) >> 16);
#endif
}

// reverse all bytes in the word _v_
void swap(uint64_t* v) {
#if defined(__x86_64__)
	__asm__("bswap %0":"+r"(*v));
#elif defined(__aarch64__)
	__asm__("rev %0,%0\n":"+r"(*v));
#else
	*v=((*v&0xff00ff00ff00ff00ULL)>>8)|((*v&0x00ff00ff00ff00ffULL)<<8);
	*v=((*v&0xffff0000ffff0000ULL)>>16)|((*v&0x0000ffff0000ffffULL)<<16);
	*v=(*v>>32)|(*v<<32);
#endif
}

void calc_dataset_item(uint8_t* cache, uint32_t item_number, uint64_t* out){
	uint32_t* cache_32 = (uint32_t*)cache; 
	uint64_t  mix[4]   = {0};
	uint32_t* mix_32   = (uint32_t*)mix;
	uint32_t* mix_32_s = (uint32_t*)&(((uint16_t*)mix)[1]);
	uint32_t  x        = 0;
	item_number = item_number >> 2;
	*mix_32    = cache_32[(item_number  )&0x1fffff];
	mix_32[1]  = cache_32[(item_number+1)&0x1fffff];
	mix_32[2]  = cache_32[(item_number+2)&0x1fffff];
	mix_32[3]  = cache_32[(item_number+3)&0x1fffff];
	mix_32[4]  = cache_32[(item_number+4)&0x1fffff];
	mix_32[5]  = cache_32[(item_number+5)&0x1fffff];
	mix_32[6]  = cache_32[(item_number+6)&0x1fffff];
	mix_32[7]  = cache_32[(item_number+7)&0x1fffff];
	*mix_32   ^= item_number; mix_32[1] ^= item_number;
	mix_32[2] ^= item_number; mix_32[3] ^= item_number;
	mix_32[4] ^= item_number; mix_32[5] ^= item_number;
	mix_32[6] ^= item_number; mix_32[7] ^= item_number;
	for(uint16_t j=0;j<DATASET_PARENTS;j++){
		x = j^item_number;
		*mix_32 &= 0x1fffff; mix_32[1] &= 0x1fffff;
		mix_32[2] &= 0x1fffff; mix_32[3] &= 0x1fffff;
		mix_32[4] &= 0x1fffff; mix_32[5] &= 0x1fffff;
		mix_32[6] &= 0x1fffff; mix_32[7] &= 0x1fffff;
		*mix_32   = cache_32[*mix_32];
		mix_32[1] = cache_32[mix_32[1]];
		mix_32[2] = cache_32[mix_32[2]];
		mix_32[3] = cache_32[mix_32[3]];
		mix_32[4] = cache_32[mix_32[4]];
		mix_32[5] = cache_32[mix_32[5]];
		mix_32[6] = cache_32[mix_32[6]];
		mix_32[7] = cache_32[mix_32[7]];
		*mix_32   ^= x; mix_32[1] ^= x;
		mix_32[2] ^= x; mix_32[3] ^= x;
		mix_32[4] ^= x; mix_32[5] ^= x;
		mix_32[6] ^= x; mix_32[7] ^= x;
		crc32i(mix_32_s);
		crc32i(&mix_32_s[1]);
		crc32i(&mix_32_s[2]);
		crc32i(&mix_32_s[3]);
		crc32i(&mix_32_s[4]);
		crc32i(&mix_32_s[5]);
		crc32i(&mix_32_s[6]);
	}
	*out  =*mix;    out[1]=mix[1];
	out[2]= mix[2]; out[3]=mix[3];
}


void squash_0(uint8_t* data, uint8_t* out){
	uint8_t   shift_0         = 0;
	uint8_t   shift_1         = 0;
	uint8_t   shift_2         = 0;
	uint8_t   shift_3         = 0;
	uint64_t  key_0[2]        = {0};
	uint64_t  key_1[2]        = {0};
	uint64_t  divr_0          = 0;
	uint64_t  divr_1          = 0;
	uint64_t  crc_64[4]       = {0};
	uint32_t* crc_32          = (uint32_t*)crc_64;
	uint32_t* data_32         = (uint32_t*)data;
	uint64_t* data_64         = (uint64_t*)data;
	uint16_t* out_16          = (uint16_t*)out;
	uint64_t* out_64          = (uint64_t*)out;
	crc32p(data_32, crc_32);
	crc32p(&data_32[1], &crc_32[1]);
	crc32p(&data_32[2], &crc_32[2]);
	crc32p(&data_32[3], &crc_32[3]);
	*crc_64 ^= 0xFFFFFFFF;
	crc_64[1] ^= 0xFFFFFFFF;
	crc_64[2] = (data_64[2] + *crc_64) ^ (data_64[2] / *crc_64);
	crc_64[3] = (data_64[3] + crc_64[1]) ^ (data_64[3] / crc_64[1]);
	*out_64   = *crc_64^divr_0; out_64[1] = crc_64[1]^divr_0;
	out_64[2] = crc_64[2]^divr_1; out_64[3] = crc_64[3]^divr_1;
	shift_0 = out_16[15]&0x3f;
	shift_2 = (*out_16)&0x3f;
	shift_1 = 64-shift_0;
	shift_3 = 64-shift_2;
	key_0[1] = (*out_64>>shift_0) | (*out_64<<(shift_1));
	key_1[1] = (out_64[1]>>shift_0) | (out_64[1]<<(shift_1));
	*key_0 = (out_64[2]<<shift_2) | (out_64[2]>>(shift_3));
	*key_1 = (out_64[3]<<shift_2) | (out_64[3]>>(shift_3));
	aes(out     , (uint8_t*)key_0);
	aes(&out[16], (uint8_t*)key_1);
}

// Squash_1 uses a lookup in addition to the previous operations
// to force a hasher to have 256B read-only scratchpad in L1 cache
void squash_1(uint8_t* data, uint8_t* scratchpad, uint8_t* out){
	uint8_t   shift_0         = 0;
	uint8_t   shift_1         = 0;
	uint8_t   shift_2         = 0;
	uint8_t   shift_3         = 0;
	uint64_t  key_0[2]        = {0};
	uint64_t  key_1[2]        = {0};
	uint64_t  divr_0          = 0;
	uint64_t  divr_1          = 0;
	uint64_t  crc_64[4]       = {0};
	uint32_t* crc_32          = (uint32_t*)crc_64;
	uint8_t*  crc_8           = (uint8_t*)crc_64;
	uint32_t* data_32         = (uint32_t*)data;
	uint64_t* data_64         = (uint64_t*)data;
	uint16_t* out_16          = (uint16_t*)out;
	uint64_t* out_64          = (uint64_t*)out;
	crc32p(data_32, crc_32);
	crc32p(&data_32[1], &crc_32[1]);
	crc32p(&data_32[2], &crc_32[2]);
	crc32p(&data_32[3], &crc_32[3]);
	crc_32[4] = *((uint32_t*)&scratchpad[*crc_8]);
	crc_32[5] = *((uint32_t*)&scratchpad[crc_8[ 4]]);
	crc_32[6] = *((uint32_t*)&scratchpad[crc_8[ 8]]);
	crc_32[7] = *((uint32_t*)&scratchpad[crc_8[12]]);
	reverse(crc_32);
	reverse(&crc_32[1]);
	reverse(&crc_32[6]);
	reverse(&crc_32[7]);
	swap(&crc_64[1]);
	swap(&crc_64[2]);
	divr_0  = (data_64[2] + *crc_64);
	divr_1  = (data_64[3] + crc_64[1]);
	divr_0 ^= (data_64[2] / crc_64[2]);
	divr_1 ^= (data_64[3] / crc_64[3]);
	*out_64   = *crc_64^divr_0; out_64[1] = crc_64[1]^divr_0;
	out_64[2] = crc_64[2]^divr_1; out_64[3] = crc_64[3]^divr_1;
	shift_0 = out_16[15]&0x3f;
	shift_2 = (*out_16)&0x3f;
	shift_1 = 64-shift_0;
	shift_3 = 64-shift_2;
	key_0[1] = (*out_64>>shift_0) | (*out_64<<(shift_1));
	key_1[1] = (out_64[1]>>shift_0) | (out_64[1]<<(shift_1));
	*key_0 = (out_64[2]<<shift_2) | (out_64[2]>>(shift_3));
	*key_1 = (out_64[3]<<shift_2) | (out_64[3]>>(shift_3));
	aes(out     , (uint8_t*)key_0);
	aes(&out[16], (uint8_t*)key_1);
}

// Difference from Squash_1 is a 16bit integer is used to obtain the
// data from the scratchpad. (64KiB scratchpad)
void squash_2(uint8_t* data, uint8_t* scratchpad, uint8_t* out){
	uint8_t   shift_0         = 0;
	uint8_t   shift_1         = 0;
	uint8_t   shift_2         = 0;
	uint8_t   shift_3         = 0;
	uint64_t  key_0[2]        = {0};
	uint64_t  key_1[2]        = {0};
	uint64_t  divr_0          = 0;
	uint64_t  divr_1          = 0;
	uint64_t  crc_64[4]       = {0};
	uint32_t* crc_32          = (uint32_t*)crc_64;
	uint16_t* crc_16          = (uint16_t*)crc_64;
	uint32_t* data_32         = (uint32_t*)data;
	uint64_t* data_64         = (uint64_t*)data;
	uint16_t* out_16          = (uint16_t*)out;
	uint64_t* out_64          = (uint64_t*)out;
	crc32p(data_32, crc_32);
	crc32p(&data_32[1], &crc_32[1]);
	crc32p(&data_32[2], &crc_32[2]);
	crc32p(&data_32[3], &crc_32[3]);
	crc_32[4] = *((uint32_t*)&scratchpad[*crc_16]);
	crc_32[5] = *((uint32_t*)&scratchpad[crc_16[2]]);
	crc_32[6] = *((uint32_t*)&scratchpad[crc_16[4]]);
	crc_32[7] = *((uint32_t*)&scratchpad[crc_16[6]]);
	reverse(crc_32);
	reverse(&crc_32[1]);
	reverse(&crc_32[6]);
	reverse(&crc_32[7]);
	swap(&crc_64[1]);
	swap(&crc_64[2]);
	divr_0  = (data_64[2] + *crc_64);
	divr_1  = (data_64[3] + crc_64[1]);
	divr_0 ^= (data_64[2] / crc_64[2]);
	divr_1 ^= (data_64[3] / crc_64[3]);
	*out_64   = *crc_64^divr_0; out_64[1] = crc_64[1]^divr_0;
	out_64[2] = crc_64[2]^divr_1; out_64[3] = crc_64[3]^divr_1;
	shift_0 = out_16[15]&0x3f;
	shift_2 = (*out_16)&0x3f;
	shift_1 = 64-shift_0;
	shift_3 = 64-shift_2;
	key_0[1] = (*out_64>>shift_0) | (*out_64<<(shift_1));
	key_1[1] = (out_64[1]>>shift_0) | (out_64[1]<<(shift_1));
	*key_0 = (out_64[2]<<shift_2) | (out_64[2]>>(shift_3));
	*key_1 = (out_64[3]<<shift_2) | (out_64[3]>>(shift_3));
	aes(out     , (uint8_t*)key_0);
	aes(&out[16], (uint8_t*)key_1);
}

// Difference from Squash_2 is a 32bit integer is used to obtain the
// data from the dataset. (4 GiB dataset)
void squash_3_full(uint8_t* data, uint64_t* dataset, uint8_t* out){
	uint8_t   shift_0         = 0;
	uint8_t   shift_1         = 0;
	uint8_t   shift_2         = 0;
	uint8_t   shift_3         = 0;
	uint64_t  key_0[2]        = {0};
	uint64_t  key_1[2]        = {0};
	uint64_t  divr_0          = 0;
	uint64_t  divr_1          = 0;
	uint64_t  crc_64[4]       = {0};
	uint32_t* crc_32          = (uint32_t*)crc_64;
	uint16_t* crc_16          = (uint16_t*)crc_64;
	uint32_t* crc_32_s_0      = (uint32_t*)&crc_16[9];
	uint32_t* crc_32_s_1      = (uint32_t*)&crc_16[11];
	uint32_t* crc_32_s_2      = (uint32_t*)&crc_16[13];
	uint32_t* data_32         = (uint32_t*)data;
	uint64_t* data_64         = (uint64_t*)data;
	uint16_t* out_16          = (uint16_t*)out;
	uint64_t* out_64          = (uint64_t*)out;
	crc32p(data_32, crc_32);
	crc32p(&data_32[1], &crc_32[1]);
	crc32p(&data_32[2], &crc_32[2]);
	crc32p(&data_32[3], &crc_32[3]);
	crc_32[4] = *((uint32_t*)&dataset[*crc_32&0x1ffffffc]);
	crc_32[5] = *((uint32_t*)&dataset[crc_32[1]&0x1ffffffc]);
	crc_32[6] = *((uint32_t*)&dataset[crc_32[2]&0x1ffffffc]);
	crc_32[7] = *((uint32_t*)&dataset[crc_32[3]&0x1ffffffc]);
	crc32i(crc_32_s_0);
	crc32i(crc_32_s_1);
	crc32i(crc_32_s_2);
	for(uint16_t i=1;i<ACCESSES;i++){
		for(uint8_t j=0;j<8;j++){
			crc_32[4] = ((uint32_t*)&dataset[crc_32[4]&0x1ffffffc])[j];
			crc_32[5] = ((uint32_t*)&dataset[crc_32[5]&0x1ffffffc])[j];
			crc_32[6] = ((uint32_t*)&dataset[crc_32[6]&0x1ffffffc])[j];
			crc_32[7] = ((uint32_t*)&dataset[crc_32[7]&0x1ffffffc])[j];
			crc32i(crc_32_s_0);
			crc32i(crc_32_s_1);
			crc32i(crc_32_s_2);
		}
	}
	reverse(crc_32);
	reverse(&crc_32[1]);
	reverse(&crc_32[6]);
	reverse(&crc_32[7]);
	swap(&crc_64[1]);
	swap(&crc_64[2]);
	divr_0  = (data_64[2] + *crc_64);
	divr_1  = (data_64[3] + crc_64[1]);
	divr_0 ^= (data_64[2] / crc_64[2]);
	divr_1 ^= (data_64[3] / crc_64[3]);
	*out_64   = *crc_64^divr_0; out_64[1] = crc_64[1]^divr_0;
	out_64[2] = crc_64[2]^divr_1; out_64[3] = crc_64[3]^divr_1;
	shift_0 = out_16[15]&0x3f;
	shift_2 = (*out_16)&0x3f;
	shift_1 = 64-shift_0;
	shift_3 = 64-shift_2;
	key_0[1] = (*out_64>>shift_0) | (*out_64<<(shift_1));
	key_1[1] = (out_64[1]>>shift_0) | (out_64[1]<<(shift_1));
	*key_0 = (out_64[2]<<shift_2) | (out_64[2]>>(shift_3));
	*key_1 = (out_64[3]<<shift_2) | (out_64[3]>>(shift_3));
	aes(out     , (uint8_t*)key_0);
	aes(&out[16], (uint8_t*)key_1);
}

// Difference from Squash_2 is a 32bit integer is used to obtain the
// data from the scratchpad. (4 GiB scratchpad)
void squash_3_light(uint8_t* data, uint8_t* cache, uint8_t* out){
	uint8_t   shift_0         = 0;
	uint8_t   shift_1         = 0;
	uint8_t   shift_2         = 0;
	uint8_t   shift_3         = 0;
	uint64_t  key_0[2]        = {0};
	uint64_t  key_1[2]        = {0};
	uint64_t  divr_0          = 0;
	uint64_t  divr_1          = 0;
	uint64_t  crc_64[4]       = {0};
	uint32_t* crc_32          = (uint32_t*)crc_64;
	uint16_t* crc_16          = (uint16_t*)crc_64;
	uint32_t* crc_32_s_0      = (uint32_t*)&crc_16[9];
	uint32_t* crc_32_s_1      = (uint32_t*)&crc_16[11];
	uint32_t* crc_32_s_2      = (uint32_t*)&crc_16[13];
	uint32_t* data_32         = (uint32_t*)data;
	uint64_t* data_64         = (uint64_t*)data;
	uint16_t* out_16          = (uint16_t*)out;
	uint64_t* out_64          = (uint64_t*)out;
	uint64_t  dataset_item[4] = {0};
	uint32_t* dataset_item_32 = (uint32_t*)dataset_item;
	crc32p(data_32, crc_32);
	crc32p(&data_32[1], &crc_32[1]);
	crc32p(&data_32[2], &crc_32[2]);
	crc32p(&data_32[3], &crc_32[3]);
	calc_dataset_item(cache, (*crc_32&0x1ffffffc), dataset_item);
	crc_32[4] = *dataset_item_32;
	calc_dataset_item(cache, (crc_32[1]&0x1ffffffc), dataset_item);
	crc_32[5] = *dataset_item_32;
	calc_dataset_item(cache, (crc_32[2]&0x1ffffffc), dataset_item);
	crc_32[6] = *dataset_item_32;
	calc_dataset_item(cache, (crc_32[3]&0x1ffffffc), dataset_item);
	crc_32[7] = *dataset_item_32;
	crc32i(crc_32_s_0);
	crc32i(crc_32_s_1);
	crc32i(crc_32_s_2);
	for(uint16_t i=1;i<ACCESSES;i++){
		for(uint8_t j=0;j<8;j++){
			calc_dataset_item(cache, (crc_32[4]&0x1ffffffc), dataset_item);
			crc_32[4] = dataset_item_32[j];
			calc_dataset_item(cache, (crc_32[5]&0x1ffffffc), dataset_item);
			crc_32[5] = dataset_item_32[j];
			calc_dataset_item(cache, (crc_32[6]&0x1ffffffc), dataset_item);
			crc_32[6] = dataset_item_32[j];
			calc_dataset_item(cache, (crc_32[7]&0x1ffffffc), dataset_item);
			crc_32[7] = dataset_item_32[j];
			crc32i(crc_32_s_0);
			crc32i(crc_32_s_1);
			crc32i(crc_32_s_2);
		}
	}
	reverse(crc_32);
	reverse(&crc_32[1]);
	reverse(&crc_32[6]);
	reverse(&crc_32[7]);
	swap(&crc_64[1]);
	swap(&crc_64[2]);
	divr_0  = (data_64[2] + *crc_64);
	divr_1  = (data_64[3] + crc_64[1]);
	divr_0 ^= (data_64[2] / crc_64[2]);
	divr_1 ^= (data_64[3] / crc_64[3]);
	*out_64   = *crc_64^divr_0; out_64[1] = crc_64[1]^divr_0;
	out_64[2] = crc_64[2]^divr_1; out_64[3] = crc_64[3]^divr_1;
	shift_0 = out_16[15]&0x3f;
	shift_2 = (*out_16)&0x3f;
	shift_1 = 64-shift_0;
	shift_3 = 64-shift_2;
	key_0[1] = (*out_64>>shift_0) | (*out_64<<(shift_1));
	key_1[1] = (out_64[1]>>shift_0) | (out_64[1]<<(shift_1));
	*key_0 = (out_64[2]<<shift_2) | (out_64[2]>>(shift_3));
	*key_1 = (out_64[3]<<shift_2) | (out_64[3]>>(shift_3));
	aes(out     , (uint8_t*)key_0);
	aes(&out[16], (uint8_t*)key_1);
}


void make_scratchpad(uint8_t* seed, uint8_t* scratchpad){
	squash_0(seed, scratchpad);
	for(uint32_t i=32; i<65536;i+=32) squash_0(&scratchpad[i-32], &scratchpad[i]);
}

void make_cache(uint8_t* scratchpad, uint8_t* cache){
	/* 64MiB cache is allocated before executing
	   this function */
	uint32_t  mask          = 67108864/HASH_BYTES-1;
	uint64_t* cache_64      = (uint64_t*)cache; 
	uint64_t  temp_cache[4] = {0};
	uint64_t  index_0       = 0;
	uint64_t  index_1       = 0;
	for(uint32_t i=0;i<mask;i++) squash_2(&cache[i*32], scratchpad, &cache[(i+1)*32]);
	for(uint8_t j=0;j<CACHE_ROUNDS;j++){
		for(uint32_t i=0;i<mask;i++){
			index_0   = cache_64[i*4]&mask;
			index_1 = (i-1+mask)&mask; 
			for(uint8_t k=0;k<4;k++)
				temp_cache[k] = *((uint64_t*)&cache[index_0+k])^*((uint64_t*)&cache[index_1+k]);
			squash_2((uint8_t*)temp_cache, scratchpad, &cache[i*32]);
		}
	}
}

void calc_dataset(uint8_t* cache, uint64_t* out){
	for(uint64_t i=0;i<536870912;i+=4){ // (1<<32)>>3
		calc_dataset_item(cache, i, &out[i]);
	}
}

void squash_pow_full(uint8_t* data, uint32_t lenght, uint8_t* dataset, uint8_t* result){
	uint64_t  seed_64[4] = {0}; 
	uint8_t*  seed       = (uint8_t*)seed_64; 
	blake2b(seed, 32, data, (size_t) lenght, NULL, 0);
	squash_3_full(seed, (uint64_t*)dataset, result);
}

void squash_pow_light(uint8_t* data, uint32_t lenght, uint8_t* cache, uint8_t* result){
	uint64_t  seed_64[4] = {0}; 
	uint8_t*  seed       = (uint8_t*)seed_64; 
	blake2b(seed, 32, data, (size_t) lenght, NULL, 0);
	squash_3_light(seed, cache, result);
}

void cache_from_previous_hash(uint8_t* previousBlockhash, uint8_t* cache){
	uint64_t  scratchpad_64[8193] = {0};
	uint8_t*  scratchpad          = (uint8_t*)scratchpad_64;
	make_scratchpad(previousBlockhash, scratchpad);
	make_cache(scratchpad, cache);
}

//      ]===[ API Functions ]====[

void dataset_from_seed(uint64_t* dataset, uint8_t* previousBlockhash){
	uint64_t* cache_64    = (uint64_t*)calloc(8388608,8);
	uint8_t*  cache       = (uint8_t*)cache_64;
	if(!cache_64) error_exit(1);
	cache_from_previous_hash(previousBlockhash, cache);
	calc_dataset(cache, dataset);
	free(cache);
}

void squash_light_api(const void* data, uint32_t length, uint8_t* hash_out, uint8_t* previousBlockhash){
	uint64_t* cache_64    = (uint64_t*)calloc(8388608,8);
	uint8_t*  cache       = (uint8_t*)cache_64;
	if (!cache_64) error_exit(1);
	cache_from_previous_hash(previousBlockhash, cache);
	squash_pow_light((uint8_t*)data, length, cache, hash_out);
	free(cache_64);
}

void squash_full_api(const void* data, uint32_t length, uint8_t* hash_out, uint64_t* dataset){
	squash_pow_full((uint8_t*)data, length, (uint8_t*)dataset, hash_out);
}

