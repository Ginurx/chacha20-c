#pragma once

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_VARIANT_RFC8439  1
#define CHACHA20_VARIANT_ORIGINAL 2

#ifndef CHACHA20_VARIANT
#define CHACHA20_VARIANT CHACHA20_VARIANT_RFC8439
#endif

#define CHACHA20_KEY_SIZE   32u
#define CHACHA20_BLOCK_SIZE 64u

#if CHACHA20_VARIANT == CHACHA20_VARIANT_RFC8439
#define CHACHA20_NONCE_SIZE  12u
#define CHACHA20_COUNTER_MAX UINT32_MAX
#elif CHACHA20_VARIANT == CHACHA20_VARIANT_ORIGINAL
#define CHACHA20_NONCE_SIZE  8u
#define CHACHA20_COUNTER_MAX UINT64_MAX
#else
#error "CHACHA20_VARIANT must be CHACHA20_VARIANT_RFC8439 or CHACHA20_VARIANT_ORIGINAL"
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum chacha20_status
{
	CHACHA20_OK = 0,
	CHACHA20_ERR_INVALID_ARGUMENT,
	CHACHA20_ERR_COUNTER_RANGE,
	CHACHA20_ERR_COUNTER_EXHAUSTED,
	CHACHA20_ERR_INVALID_STATE
};

/*
 * This structure is public only so that contexts can be stack allocated.
 * Its fields and layout are implementation details and are not a stable ABI.
 */
struct chacha20_context
{
	uint32_t _chacha20_state[16];
	uint8_t _chacha20_keystream[CHACHA20_BLOCK_SIZE];
	size_t _chacha20_position;
	uint32_t _chacha20_magic;
	uint8_t _chacha20_exhausted;
};

#if CHACHA20_VARIANT == CHACHA20_VARIANT_RFC8439

enum chacha20_status chacha20_rfc8439_init_context(
	struct chacha20_context *ctx,
	const uint8_t key[CHACHA20_KEY_SIZE],
	const uint8_t nonce[CHACHA20_NONCE_SIZE],
	uint64_t counter);

enum chacha20_status chacha20_rfc8439_xor(
	struct chacha20_context *ctx,
	uint8_t *bytes,
	size_t n_bytes);

#define chacha20_init_context chacha20_rfc8439_init_context
#define chacha20_xor          chacha20_rfc8439_xor

#else

enum chacha20_status chacha20_original_init_context(
	struct chacha20_context *ctx,
	const uint8_t key[CHACHA20_KEY_SIZE],
	const uint8_t nonce[CHACHA20_NONCE_SIZE],
	uint64_t counter);

enum chacha20_status chacha20_original_xor(
	struct chacha20_context *ctx,
	uint8_t *bytes,
	size_t n_bytes);

#define chacha20_init_context chacha20_original_init_context
#define chacha20_xor          chacha20_original_xor

#endif

#ifdef __cplusplus
}
#endif
