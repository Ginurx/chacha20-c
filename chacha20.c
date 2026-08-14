#include "chacha20.h"

#include <string.h>

#if CHACHA20_VARIANT == CHACHA20_VARIANT_RFC8439
#define CHACHA20_CONTEXT_MAGIC UINT32_C(0x84390001)
#else
#define CHACHA20_CONTEXT_MAGIC UINT32_C(0x4f524947)
#endif

static uint32_t rotl32(uint32_t value, unsigned int count)
{
	return (value << count) | (value >> (32u - count));
}

static uint32_t load32_le(const uint8_t bytes[4])
{
	return ((uint32_t)bytes[0]) |
	       ((uint32_t)bytes[1] << 8) |
	       ((uint32_t)bytes[2] << 16) |
	       ((uint32_t)bytes[3] << 24);
}

static void store32_le(uint8_t bytes[4], uint32_t value)
{
	bytes[0] = (uint8_t)value;
	bytes[1] = (uint8_t)(value >> 8);
	bytes[2] = (uint8_t)(value >> 16);
	bytes[3] = (uint8_t)(value >> 24);
}

static void quarter_round(
	uint32_t words[16], unsigned int a, unsigned int b,
	unsigned int c, unsigned int d)
{
	words[a] += words[b];
	words[d] = rotl32(words[d] ^ words[a], 16);
	words[c] += words[d];
	words[b] = rotl32(words[b] ^ words[c], 12);
	words[a] += words[b];
	words[d] = rotl32(words[d] ^ words[a], 8);
	words[c] += words[d];
	words[b] = rotl32(words[b] ^ words[c], 7);
}

static uint64_t current_counter(const struct chacha20_context *ctx)
{
#if CHACHA20_VARIANT == CHACHA20_VARIANT_RFC8439
	return ctx->_chacha20_state[12];
#else
	return ((uint64_t)ctx->_chacha20_state[13] << 32) |
	       ctx->_chacha20_state[12];
#endif
}

static int context_is_valid(const struct chacha20_context *ctx)
{
	if (ctx->_chacha20_magic != CHACHA20_CONTEXT_MAGIC ||
	    ctx->_chacha20_position > CHACHA20_BLOCK_SIZE ||
	    ctx->_chacha20_exhausted > 1u)
	{
		return 0;
	}

	if (ctx->_chacha20_exhausted != 0u &&
	    current_counter(ctx) != CHACHA20_COUNTER_MAX)
	{
		return 0;
	}

	return 1;
}

static void advance_counter(struct chacha20_context *ctx)
{
	if (current_counter(ctx) == CHACHA20_COUNTER_MAX)
	{
		ctx->_chacha20_exhausted = 1u;
		return;
	}

	ctx->_chacha20_state[12]++;
#if CHACHA20_VARIANT == CHACHA20_VARIANT_ORIGINAL
	if (ctx->_chacha20_state[12] == 0u)
	{
		ctx->_chacha20_state[13]++;
	}
#endif
}

static void generate_block(struct chacha20_context *ctx)
{
	uint32_t working[16];
	unsigned int i;

	memcpy(working, ctx->_chacha20_state, sizeof(working));

	for (i = 0; i < 10u; ++i)
	{
		quarter_round(working, 0, 4, 8, 12);
		quarter_round(working, 1, 5, 9, 13);
		quarter_round(working, 2, 6, 10, 14);
		quarter_round(working, 3, 7, 11, 15);
		quarter_round(working, 0, 5, 10, 15);
		quarter_round(working, 1, 6, 11, 12);
		quarter_round(working, 2, 7, 8, 13);
		quarter_round(working, 3, 4, 9, 14);
	}

	for (i = 0; i < 16u; ++i)
	{
		working[i] += ctx->_chacha20_state[i];
		store32_le(ctx->_chacha20_keystream + (i * 4u), working[i]);
	}

	advance_counter(ctx);
	ctx->_chacha20_position = 0u;
}

enum chacha20_status chacha20_init_context(
	struct chacha20_context *ctx,
	const uint8_t key[CHACHA20_KEY_SIZE],
	const uint8_t nonce[CHACHA20_NONCE_SIZE],
	uint64_t counter)
{
	static const uint8_t constants[] = "expand 32-byte k";
	unsigned int i;

	if (ctx == NULL)
	{
		return CHACHA20_ERR_INVALID_ARGUMENT;
	}

	/* Every failed initialization leaves a deterministically invalid context. */
	memset(ctx, 0, sizeof(*ctx));

	if (key == NULL || nonce == NULL)
	{
		return CHACHA20_ERR_INVALID_ARGUMENT;
	}

#if CHACHA20_VARIANT == CHACHA20_VARIANT_RFC8439
	if (counter > CHACHA20_COUNTER_MAX)
	{
		return CHACHA20_ERR_COUNTER_RANGE;
	}
#endif

	for (i = 0; i < 4u; ++i)
	{
		ctx->_chacha20_state[i] = load32_le(constants + (i * 4u));
	}
	for (i = 0; i < 8u; ++i)
	{
		ctx->_chacha20_state[4u + i] = load32_le(key + (i * 4u));
	}

	ctx->_chacha20_state[12] = (uint32_t)counter;
#if CHACHA20_VARIANT == CHACHA20_VARIANT_RFC8439
	ctx->_chacha20_state[13] = load32_le(nonce);
	ctx->_chacha20_state[14] = load32_le(nonce + 4u);
	ctx->_chacha20_state[15] = load32_le(nonce + 8u);
#else
	ctx->_chacha20_state[13] = (uint32_t)(counter >> 32);
	ctx->_chacha20_state[14] = load32_le(nonce);
	ctx->_chacha20_state[15] = load32_le(nonce + 4u);
#endif

	ctx->_chacha20_position = CHACHA20_BLOCK_SIZE;
	ctx->_chacha20_magic = CHACHA20_CONTEXT_MAGIC;
	return CHACHA20_OK;
}

enum chacha20_status chacha20_xor(
	struct chacha20_context *ctx,
	uint8_t *bytes,
	size_t n_bytes)
{
	size_t cached_bytes;
	size_t bytes_requiring_blocks;
	size_t blocks_needed;
	size_t offset = 0u;

	if (ctx == NULL)
	{
		return CHACHA20_ERR_INVALID_ARGUMENT;
	}
	if (!context_is_valid(ctx))
	{
		return CHACHA20_ERR_INVALID_STATE;
	}
	if (n_bytes == 0u)
	{
		return CHACHA20_OK;
	}
	if (bytes == NULL)
	{
		return CHACHA20_ERR_INVALID_ARGUMENT;
	}

	cached_bytes = CHACHA20_BLOCK_SIZE - ctx->_chacha20_position;
	bytes_requiring_blocks = n_bytes > cached_bytes
		? n_bytes - cached_bytes
		: 0u;
	blocks_needed = bytes_requiring_blocks / CHACHA20_BLOCK_SIZE;
	if ((bytes_requiring_blocks % CHACHA20_BLOCK_SIZE) != 0u)
	{
		blocks_needed++;
	}

	/* Preflight the complete request before changing the context or output. */
	if (blocks_needed != 0u)
	{
		uint64_t counter = current_counter(ctx);

		if (ctx->_chacha20_exhausted != 0u ||
		    blocks_needed - 1u > CHACHA20_COUNTER_MAX - counter)
		{
			return CHACHA20_ERR_COUNTER_EXHAUSTED;
		}
	}

	while (offset < n_bytes)
	{
		size_t available;
		size_t chunk;
		size_t i;

		if (ctx->_chacha20_position == CHACHA20_BLOCK_SIZE)
		{
			generate_block(ctx);
		}

		available = CHACHA20_BLOCK_SIZE - ctx->_chacha20_position;
		chunk = n_bytes - offset;
		if (chunk > available)
		{
			chunk = available;
		}

		for (i = 0; i < chunk; ++i)
		{
			bytes[offset + i] ^=
				ctx->_chacha20_keystream[ctx->_chacha20_position + i];
		}

		ctx->_chacha20_position += chunk;
		offset += chunk;
	}

	return CHACHA20_OK;
}
