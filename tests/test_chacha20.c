#include "chacha20.h"

#include <stdio.h>
#include <string.h>

#define TEST_STATIC_ASSERT(condition, name) \
	typedef char test_static_assert_##name[(condition) ? 1 : -1]

#if CHACHA20_VARIANT == CHACHA20_VARIANT_RFC8439
#define TEST_VARIANT_NAME "RFC 8439"
TEST_STATIC_ASSERT(CHACHA20_NONCE_SIZE == 12u, rfc8439_nonce_size);
TEST_STATIC_ASSERT(CHACHA20_COUNTER_MAX == UINT32_MAX, rfc8439_counter_limit);
#elif CHACHA20_VARIANT == CHACHA20_VARIANT_ORIGINAL
#define TEST_VARIANT_NAME "Original ChaCha20"
TEST_STATIC_ASSERT(CHACHA20_NONCE_SIZE == 8u, original_nonce_size);
TEST_STATIC_ASSERT(CHACHA20_COUNTER_MAX == UINT64_MAX, original_counter_limit);
#else
#error "unexpected ChaCha20 variant"
#endif

TEST_STATIC_ASSERT(CHACHA20_KEY_SIZE == 32u, key_size);
TEST_STATIC_ASSERT(CHACHA20_BLOCK_SIZE == 64u, block_size);

static unsigned int failures;

#define CHECK(condition) check_condition((condition), #condition, __FILE__, __LINE__)
#define CHECK_STATUS(expression, expected) \
	check_status((expression), (expected), #expression, __FILE__, __LINE__)

static void check_condition(
	int condition, const char *description, const char *file, int line)
{
	if (!condition)
	{
		fprintf(stderr, "%s:%d: check failed: %s\n", file, line, description);
		failures++;
	}
}

static void check_status(
	enum chacha20_status actual,
	enum chacha20_status expected,
	const char *description,
	const char *file,
	int line)
{
	if (actual != expected)
	{
		fprintf(
			stderr,
			"%s:%d: %s returned status %d; expected %d\n",
			file,
			line,
			description,
			(int)actual,
			(int)expected);
		failures++;
	}
}

static int hex_value(char character)
{
	if (character >= '0' && character <= '9')
	{
		return character - '0';
	}
	if (character >= 'a' && character <= 'f')
	{
		return character - 'a' + 10;
	}
	if (character >= 'A' && character <= 'F')
	{
		return character - 'A' + 10;
	}
	return -1;
}

static int decode_hex(const char *hex, uint8_t *output, size_t output_size)
{
	size_t i;

	if (strlen(hex) != output_size * 2u)
	{
		return 0;
	}

	for (i = 0u; i < output_size; ++i)
	{
		int high = hex_value(hex[i * 2u]);
		int low = hex_value(hex[i * 2u + 1u]);

		if (high < 0 || low < 0)
		{
			return 0;
		}
		output[i] = (uint8_t)((high << 4) | low);
	}
	return 1;
}

static void check_bytes_equal(
	const uint8_t *actual,
	const uint8_t *expected,
	size_t size,
	const char *description)
{
	size_t i;

	for (i = 0u; i < size; ++i)
	{
		if (actual[i] != expected[i])
		{
			fprintf(
				stderr,
				"%s: byte %zu is %02x; expected %02x\n",
				description,
				i,
				(unsigned int)actual[i],
				(unsigned int)expected[i]);
			failures++;
			return;
		}
	}
}

static void fill_inputs(
	uint8_t key[CHACHA20_KEY_SIZE],
	uint8_t nonce[CHACHA20_NONCE_SIZE])
{
	size_t i;

	for (i = 0u; i < CHACHA20_KEY_SIZE; ++i)
	{
		key[i] = (uint8_t)(i * 7u + 3u);
	}
	for (i = 0u; i < CHACHA20_NONCE_SIZE; ++i)
	{
		nonce[i] = (uint8_t)(0xa0u + i * 5u);
	}
}

static void run_keystream_kat(
	const char *name,
	const uint8_t key[CHACHA20_KEY_SIZE],
	const uint8_t nonce[CHACHA20_NONCE_SIZE],
	uint64_t counter,
	const char *expected_hex,
	size_t output_size)
{
	struct chacha20_context ctx;
	uint8_t actual[128] = {0};
	uint8_t expected[128];

	CHECK(output_size <= sizeof(actual));
	if (output_size > sizeof(actual))
	{
		return;
	}
	CHECK(decode_hex(expected_hex, expected, output_size));
	CHECK_STATUS(
		chacha20_init_context(&ctx, key, nonce, counter),
		CHACHA20_OK);
	CHECK_STATUS(chacha20_xor(&ctx, actual, output_size), CHACHA20_OK);
	check_bytes_equal(actual, expected, output_size, name);
}

#if CHACHA20_VARIANT == CHACHA20_VARIANT_RFC8439

static void test_rfc8439_block_vector(void)
{
	uint8_t key[CHACHA20_KEY_SIZE];
	const uint8_t nonce[CHACHA20_NONCE_SIZE] = {
		0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
		0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
	};
	size_t i;

	for (i = 0u; i < sizeof(key); ++i)
	{
		key[i] = (uint8_t)i;
	}
	run_keystream_kat(
		"RFC 8439 section 2.3.2 block",
		key,
		nonce,
		UINT64_C(1),
		"10f1e7e4d13b5915500fdd1fa32071c4"
		"c7d1f4c733c068030422aa9ac3d46c4e"
		"d2826446079faa0914c2d705d98b02a2"
		"b5129cd1de164eb9cbd083e8a2503c4e",
		64u);
}

static void test_rfc8439_cipher_vector(void)
{
	static const char plaintext[] =
		"Ladies and Gentlemen of the class of '99: If I could offer you only "
		"one tip for the future, sunscreen would be it.";
	uint8_t key[CHACHA20_KEY_SIZE];
	const uint8_t nonce[CHACHA20_NONCE_SIZE] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
	};
	uint8_t actual[sizeof(plaintext) - 1u];
	uint8_t expected[sizeof(actual)];
	struct chacha20_context ctx;
	size_t i;

	for (i = 0u; i < sizeof(key); ++i)
	{
		key[i] = (uint8_t)i;
	}
	memcpy(actual, plaintext, sizeof(actual));
	CHECK(decode_hex(
		"6e2e359a2568f98041ba0728dd0d6981"
		"e97e7aec1d4360c20a27afccfd9fae0b"
		"f91b65c5524733ab8f593dabcd62b357"
		"1639d624e65152ab8f530c359f0861d8"
		"07ca0dbf500d6a6156a38e088a22b65e"
		"52bc514d16ccf806818ce91ab7793736"
		"5af90bbf74a35be6b40b8eedf2785e42"
		"874d",
		expected,
		sizeof(expected)));
	CHECK_STATUS(chacha20_init_context(&ctx, key, nonce, 1u), CHACHA20_OK);
	CHECK_STATUS(chacha20_xor(&ctx, actual, sizeof(actual)), CHACHA20_OK);
	check_bytes_equal(
		actual,
		expected,
		sizeof(actual),
		"RFC 8439 section 2.4.2 ciphertext");
}

static void test_issue_7_counter_range(void)
{
	uint8_t key[CHACHA20_KEY_SIZE] = {0};
	uint8_t nonce[CHACHA20_NONCE_SIZE] = {0};
	uint8_t byte = 0x5au;
	struct chacha20_context ctx;

	memset(&ctx, 0xa5, sizeof(ctx));
	CHECK_STATUS(
		chacha20_init_context(&ctx, key, nonce, UINT64_C(0x100000000)),
		CHACHA20_ERR_COUNTER_RANGE);
	CHECK_STATUS(chacha20_xor(&ctx, &byte, 1u), CHACHA20_ERR_INVALID_STATE);
	CHECK(byte == 0x5au);
}

#else

static void test_original_vectors(void)
{
	uint8_t key[CHACHA20_KEY_SIZE] = {0};
	uint8_t nonce[CHACHA20_NONCE_SIZE] = {0};

	run_keystream_kat(
		"Original ChaCha20 draft TC1",
		key,
		nonce,
		UINT64_C(0),
		"76b8e0ada0f13d90405d6ae55386bd28"
		"bdd219b8a08ded1aa836efcc8b770dc7"
		"da41597c5157488d7724e03fb8d84a37"
		"6a43b8f41518a11cc387b669b2ee6586"
		"9f07e7be5551387a98ba977c732d080d"
		"cb0f29a048e3656912c6533e32ee7aed"
		"29b721769ce64e43d57133b074d839d5"
		"31ed1f28510afb45ace10a1f4b794d6f",
		128u);

	nonce[0] = 1u;
	run_keystream_kat(
		"Original ChaCha20 draft TC3",
		key,
		nonce,
		UINT64_C(0),
		"ef3fdfd6c61578fbf5cf35bd3dd33b80"
		"09631634d21e42ac33960bd138e50d32"
		"111e4caf237ee53ca8ad6426194a8854"
		"5ddc497a0b466e7d6bbdb0041b2f586b"
		"5305e5e44aff19b235936144675efbe4"
		"409eb7e8e5f1430f5f5836aeb49bb532"
		"8b017c4b9dc11f8a03863fa803dc71d5"
		"726b2b6b31aa32708afe5af1d6b69058",
		128u);
}

static void test_original_high_counter_vector(void)
{
	uint8_t key[CHACHA20_KEY_SIZE];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
	size_t i;

	for (i = 0u; i < sizeof(key); ++i)
	{
		key[i] = (uint8_t)i;
	}
	for (i = 0u; i < sizeof(nonce); ++i)
	{
		nonce[i] = (uint8_t)i;
	}

	/* Cross-checked with OpenSSL EVP_chacha20 using a little-endian 16-byte IV. */
	run_keystream_kat(
		"Original ChaCha20 counter 2^32",
		key,
		nonce,
		UINT64_C(0x100000000),
		"2fcab2c09a960545c6f57e9269ebc22b"
		"4ed12782e66dc4cb612536f5cdbed4bc"
		"ba16af8a92140bf4ded4808af8eee82b"
		"d0f18fbb64f073c2a547bc2372528f36",
		64u);
}

#endif

static void xor_in_fragments(
	struct chacha20_context *ctx,
	uint8_t *bytes,
	size_t size)
{
	static const size_t fragment_sizes[] = {1u, 7u, 31u, 2u, 64u, 3u, 17u};
	size_t offset = 0u;
	size_t fragment_index = 0u;

	while (offset < size)
	{
		size_t fragment = fragment_sizes[
			fragment_index % (sizeof(fragment_sizes) / sizeof(fragment_sizes[0]))];
		if (fragment > size - offset)
		{
			fragment = size - offset;
		}
		CHECK_STATUS(chacha20_xor(ctx, bytes + offset, fragment), CHACHA20_OK);
		offset += fragment;
		fragment_index++;
	}
}

static void test_streaming_and_round_trip(void)
{
	static const size_t sizes[] = {0u, 1u, 63u, 64u, 65u, 127u, 128u, 129u};
	uint8_t key[CHACHA20_KEY_SIZE];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
	size_t case_index;

	fill_inputs(key, nonce);

	for (case_index = 0u; case_index < sizeof(sizes) / sizeof(sizes[0]); ++case_index)
	{
		uint8_t plaintext[129];
		uint8_t one_shot[129];
		uint8_t fragmented[129];
		struct chacha20_context one_shot_ctx;
		struct chacha20_context fragmented_ctx;
		struct chacha20_context decrypt_ctx;
		size_t i;
		size_t size = sizes[case_index];

		for (i = 0u; i < sizeof(plaintext); ++i)
		{
			plaintext[i] = (uint8_t)(i * 11u + case_index);
		}
		memcpy(one_shot, plaintext, sizeof(one_shot));
		memcpy(fragmented, plaintext, sizeof(fragmented));

		CHECK_STATUS(
			chacha20_init_context(&one_shot_ctx, key, nonce, 7u),
			CHACHA20_OK);
		CHECK_STATUS(
			chacha20_init_context(&fragmented_ctx, key, nonce, 7u),
			CHACHA20_OK);
		CHECK_STATUS(
			chacha20_xor(&one_shot_ctx, size == 0u ? NULL : one_shot, size),
			CHACHA20_OK);
		xor_in_fragments(&fragmented_ctx, fragmented, size);
		check_bytes_equal(one_shot, fragmented, size, "one-shot/fragmented");

		CHECK_STATUS(
			chacha20_init_context(&decrypt_ctx, key, nonce, 7u),
			CHACHA20_OK);
		CHECK_STATUS(
			chacha20_xor(&decrypt_ctx, size == 0u ? NULL : one_shot, size),
			CHACHA20_OK);
		check_bytes_equal(one_shot, plaintext, size, "encrypt/decrypt round trip");
	}
}

static void test_reinitialization(void)
{
	uint8_t key[CHACHA20_KEY_SIZE];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
	uint8_t first[129] = {0};
	uint8_t second[129] = {0};
	struct chacha20_context reused;
	struct chacha20_context fresh;

	fill_inputs(key, nonce);
	CHECK_STATUS(chacha20_init_context(&reused, key, nonce, 19u), CHACHA20_OK);
	CHECK_STATUS(chacha20_xor(&reused, first, sizeof(first)), CHACHA20_OK);
	CHECK_STATUS(chacha20_init_context(&reused, key, nonce, 19u), CHACHA20_OK);
	CHECK_STATUS(chacha20_xor(&reused, second, sizeof(second)), CHACHA20_OK);
	check_bytes_equal(second, first, sizeof(first), "reinitialized context");

	memset(second, 0, sizeof(second));
	CHECK_STATUS(chacha20_init_context(&fresh, key, nonce, 19u), CHACHA20_OK);
	CHECK_STATUS(chacha20_xor(&fresh, second, sizeof(second)), CHACHA20_OK);
	check_bytes_equal(second, first, sizeof(first), "fresh/reinitialized context");
}

static void test_invalid_arguments_and_state(void)
{
	uint8_t key[CHACHA20_KEY_SIZE];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
	uint8_t byte = 0xc3u;
	struct chacha20_context ctx;
	struct chacha20_context snapshot;

	fill_inputs(key, nonce);
	CHECK_STATUS(
		chacha20_init_context(NULL, key, nonce, 0u),
		CHACHA20_ERR_INVALID_ARGUMENT);

	memset(&ctx, 0xa5, sizeof(ctx));
	CHECK_STATUS(
		chacha20_init_context(&ctx, NULL, nonce, 0u),
		CHACHA20_ERR_INVALID_ARGUMENT);
	CHECK_STATUS(chacha20_xor(&ctx, &byte, 1u), CHACHA20_ERR_INVALID_STATE);
	CHECK(byte == 0xc3u);

	memset(&ctx, 0xa5, sizeof(ctx));
	CHECK_STATUS(
		chacha20_init_context(&ctx, key, NULL, 0u),
		CHACHA20_ERR_INVALID_ARGUMENT);
	CHECK_STATUS(chacha20_xor(&ctx, NULL, 0u), CHACHA20_ERR_INVALID_STATE);

	CHECK_STATUS(chacha20_init_context(&ctx, key, nonce, 0u), CHACHA20_OK);
	memcpy(&snapshot, &ctx, sizeof(snapshot));
	CHECK_STATUS(chacha20_xor(&ctx, NULL, 0u), CHACHA20_OK);
	CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0);
	CHECK_STATUS(chacha20_xor(&ctx, NULL, 1u), CHACHA20_ERR_INVALID_ARGUMENT);
	CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0);

	CHECK_STATUS(chacha20_xor(NULL, &byte, 1u), CHACHA20_ERR_INVALID_ARGUMENT);
	CHECK_STATUS(chacha20_xor(NULL, NULL, 0u), CHACHA20_ERR_INVALID_ARGUMENT);

	memset(&ctx, 0, sizeof(ctx));
	memcpy(&snapshot, &ctx, sizeof(snapshot));
	CHECK_STATUS(chacha20_xor(&ctx, &byte, 1u), CHACHA20_ERR_INVALID_STATE);
	CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0);
	CHECK(byte == 0xc3u);
}

static void test_counter_exhaustion(void)
{
	const uint64_t counter_max = (uint64_t)CHACHA20_COUNTER_MAX;
	uint8_t key[CHACHA20_KEY_SIZE];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
	uint8_t full_block[CHACHA20_BLOCK_SIZE] = {0};
	uint8_t split_block[CHACHA20_BLOCK_SIZE] = {0};
	uint8_t oversized[CHACHA20_BLOCK_SIZE + 1u];
	uint8_t compare_two_blocks[CHACHA20_BLOCK_SIZE * 2u] = {0};
	uint8_t too_many_blocks[CHACHA20_BLOCK_SIZE * 2u + 1u];
	uint8_t standalone_last[CHACHA20_BLOCK_SIZE] = {0};
	uint8_t byte;
	struct chacha20_context ctx;
	struct chacha20_context snapshot;
	size_t nonce_word_start;
	size_t nonce_word_count;
	uint32_t nonce_words[3] = {0};

	fill_inputs(key, nonce);
#if CHACHA20_VARIANT == CHACHA20_VARIANT_RFC8439
	nonce_word_start = 13u;
	nonce_word_count = 3u;
#else
	nonce_word_start = 14u;
	nonce_word_count = 2u;
#endif

	/* The final block is usable, but a request needing a second block is atomic. */
	memset(oversized, 0x6d, sizeof(oversized));
	CHECK_STATUS(
		chacha20_init_context(&ctx, key, nonce, counter_max),
		CHACHA20_OK);
	memcpy(&snapshot, &ctx, sizeof(snapshot));
	CHECK_STATUS(
		chacha20_xor(&ctx, oversized, sizeof(oversized)),
		CHACHA20_ERR_COUNTER_EXHAUSTED);
	CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0);
	{
		uint8_t expected_oversized[CHACHA20_BLOCK_SIZE + 1u];
		memset(expected_oversized, 0x6d, sizeof(expected_oversized));
		CHECK(memcmp(oversized, expected_oversized, sizeof(oversized)) == 0);
	}

	CHECK_STATUS(
		chacha20_init_context(&ctx, key, nonce, counter_max),
		CHACHA20_OK);
	memcpy(
		nonce_words,
		ctx._chacha20_state + nonce_word_start,
		nonce_word_count * sizeof(nonce_words[0]));
	CHECK_STATUS(chacha20_xor(&ctx, full_block, sizeof(full_block)), CHACHA20_OK);
	CHECK(memcmp(
		nonce_words,
		ctx._chacha20_state + nonce_word_start,
		nonce_word_count * sizeof(nonce_words[0])) == 0);
	memcpy(&snapshot, &ctx, sizeof(snapshot));
	byte = 0x91u;
	CHECK_STATUS(chacha20_xor(&ctx, &byte, 1u), CHACHA20_ERR_COUNTER_EXHAUSTED);
	CHECK(byte == 0x91u);
	CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0);

	/* Cached bytes from the final block remain consumable after exhaustion. */
	CHECK_STATUS(
		chacha20_init_context(&ctx, key, nonce, counter_max),
		CHACHA20_OK);
	CHECK_STATUS(chacha20_xor(&ctx, split_block, 1u), CHACHA20_OK);
	CHECK_STATUS(
		chacha20_xor(&ctx, split_block + 1u, CHACHA20_BLOCK_SIZE - 1u),
		CHACHA20_OK);
	check_bytes_equal(split_block, full_block, sizeof(full_block), "split final block");
	byte = 0x37u;
	CHECK_STATUS(chacha20_xor(&ctx, &byte, 1u), CHACHA20_ERR_COUNTER_EXHAUSTED);
	CHECK(byte == 0x37u);

	/* MAX-1 has exactly two blocks left; the second equals standalone MAX. */
	CHECK_STATUS(
		chacha20_init_context(&ctx, key, nonce, counter_max - UINT64_C(1)),
		CHACHA20_OK);
	CHECK_STATUS(
		chacha20_xor(&ctx, compare_two_blocks, sizeof(compare_two_blocks)),
		CHACHA20_OK);
	CHECK_STATUS(
		chacha20_init_context(&snapshot, key, nonce, counter_max),
		CHACHA20_OK);
	CHECK_STATUS(
		chacha20_xor(&snapshot, standalone_last, sizeof(standalone_last)),
		CHACHA20_OK);
	check_bytes_equal(
		compare_two_blocks + CHACHA20_BLOCK_SIZE,
		standalone_last,
		CHACHA20_BLOCK_SIZE,
		"MAX-1 counter progression");

	memset(too_many_blocks, 0x42, sizeof(too_many_blocks));
	CHECK_STATUS(
		chacha20_init_context(&ctx, key, nonce, counter_max - UINT64_C(1)),
		CHACHA20_OK);
	memcpy(&snapshot, &ctx, sizeof(snapshot));
	CHECK_STATUS(
		chacha20_xor(&ctx, too_many_blocks, sizeof(too_many_blocks)),
		CHACHA20_ERR_COUNTER_EXHAUSTED);
	CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0);
	{
		uint8_t expected_two_blocks[CHACHA20_BLOCK_SIZE * 2u + 1u];
		memset(expected_two_blocks, 0x42, sizeof(expected_two_blocks));
		CHECK(memcmp(
			too_many_blocks,
			expected_two_blocks,
			sizeof(too_many_blocks)) == 0);
	}

	/* A huge request must fail in preflight without dereferencing past byte. */
	CHECK_STATUS(
		chacha20_init_context(&ctx, key, nonce, counter_max),
		CHACHA20_OK);
	memcpy(&snapshot, &ctx, sizeof(snapshot));
	byte = 0xabu;
	CHECK_STATUS(chacha20_xor(&ctx, &byte, SIZE_MAX), CHACHA20_ERR_COUNTER_EXHAUSTED);
	CHECK(byte == 0xabu);
	CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0);
}

static void test_counter_progression(void)
{
	uint8_t key[CHACHA20_KEY_SIZE];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
	uint8_t consecutive[CHACHA20_BLOCK_SIZE * 2u] = {0};
	uint8_t standalone[CHACHA20_BLOCK_SIZE] = {0};
	struct chacha20_context ctx;
	struct chacha20_context standalone_ctx;
	uint64_t first_counter;

	fill_inputs(key, nonce);
#if CHACHA20_VARIANT == CHACHA20_VARIANT_RFC8439
	first_counter = UINT64_C(12345);
#else
	/* Exercise carry from the low counter word into the high word. */
	first_counter = UINT64_C(0xffffffff);
#endif

	CHECK_STATUS(
		chacha20_init_context(&ctx, key, nonce, first_counter),
		CHACHA20_OK);
	CHECK_STATUS(
		chacha20_xor(&ctx, consecutive, sizeof(consecutive)),
		CHACHA20_OK);
	CHECK_STATUS(
		chacha20_init_context(&standalone_ctx, key, nonce, first_counter + 1u),
		CHACHA20_OK);
	CHECK_STATUS(
		chacha20_xor(&standalone_ctx, standalone, sizeof(standalone)),
		CHACHA20_OK);
	check_bytes_equal(
		consecutive + CHACHA20_BLOCK_SIZE,
		standalone,
		CHACHA20_BLOCK_SIZE,
		"counter progression and nonce stability");
}

int main(void)
{
#if CHACHA20_VARIANT == CHACHA20_VARIANT_RFC8439
	test_rfc8439_block_vector();
	test_rfc8439_cipher_vector();
	test_issue_7_counter_range();
#else
	test_original_vectors();
	test_original_high_counter_vector();
#endif
	test_streaming_and_round_trip();
	test_reinitialization();
	test_invalid_arguments_and_state();
	test_counter_exhaustion();
	test_counter_progression();

	if (failures != 0u)
	{
		fprintf(stderr, "%u %s test(s) failed\n", failures, TEST_VARIANT_NAME);
		return 1;
	}

	printf("All %s tests passed\n", TEST_VARIANT_NAME);
	return 0;
}
