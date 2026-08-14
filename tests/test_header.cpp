#include "chacha20.h"

#include <cstdint>

static_assert(CHACHA20_KEY_SIZE == 32u, "ChaCha20 key size");
static_assert(CHACHA20_BLOCK_SIZE == 64u, "ChaCha20 block size");

int main()
{
	chacha20_context ctx{};
	std::uint8_t key[CHACHA20_KEY_SIZE]{};
	std::uint8_t nonce[CHACHA20_NONCE_SIZE]{};

	if (chacha20_init_context(&ctx, key, nonce, 0u) != CHACHA20_OK)
	{
		return 1;
	}
	if (chacha20_xor(&ctx, nullptr, 0u) != CHACHA20_OK)
	{
		return 2;
	}
	return 0;
}
