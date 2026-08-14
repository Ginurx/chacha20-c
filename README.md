# chacha20-c

A small C implementation of the ChaCha20 stream cipher. The library supports
two ChaCha20 variants as compile-time alternatives:

| Variant | Nonce | Block counter |
| --- | ---: | ---: |
| [RFC 8439 / IETF](https://datatracker.ietf.org/doc/html/rfc8439) (default) | 12 bytes | 32 bits |
| [Original ChaCha20](https://cr.yp.to/chacha.html) | 8 bytes | 64 bits |

> [!WARNING]
> This library only provides the unauthenticated ChaCha20 XOR operation. It
> does not detect modified ciphertext. For production protocols, prefer a
> mature implementation of an AEAD construction such as ChaCha20-Poly1305.

## Selecting a variant

RFC 8439 is the default and requires no configuration:

```sh
cc -std=c11 -c chacha20.c -o chacha20.o
```

To use Original ChaCha20, define `CHACHA20_VARIANT` when compiling both the
library and application code that includes `chacha20.h`:

```sh
cc -std=c11 -DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL \
   -c chacha20.c -o chacha20-original.o
```

Any other value of `CHACHA20_VARIANT` is rejected at compile time.

## API

The header exposes these size and limit constants:

- `CHACHA20_KEY_SIZE`: 32 in both variants.
- `CHACHA20_BLOCK_SIZE`: 64 in both variants.
- `CHACHA20_NONCE_SIZE`: 12 for RFC 8439, 8 for Original ChaCha20.
- `CHACHA20_COUNTER_MAX`: `UINT32_MAX` for RFC 8439, `UINT64_MAX` for
  Original ChaCha20.

```c
enum chacha20_status {
    CHACHA20_OK = 0,
    CHACHA20_ERR_INVALID_ARGUMENT,
    CHACHA20_ERR_COUNTER_RANGE,
    CHACHA20_ERR_COUNTER_EXHAUSTED,
    CHACHA20_ERR_INVALID_STATE
};

enum chacha20_status chacha20_init_context(
    struct chacha20_context *ctx,
    const uint8_t key[CHACHA20_KEY_SIZE],
    const uint8_t nonce[CHACHA20_NONCE_SIZE],
    uint64_t counter);

enum chacha20_status chacha20_xor(
    struct chacha20_context *ctx,
    uint8_t *bytes,
    size_t n_bytes);
```

The context may be stack-allocated, but its fields are internal implementation
details. Do not inspect, copy, serialize, or modify them.

Always check both return values:

```c
#include "chacha20.h"

static enum chacha20_status
crypt_in_place(uint8_t *buffer, size_t buffer_size,
               const uint8_t key[CHACHA20_KEY_SIZE],
               const uint8_t nonce[CHACHA20_NONCE_SIZE],
               uint64_t initial_counter)
{
    struct chacha20_context ctx;
    enum chacha20_status status;

    status = chacha20_init_context(&ctx, key, nonce, initial_counter);
    if (status != CHACHA20_OK) {
        return status;
    }

    return chacha20_xor(&ctx, buffer, buffer_size);
}
```

Calling `chacha20_xor` again continues the same stream. To decrypt, initialize
a fresh context with the same key, nonce, initial counter, and variant, then
apply `chacha20_xor` to the ciphertext from the beginning.

For a valid context, a zero-length call succeeds and `bytes` may be `NULL`.
For a nonzero length, `bytes == NULL` returns
`CHACHA20_ERR_INVALID_ARGUMENT`. A context left invalid by failed
initialization returns `CHACHA20_ERR_INVALID_STATE` when used.

### Counter limits

RFC 8439 accepts initial counters from 0 through `UINT32_MAX`. Passing a larger
value returns `CHACHA20_ERR_COUNTER_RANGE`; it is never folded into the nonce.
Original ChaCha20 accepts the full `uint64_t` range.

In both variants the block at `CHACHA20_COUNTER_MAX` is usable. Once that block
has been generated, any bytes already cached from it may still be consumed,
but the library will not wrap the counter to zero. A request that would require
another block returns `CHACHA20_ERR_COUNTER_EXHAUSTED`. Exhaustion is checked
for the whole request before encryption, so on this error both the caller's
buffer and the context remain unchanged.

Do not use the same raw key in both variants. If an application must support
both, derive independent, domain-separated keys outside this library. As with
every stream cipher, never reuse a key/nonce pair within a variant.

## Building and testing

The test program is dependency-free. Each command set below builds and runs
both variants. It covers published known-answer vectors, streaming/chunk boundaries,
counter exhaustion and atomic failure, invalid inputs, and the historical
counter/nonce collision regression. Run commands from the repository root.

GitHub Actions also cross-compiles and runs both variants for big-endian s390x
under QEMU. Published known-answer vectors, rather than round trips alone, are
the regression check for host-independent byte ordering.

### GCC

Debug:

```sh
gcc -std=c11 -O0 -g -Wall -Wextra -Wpedantic -Werror -I. \
    chacha20.c tests/test_chacha20.c -o test-rfc8439
./test-rfc8439
gcc -std=c11 -O0 -g -Wall -Wextra -Wpedantic -Werror -I. \
    -DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL \
    chacha20.c tests/test_chacha20.c -o test-original
./test-original
```

Release (`assert` disabled):

```sh
gcc -std=c11 -O2 -DNDEBUG -Wall -Wextra -Wpedantic -Werror -I. \
    chacha20.c tests/test_chacha20.c -o test-rfc8439-release
./test-rfc8439-release
gcc -std=c11 -O2 -DNDEBUG -Wall -Wextra -Wpedantic -Werror -I. \
    -DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL \
    chacha20.c tests/test_chacha20.c -o test-original-release
./test-original-release
```

AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
gcc -std=c11 -O1 -g -fno-omit-frame-pointer \
    -fsanitize=address,undefined -Wall -Wextra -Wpedantic -I. \
    chacha20.c tests/test_chacha20.c -o test-rfc8439-sanitize
./test-rfc8439-sanitize
gcc -std=c11 -O1 -g -fno-omit-frame-pointer \
    -fsanitize=address,undefined -Wall -Wextra -Wpedantic -I. \
    -DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL \
    chacha20.c tests/test_chacha20.c -o test-original-sanitize
./test-original-sanitize
```

### Clang

Debug:

```sh
clang -std=c11 -O0 -g -Wall -Wextra -Wpedantic -Werror -I. \
      chacha20.c tests/test_chacha20.c -o test-rfc8439
./test-rfc8439
clang -std=c11 -O0 -g -Wall -Wextra -Wpedantic -Werror -I. \
      -DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL \
      chacha20.c tests/test_chacha20.c -o test-original
./test-original
```

Release (`assert` disabled):

```sh
clang -std=c11 -O2 -DNDEBUG -Wall -Wextra -Wpedantic -Werror -I. \
      chacha20.c tests/test_chacha20.c -o test-rfc8439-release
./test-rfc8439-release
clang -std=c11 -O2 -DNDEBUG -Wall -Wextra -Wpedantic -Werror -I. \
      -DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL \
      chacha20.c tests/test_chacha20.c -o test-original-release
./test-original-release
```

AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
clang -std=c11 -O1 -g -fno-omit-frame-pointer \
      -fsanitize=address,undefined -Wall -Wextra -Wpedantic -I. \
      chacha20.c tests/test_chacha20.c -o test-rfc8439-sanitize
./test-rfc8439-sanitize
clang -std=c11 -O1 -g -fno-omit-frame-pointer \
      -fsanitize=address,undefined -Wall -Wextra -Wpedantic -I. \
      -DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL \
      chacha20.c tests/test_chacha20.c -o test-original-sanitize
./test-original-sanitize
```

### MSVC Developer Command Prompt

Debug:

```bat
cl /nologo /std:c11 /W4 /WX /Od /Zi /I. chacha20.c tests\test_chacha20.c /Fe:test-rfc8439.exe
test-rfc8439.exe
cl /nologo /std:c11 /W4 /WX /Od /Zi /I. /DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL chacha20.c tests\test_chacha20.c /Fe:test-original.exe
test-original.exe
```

Release (`assert` disabled):

```bat
cl /nologo /std:c11 /W4 /WX /O2 /DNDEBUG /I. chacha20.c tests\test_chacha20.c /Fe:test-rfc8439-release.exe
test-rfc8439-release.exe
cl /nologo /std:c11 /W4 /WX /O2 /DNDEBUG /I. /DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL chacha20.c tests\test_chacha20.c /Fe:test-original-release.exe
test-original-release.exe
```

AddressSanitizer (supported MSVC targets only):

```bat
cl /nologo /std:c11 /W4 /Od /Zi /fsanitize=address /I. chacha20.c tests\test_chacha20.c /Fe:test-rfc8439-asan.exe
test-rfc8439-asan.exe
cl /nologo /std:c11 /W4 /Od /Zi /fsanitize=address /I. /DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL chacha20.c tests\test_chacha20.c /Fe:test-original-asan.exe
test-original-asan.exe
```

### C++ header/link smoke test

Compile `chacha20.c` as C, then link the C++17 smoke test using the same variant
macro. For GCC (replace `gcc`/`g++` with `clang`/`clang++` to use Clang):

```sh
gcc -std=c11 -Wall -Wextra -Wpedantic -Werror -I. \
    -c chacha20.c -o chacha20-rfc8439.o
g++ -std=c++17 -Wall -Wextra -Wpedantic -Werror -I. \
    tests/test_header.cpp chacha20-rfc8439.o -o test-header-rfc8439
./test-header-rfc8439
gcc -std=c11 -Wall -Wextra -Wpedantic -Werror -I. \
    -DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL \
    -c chacha20.c -o chacha20-original.o
g++ -std=c++17 -Wall -Wextra -Wpedantic -Werror -I. \
    -DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL \
    tests/test_header.cpp chacha20-original.o -o test-header-original
./test-header-original
```

For MSVC:

```bat
cl /nologo /std:c11 /W4 /WX /c /I. chacha20.c /Fochacha20-rfc8439.obj
cl /nologo /std:c++17 /W4 /WX /TP /I. tests\test_header.cpp chacha20-rfc8439.obj /Fe:test-header-rfc8439.exe
test-header-rfc8439.exe
cl /nologo /std:c11 /W4 /WX /c /I. /DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL chacha20.c /Fochacha20-original.obj
cl /nologo /std:c++17 /W4 /WX /TP /I. /DCHACHA20_VARIANT=CHACHA20_VARIANT_ORIGINAL tests\test_header.cpp chacha20-original.obj /Fe:test-header-original.exe
test-header-original.exe
```

## Migrating from versions before this fix

This release intentionally breaks the old source and binary interfaces:

| Before | Now |
| --- | --- |
| One nonstandard 12-byte-nonce/64-bit-counter layout | A build selects RFC 8439 or Original ChaCha20 |
| `void` initialization and XOR functions | Both functions return `enum chacha20_status` |
| Any `uint64_t` accepted with a 12-byte nonce | RFC 8439 rejects counters above `UINT32_MAX` |
| Counter overflow modified the first nonce word | Nonce words never change; exhaustion is an error |
| Shared unsuffixed link symbols | Variant-specific symbols detect configuration mismatch |
| Public context layout could appear stable | Context fields are explicitly internal and ABI-unstable |

Recompile all callers, choose a variant explicitly where appropriate, use a
nonce of `CHACHA20_NONCE_SIZE`, and handle every returned status. Do not restore
the former function signatures with casts or wrappers that discard errors.

There is deliberately no compatibility mode for the historical mixed layout,
and this API cannot continue a stream that used it. Isolate any unavoidable
legacy recovery in a separate migration tool; do not expose the old construction
through the normal encryption API. Historical data produced entirely within the
RFC-compatible counter range may happen to match RFC 8439, but that data should
be verified before migration rather than relying on legacy behavior.

## Scope

"Original ChaCha20" here means the 256-bit-key, 20-round construction with an
8-byte nonce and 64-bit block counter. This library does not implement 128-bit
keys, ChaCha8/12, XChaCha20, Poly1305, key derivation, or a legacy mixed layout.
