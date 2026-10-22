#ifndef XS_SPECTRE_UTILS_H
#define XS_SPECTRE_UTILS_H

#include <klib.h>
#include <stdint.h>

#define BYTE (1)
#define KB (1024 * BYTE)

#define L1_SETS 64
#define L1_WAYS 8
#define L1_BLOCK_SZ_BYTES 64
#define L1_BLOCK_BITS 6
#define L1_SZ_BYTES (L1_SETS * L1_WAYS * L1_BLOCK_SZ_BYTES)

#define PROBE_ENTRIES 256
#ifndef PROBE_CANDIDATES
#ifndef PROBE_CANDIDATES
#ifndef PROBE_CANDIDATES
#define PROBE_CANDIDATES 62
#endif
#endif
#endif
#define PROBE_BYTES (PROBE_ENTRIES * L1_BLOCK_SZ_BYTES)

#ifndef CACHE_HIT_THRESHOLD
#define CACHE_HIT_THRESHOLD 70
#endif

#ifndef USE_FIXED_CACHE_HIT_THRESHOLD
#define USE_FIXED_CACHE_HIT_THRESHOLD 0
#endif

#ifndef FULL_BYTE_PROBE
#define FULL_BYTE_PROBE 0
#endif


#ifdef CANDIDATE_BASE
#define XS_USE_CANDIDATE_BASE 1
#else
#define XS_USE_CANDIDATE_BASE 0
#endif



#ifndef USE_EVICTION_FLUSH
#define USE_EVICTION_FLUSH 0
#endif

#if USE_EVICTION_FLUSH
#define XS_FULL_MASK 0xFFFFFFFFFFFFFFFFUL
#define XS_L1_SET_BITS 6
#define XS_OFF_MASK (~(XS_FULL_MASK << L1_BLOCK_BITS))
#define XS_TAG_MASK (XS_FULL_MASK << (XS_L1_SET_BITS + L1_BLOCK_BITS))
#define XS_SET_MASK (~(XS_TAG_MASK | XS_OFF_MASK))

static uint8_t xs_evict_dummy_mem[5 * L1_SZ_BYTES] __attribute__((aligned(4096)));

static inline void xs_evict_cache_line(void *addr)
{
  volatile uint8_t dummy = 0;
  uint64_t addr64 = (uint64_t)addr;
  uint64_t aligned_mem = (((uint64_t)&xs_evict_dummy_mem) + L1_SZ_BYTES) & XS_TAG_MASK;
  uint64_t set_offset = ((addr64 & XS_SET_MASK) >> L1_BLOCK_BITS) << L1_BLOCK_BITS;

  for (uint64_t way = 0; way < 4 * L1_WAYS; ++way) {
    uint64_t way_offset = way << (L1_BLOCK_BITS + XS_L1_SET_BITS);
    dummy ^= *((volatile uint8_t *)(aligned_mem + set_offset + way_offset));
  }
  asm volatile("" : "+r"(dummy) : : "memory");
}
#endif


static inline uint64_t xs_rdcycle(void)
{
  uint64_t value;
  asm volatile("csrr %0, cycle" : "=r"(value));
  return value;
}

static inline void xs_fence(void)
{
  asm volatile("fence rw, rw" ::: "memory");
}

static inline void xs_flush_cache_line(void *addr)
{
#if USE_EVICTION_FLUSH
  xs_evict_cache_line(addr);
#else
  asm volatile("cbo.flush 0(%0)" : : "r"(addr) : "memory");
#endif
}

static inline uint64_t xs_probe_time(volatile uint8_t *addr)
{
  uint64_t start;
  uint64_t end;
  volatile uint8_t dummy = 0;

  xs_fence();
  start = xs_rdcycle();
  dummy &= *addr;
  xs_fence();
  end = xs_rdcycle();

  return end - start;
}

static inline uint64_t xs_calibrate_threshold(uint8_t *probe)
{
  uint64_t hot_total = 0;
  uint64_t cold_total = 0;
  volatile uint8_t dummy = 0;

  for (uint64_t i = 0; i < 8; ++i) {
    volatile uint8_t *hot = &probe[0];
    volatile uint8_t *cold = &probe[L1_BLOCK_SZ_BYTES];

    dummy &= *hot;
    hot_total += xs_probe_time(hot);

    xs_flush_cache_line((void *)cold);
    xs_fence();
    cold_total += xs_probe_time(cold);
  }

  return ((hot_total / 8) + (cold_total / 8)) / 2;
}

static inline uint64_t xs_select_threshold(uint64_t measured)
{
#if USE_FIXED_CACHE_HIT_THRESHOLD
  return CACHE_HIT_THRESHOLD;
#else
  return measured == 0 ? CACHE_HIT_THRESHOLD : measured;
#endif
}

static inline void xs_probe_init(uint8_t *probe)
{
  for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
    probe[i * L1_BLOCK_SZ_BYTES] = 1;
  xs_fence();
}

static inline void xs_flush_probe(uint8_t *probe)
{
  for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
    xs_flush_cache_line(&probe[i * L1_BLOCK_SZ_BYTES]);
  xs_fence();
}

static inline uint64_t xs_probe_mix(uint64_t idx)
{
  return ((idx * 167) + 13) & 255;
}

static inline uint64_t xs_candidate_value(uint64_t idx)
{
#if XS_USE_CANDIDATE_BASE
  return ((uint64_t)CANDIDATE_BASE + idx) & 255u;
#else
  if (idx < 10)
    return '0' + idx;
  if (idx < 36)
    return 'A' + (idx - 10);
  return 'a' + (idx - 36);
#endif
}

static inline uint64_t xs_probe_value(uint64_t idx)
{
#if FULL_BYTE_PROBE
  return xs_probe_mix(idx);
#else
  return xs_candidate_value(idx);
#endif
}

static inline uint64_t xs_probe_count(void)
{
#if FULL_BYTE_PROBE
  return PROBE_ENTRIES;
#else
  return PROBE_CANDIDATES;
#endif
}

static inline void xs_top_two_idx(uint64_t *hits, uint64_t count,
                                  uint8_t result[2], uint64_t score[2])
{
  result[0] = 0;
  result[1] = 0;
  score[0] = 0;
  score[1] = 0;

  for (uint64_t i = 0; i < count; ++i) {
    if (hits[i] > score[0]) {
      score[1] = score[0];
      result[1] = result[0];
      score[0] = hits[i];
      result[0] = i;
    } else if (hits[i] > score[1]) {
      score[1] = hits[i];
      result[1] = i;
    }
  }
}

static inline uint64_t xs_limit_len(uint64_t available, uint64_t requested)
{
  return requested < available ? requested : available;
}

#endif
