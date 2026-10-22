#ifndef CACHE_H
#define CACHE_H

#define BYTE (1)
#define KB (1024*BYTE)
#define MB (1024*KB)
#define GB (1024*MB)

#define L1_SETS 64
#define L1_SET_BITS 6
#define L1_WAYS 8
#define L1_BLOCK_SZ_BYTES 64
#define L1_BLOCK_BITS 6
#define L1_SZ_BYTES (L1_SETS*L1_WAYS*L1_BLOCK_SZ_BYTES)
#define FULL_MASK 0xFFFFFFFFFFFFFFFF
#define OFF_MASK (~(FULL_MASK << L1_BLOCK_BITS))
#define TAG_MASK (FULL_MASK << (L1_SET_BITS + L1_BLOCK_BITS))
#define SET_MASK (~(TAG_MASK | OFF_MASK))

#ifndef USE_EVICTION_FLUSH
#define USE_EVICTION_FLUSH 0
#endif

#if USE_EVICTION_FLUSH
char __attribute__((aligned(4096))) buffer[4 * 1024 * 1024];
uint8_t dummyMem[5 * L1_SZ_BYTES];
#endif

static inline uint64_t rdcycle(void) {
  uint64_t value;
  asm volatile("csrr %0, cycle" : "=r"(value));
  return value;
}

static inline void xs_fence(void) {
  asm volatile ("fence rw, rw" ::: "memory");
}

static inline void xs_flush_cache_line(void* addr) {
  asm volatile (
    "cbo.flush 0(%0)"
    :
    : "r"(addr)
    : "memory");
}

static inline uint64_t xs_probe_time(volatile uint8_t* addr) {
  uint64_t start, end;
  uint8_t volatile dummy = 0;

  xs_fence();
  start = rdcycle();
  dummy &= *addr;
  xs_fence();
  end = rdcycle();

  return end - start;
}

static inline uint64_t xs_calibrate_threshold(uint8_t* probe, uint64_t stride) {
  uint64_t hot_total = 0;
  uint64_t cold_total = 0;
  uint8_t volatile dummy = 0;

  for (uint64_t i = 0; i < 8; ++i) {
    volatile uint8_t* hot = &probe[0];
    volatile uint8_t* cold = &probe[stride];

    dummy &= *hot;
    hot_total += xs_probe_time(hot);

    xs_flush_cache_line((void*)cold);
    xs_fence();
    cold_total += xs_probe_time(cold);
  }

  return ((hot_total / 8) + (cold_total / 8)) / 2;
}

#if USE_EVICTION_FLUSH
void flushCache(uint64_t addr, uint64_t sz){
    uint64_t numSetsClear = sz >> L1_BLOCK_BITS;
    if ((sz & OFF_MASK) != 0){
        numSetsClear += 1;
    }
    if (numSetsClear > L1_SETS){
        numSetsClear = L1_SETS;
    }

    uint8_t dummy = 0;
    uint64_t alignedMem = (((uint64_t)&dummyMem) + L1_SZ_BYTES) & TAG_MASK;

    for (uint64_t i = 0; i < numSetsClear; ++i){
        uint64_t setOffset = (((addr & SET_MASK) >> L1_BLOCK_BITS) + i) << L1_BLOCK_BITS;
        for(uint64_t j = 0; j < 4*L1_WAYS; ++j){
            uint64_t wayOffset = j << (L1_BLOCK_BITS + L1_SET_BITS);
            dummy = *((uint8_t*)(alignedMem + setOffset + wayOffset));
        }
    }
}
#endif

#endif
