#include <stdio.h>
#include "Camellia.h"

void dbg_print(char* pr, uint64_t* a){
    printf("%s: ", pr);
    printf("%llx %llx", a[0], a[1]);
    printf("\n");
}

int main(int argc, char** argv){
    uint64_t KEY1[4] = {0x0123456789abcdef, 0xfedcba9876543210, 0x0011223344556677, 0x8899aabbccddeeff};
    uint64_t plain1[2] = {0x0123456789abcdef, 0xfedcba9876543210};
	
    uint64_t KEY2[4] = {0xc940117c2eda1d1e, 0xea32c009d3c85421, 0xb330d6547f0d36e7, 0xaa6a2b1e6d584636};
    uint64_t plain2[16] = {0x4deadcb5a14f37e2, 0x679c344437032d64};
    
    uint64_t KEY3[4] = {0xa8cd7528daab0f84, 0x153a668392acb92a, 0x036cf1343dd64f3f, 0x7c7415eaec0c0b95};
    uint64_t plain3[16] = {0x9857b3c731d0e51b, 0x02a524d66e78f721};
    
    uint64_t KEY4[4] = {0xe9b481268ad16606, 0x457bf03188fbc661, 0x7b8315a64f4ee755, 0xecaaed3727b08411};
    uint64_t plain4[16] = {0xd980bdb42bcc3840, 0x069ec3984a7dc24d};
    
    uint64_t KEY5[4] = {0x971803e766ea3c52, 0x942a89bcda0ecd3e, 0x14042ceba22107bb, 0x07545ce8685e4400};
    uint64_t plain5[16] = {0x640637eed79df51c, 0x19e54da1e114025c};
    
    Camellia256(KEY1, plain1, ENC); 
    dbg_print("Test1: ", plain1);
    Camellia256(KEY2, plain2, ENC); 
    dbg_print("Test2: ", plain2);
    Camellia256(KEY3, plain3, ENC); 
    dbg_print("Test3: ", plain3);
    Camellia256(KEY4, plain4, ENC); 
    dbg_print("Test4: ", plain4);
    Camellia256(KEY5, plain5, ENC); 
    dbg_print("Test5: ", plain5);
    
    return 0;
}

