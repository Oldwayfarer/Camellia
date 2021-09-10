#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "Camellia.h"
#include "GOST_Streebog.h"

typedef struct{
    char name[256];
    uint64_t size;
}file_t;

void Encryption(uint64_t* KEY, uint64_t* IV, char** files, uint32_t num){
    struct timespec t;
    struct stat st;
    uint8_t* ptr, tmp;
    char arch_name[20];
    file_t sfiles[num];
    int fd, size;
    FILE* afd;
    
    clock_gettime(CLOCK_REALTIME, &t);
    
    snprintf(arch_name, 20, "arch_%08x.enc", t.tv_nsec);
    if((afd = fopen(arch_name, "wb")) == NULL ){
        printf("Can not create arch\n");
        exit(-1);
    }
    
    fwrite((uint8_t*)IV, 1, 32, afd);
    fwrite((uint8_t*)&num, 1, 4, afd);
    for(int i=0; i<num; i++){
        if((fd = open(files[i], O_RDWR)) == -1){
            printf("Can not open file %s\n", files[i]);
            sfiles[i].size = 0;
            continue;
        }
        strncpy(sfiles[i].name, files[i], 255);
        fstat(fd, &st);
        sfiles[i].size = st.st_size;
        close(fd);
    }
    fwrite(sfiles,sizeof(file_t), num, afd);
    for(int i=0; i<num; i++){
        if(!sfiles[i].size) continue;
        if((fd = open(sfiles[i].name, O_RDWR)) <= 0){
            printf("can not open file %s\n", sfiles[i].name);
            sfiles[i].size = 0;
            continue;
        }
        size = sfiles[i].size + (sfiles[i].size%16? 16-sfiles[i].size%16: 0);
        ptr = (uint8_t*)mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
        if(ptr <= 0){
            printf("OOPs\n");
            exit(-1);
        }
        if((tmp=sfiles[i].size%16) !=0){
            for(int j=size-1; j>=sfiles[i].size ; ptr[j--] = tmp);
        }
        OFB(ptr, size, KEY, IV, ENC, Camellia256);
        fwrite(ptr, 1, size, afd);
        munmap(ptr, size);
        close(fd);
    }
    fclose(afd);
}

void Decryption(uint64_t* KEY, char* aname){
    FILE *fd, *afd = fopen(aname, "rb");
    if(afd == NULL){
        printf("Can not open %s\n", aname);
        exit(-1);
    }
    uint8_t *ptr;
    uint64_t IV[4];
    uint32_t num, size;
    fread((uint8_t*)IV, 1, 32, afd);
    fread((uint8_t*)&num, 1, 4, afd);
    file_t sfiles[num];
    fread(sfiles, sizeof(file_t), num, afd);
    for(int i=0; i<num; i++){
        if(sfiles[i].size == 0) continue;
        fd = fopen(sfiles[i].name, "wb");
        if(fd == NULL){
            printf("Can not create file %s\n", sfiles[i].name);
            continue;
        }
        size = sfiles[i].size + ((sfiles[i].size%16)? (16-sfiles[i].size%16): 0);
        ptr = (uint8_t*)malloc(size);
        fread(ptr, 1, size, afd);
        OFB(ptr, size, KEY, IV, ENC, Camellia256);
        fwrite(ptr, 1, sfiles[i].size, fd);
        fclose(fd);
    }
}
int gen_IV(uint64_t** IV){
    if((*IV = (uint64_t*)malloc(sizeof(uint64_t)*4))== NULL){
        printf("Malloc error\n");
        return -1;
    }
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd == -1){
        printf("Can not open /dev/urandom\n");
        return -1;
    }
    if(read(fd, (uint8_t*)*IV, 32) != 32){
        printf("Can not gen IV\n");
        return -1;
    }
    close(fd);
    return 0;
}

int get_KEY(uint64_t** Key, char* password){
    if((*Key = (uint64_t*)calloc(4, sizeof(uint64_t)))==NULL){
        printf("Malloc error\n");
        return -1;
    }
    uint8_t* hash = Streebog((uint8_t*)password, strlen(password), M256);
    for(int i=0; i<4; i++){
        for(int j=0; j<8; j++)
            (*Key)[i] = ((*Key)[i]<<8)|hash[i*8 +j];
    }
    return 0;
}

int main(int argc, char** argv){
    if(argc <= 3){
        printf("Usage:\n$%s, mode password file_name {file_name}\n", argv[0]);
        printf("\tmode - E(for encryption)\\D(for decryption)\n");
        printf("\tpassword - password\n");
        printf("\tfile_name- archive name in D-mode\\ file name in E-mode\n");
        exit(-1);
    }
    uint64_t* Key;
    if(get_KEY(&Key, argv[2]) == -1) exit(-1);
    if(!strcmp(argv[1], "E")){
        uint64_t* IV;
        if(gen_IV(&IV)) exit(-1);
        Encryption(Key, IV, &argv[3], argc-3);    
    }else if(!strcmp(argv[1], "D")){
        Decryption(Key, argv[3]);
    }else{
        printf("Unknown mode %s", argv[1]);
    }
    return 0;
}

