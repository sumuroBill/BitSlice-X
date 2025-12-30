#include <iostream>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <cstdint>
#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <cstring>
#include <vector>
#include <queue>
#include <map>
#include <chrono>
#include <rte_hash.h>
#include <rte_malloc.h>

using namespace std;

/*Please set the following parameters according to the actual situation of your POT scenario */
#define N 10          /* path length */ //1,2,3,4,5,6,7,8
#define G 16         /* Group size */ //1,2,4,8,16,32
#define current_node 1 //Mark the current number of nodes.

extern uint8_t pktseq;
extern uint64_t global_groupID; // The global variable groupID
extern int packetCount;                // Records the number of packets received
extern int packet_number;
int max_global_groupID = 500 / G - 1;

unsigned long long tag_1;
unsigned long long tag_2;
double tag_con_1 = 0;
double tag_con_2 = 0;
double tag_con_3 = 0;
double tag_con_4 = 0;
double tag_con_5 = 0;
double tag_con_6 = 0;
double tag_con_7 = 0;

// #define datalength 1000 //500,1000
#define datalength 500 //500,1000
#define keylength 16 //Key length
#define dhlength 32  //datahash
#define FALSE_PACKAGE -16
#define CBCMAC_len 512           /* CBC MAC length */ //128或者256
#define proof_frag_len 32 /* proof fragment length*/


// Assume a fixed packet content for test
uint8_t payload[datalength] = {
        0x7a, 0xb5, 0x60, 0x4c, 0xb9, 0xa6, 0x53, 0xf7, 0x71, 0xa8, 0xe2, 0x14, 0x02, 0xba, 0xf4, 0x03, 0x80, 0x9d, 0x96, 0xba, 0xe7, 0x75, 0x78, 0xf0, 0x5a, 0x68, 0xab, 0x54, 0xa0, 0xd5, 0xdd, 0x82, 0x9b, 0xb2, 0x7d, 0x4a, 0xcd, 0x17, 0x01, 0x4d, 0xfb, 0xcd, 0x37, 0x8f, 0xa4, 0x84, 0x80, 0x59, 0x4f, 0x24, 0x24, 0x4a, 0x0a, 0x8a, 0x9e, 0xb7, 0x9d, 0xb9, 0x4b, 0x3b, 0x96, 0xe9, 0x12, 0x0d, 0x4a, 0xa6, 0x3f, 0x1b, 0x4b, 0x40, 0x88, 0x32, 0x95, 0xa6, 0xd4, 0x7d, 0xe7, 0x7e, 0x86, 0x0e, 0x3e, 0x77, 0xc2, 0xac, 0x94, 0x8a, 0x66, 0xeb, 0x73, 0x46, 0xcb, 0x85, 0xbd, 0xae, 0xa1, 0xc2, 0x5b, 0x67, 0x9f, 0xf5
};
// uint8_t payload[datalength] = {0x7a, 0xb5, 0x60, 0x4c, 0xb9, 0xa6, 0x53};
uint8_t target_buffer[1024] = {0};  
uint8_t proof_target_buffer[32] = {0}; 

// Assume a fixed key content for test
uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x09,0xcf,0x4f,0x3c,0xe9,0x2e,0x7e,0x11,0x2e,0x40,0x9b,0x96};
uint8_t fragment_size = proof_frag_len/G;
int POT_byte_length = (fragment_size*N + 7) / 8;

uint32_t tmp_POT_frag[N][16] = {0};
uint32_t hop_POT[N] = {0};
uint32_t tmp_TS = 0;

CMAC_CTX *ctx2 = CMAC_CTX_new();
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// #define MAX_ENTRIES 60
typedef uint32_t the_CBC_mac_value_Hop8[16];
// typedef struct {
//     uint64_t id;
//     the_CBC_mac_value_Hop8 mac_value_Hop8;
// } id_mac_entry;
// id_mac_entry id_mac_table[MAX_ENTRIES];
// int current_size = 0;

uint32_t id_mac_table[400][16] = {0};
uint8_t id_mac_table_tag[400] = {0};

uint8_t CBC_mac_value_Hop4_tmp[16] = {0};
uint32_t CBC_mac_value_Hop4[4] = {0};
uint32_t CBC_mac_value_Hop8[16] = {0};

typedef enum {
    UINT8,
    UINT32,
    UINT64,
    UINT8_ARRAY
} data_type_t;

#pragma pack(push, 1)  
typedef struct {
    uint32_t fld_1; //src_addr
    uint32_t fld_2; //dst_addr
    uint64_t fld_3; //global_groupID
    uint8_t fld_4; //group_size
    uint8_t fld_5; //pktseq
    uint32_t fld_6; //timestamp
    uint8_t fld_7[datalength]; //payload[1000]
} DataPacket;
#pragma pack(pop)

#pragma pack(push, 1) 
typedef struct {
    uint16_t fld_1; //In port
    uint32_t fld_2; //AS ID
    uint16_t fld_3; //Out port
    uint32_t fld_4; //src_addr
    uint32_t fld_5; //dst_addr
    uint8_t fld_6; //header length
    uint64_t fld_7; //global_groupID
    uint8_t fld_8; //group_size
    uint8_t fld_9; //POT length
    uint32_t fld_0; //timestamp
    uint8_t append; //append
} ProofData;
#pragma pack(pop)


struct flowPVHeader
{
    uint8_t hd_length; // 1B
    uint64_t group_ID; // 8B
    uint8_t group_size; // 1B
    uint8_t pkt_seq; // 1B
    uint8_t pot_length; // 1B
    uint32_t timestamp; // 4B
    // uint32_t pkt_ID; // 4B
    unsigned char pkt_ID[16]; // 4B
    uint8_t flag; // 1B 
    uint32_t POT[N];
};

void print_char_array(unsigned char *array, int a){
for(int i=0;i<a;i++){
    printf("%02x ",array[i]);
}
printf("\n");
}

unsigned long long rdtsc() {
unsigned long long a, d;
asm volatile ("mfence");
asm volatile ("rdtsc" : "=a" (a), "=d" (d));
a = (d<<32) | a;
asm volatile ("mfence");
return a;
}


void calculate_CMAC(unsigned char *key, int length, unsigned char *in, unsigned char *out){
  size_t outlen;
  CMAC_Init(ctx2, key, length, EVP_aes_128_cbc(), NULL);
  CMAC_Update(ctx2, in, sizeof(in));
  CMAC_Final(ctx2, out, &outlen);
}


void calculate_CBCMAC(uint8_t *key, int key_len, uint8_t *data, size_t data_len, uint32_t *mac, size_t *mac_len) {
    // EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // if (!ctx) {
    //     fprintf(stderr, "Error initializing EVP_CIPHER_CTX\n");
    //     return;
    // }

    // Initialize the context with AES-128 CBC, no IV (since we're just calculating MAC)
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, NULL);

    // Disable padding (assumes data_len is a multiple of block size)
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    uint8_t buffer[16] = {0};  // Buffer to store final CBC-MAC result
    int out_len = 0;

    // Encrypt 16-byte blocks
    for (size_t i = 0; i < data_len; i += 16) {
        int block_len = (i + 16 <= data_len) ? 16 : (data_len - i);
        EVP_EncryptUpdate(ctx, buffer, &out_len, data + i, block_len);
    }

    // Get the final MAC block (no padding)
    EVP_EncryptFinal_ex(ctx, buffer, &out_len);

    // Copy the final MAC value to the output (16 bytes)
    memcpy(mac, buffer, 16);

    // Set the length of the MAC (16 bytes / sizeof(uint32_t) words)
    *mac_len = 16 / sizeof(uint32_t);

    // Free the context
    // EVP_CIPHER_CTX_free(ctx);
}


class DataPackage
{
public:
 
    int packetloss; //flag of packet loss
   
    struct flowPVHeader PVhd;
    
    DataPackage()
    {
        Initial();

    }
    ~DataPackage()
    {
        
    }
    void Initial()
    {
      
        packetloss = 0;
  
    }
    
};

void print_binary_8(uint8_t byte) {
    // Cycle 8 times, print one binary bit at a time
    for (int i = 7; i >= 0; i--) {
        // Press the bit to the right and press the i bit and press the 1 bit to extract the binary bit
        printf("%d", (byte >> i) & 1);
    }
    printf("\n");
}
void print_binary_32(uint32_t data) {
    // Cycle 32 times, printing one binary bit at a time
    for (int i = 31; i >= 0; i--) {
        // Press the bit to the right and press the i bit and press the 1 bit to extract the binary bit
        printf("%d", (data >> i) & 1);
    }
    printf("\n");
}

void calculate_pkt_ID(void *arg) {
    DataPackage *in = (DataPackage *)arg;

    DataPacket Mypacket;   
    Mypacket.fld_1 = rte_cpu_to_be_32(0xAC113C99);
    Mypacket.fld_2 = rte_cpu_to_be_32(0xAC113C98);
    Mypacket.fld_3 = (in -> PVhd.group_ID);
    Mypacket.fld_4 = (uint8_t)G;
    Mypacket.fld_5 = (in -> PVhd.pkt_seq);
    Mypacket.fld_6 = (in -> PVhd.timestamp);
    
    memcpy(Mypacket.fld_7, payload, sizeof(payload));
    memcpy(target_buffer, &Mypacket, sizeof(DataPacket));

    unsigned char mac_value[16] = {0};
    size_t mac_len = 0;
    calculate_CMAC(key, keylength, target_buffer, mac_value);

    if(memcmp(mac_value, in->PVhd.pkt_ID, 16) != 0){
        printf("!!!!!!!! pktID error, group_ID = %d, pkt_seq = %d \n", (in -> PVhd.group_ID), (in -> PVhd.pkt_seq));
    }
}

void calculate_and_update_POT(void *arg) {
    DataPackage *in = (DataPackage *)arg;

    // int find_tag = 0;
    // for (int i = 0; i < current_size; i++) {
    //     if (id_mac_table[i].id == (in -> PVhd.group_ID)) {
    //         memcpy(CBC_mac_value_Hop8, id_mac_table[i].mac_value_Hop8, sizeof(the_CBC_mac_value_Hop8));
    //         find_tag = 1;
    //     }
    // }
   
    if(id_mac_table_tag[(in -> PVhd.group_ID)] == 1){
        memcpy(CBC_mac_value_Hop8, id_mac_table[(in -> PVhd.group_ID)], sizeof(the_CBC_mac_value_Hop8));
        // printf("get\n");
    }
    else{
        ProofData Myproof;
        Myproof.fld_1 = 0;
        Myproof.fld_2 = 0;
        Myproof.fld_3 = 0;
        Myproof.fld_4 = rte_cpu_to_be_32(0xAC113C99);
        Myproof.fld_5 = rte_cpu_to_be_32(0xAC113C98);
        Myproof.fld_6 = 23 + POT_byte_length;
        Myproof.fld_7 = (in -> PVhd.group_ID);
        Myproof.fld_8 = (uint8_t)G;
        Myproof.fld_9 = fragment_size;
        Myproof.fld_0 = (in -> PVhd.timestamp);
        Myproof.append = 0;
        memcpy(proof_target_buffer, &Myproof, sizeof(ProofData));
        size_t mac_len = 0;
        
        calculate_CBCMAC(key, keylength, proof_target_buffer, sizeof(proof_target_buffer), CBC_mac_value_Hop4, &mac_len);
        memcpy(&CBC_mac_value_Hop8[0], CBC_mac_value_Hop4, sizeof(uint32_t) * 4);

        if(N >= 5 && (N - current_node) >= 4){
            memcpy(CBC_mac_value_Hop4_tmp, CBC_mac_value_Hop4, 16);
            for(int k=0;k<(N - current_node + 3) / 4; k++){
                calculate_CBCMAC(key, keylength, CBC_mac_value_Hop4_tmp, sizeof(CBC_mac_value_Hop4_tmp), CBC_mac_value_Hop4, &mac_len);
                memcpy(&CBC_mac_value_Hop8[4*(k+1)], CBC_mac_value_Hop4, sizeof(uint32_t) * 4);
                memcpy(CBC_mac_value_Hop4_tmp, CBC_mac_value_Hop4, 16);
            }
      
        }

        memcpy(&id_mac_table[(in -> PVhd.group_ID)], CBC_mac_value_Hop8, sizeof(the_CBC_mac_value_Hop8));
        id_mac_table_tag[(in -> PVhd.group_ID)] = 1;
        // printf("calculate\n");
    
    }
  
    // if(find_tag != 1){
    //     ProofData Myproof;
    //     Myproof.fld_1 = 0;
    //     Myproof.fld_2 = 0;
    //     Myproof.fld_3 = 0;
    //     Myproof.fld_4 = rte_cpu_to_be_32(0xAC113C99);
    //     Myproof.fld_5 = rte_cpu_to_be_32(0xAC113C98);
    //     Myproof.fld_6 = 23 + POT_byte_length;
    //     Myproof.fld_7 = (in -> PVhd.group_ID);
    //     Myproof.fld_8 = (uint8_t)G;
    //     Myproof.fld_9 = fragment_size;
    //     Myproof.fld_0 = (in -> PVhd.timestamp);
    //     Myproof.append = 0;
    //     memcpy(proof_target_buffer, &Myproof, sizeof(ProofData));
    //     size_t mac_len = 0;
        
    //     calculate_CBCMAC(key, keylength, proof_target_buffer, sizeof(proof_target_buffer), CBC_mac_value_Hop4, &mac_len);
    //     memcpy(&CBC_mac_value_Hop8[0], CBC_mac_value_Hop4, sizeof(uint32_t) * 4);

    //     if(N >= 5 && (N - current_node) >= 4){
    //         memcpy(CBC_mac_value_Hop4_tmp, CBC_mac_value_Hop4, 16);
    //         calculate_CBCMAC(key, keylength, CBC_mac_value_Hop4_tmp, sizeof(CBC_mac_value_Hop4_tmp), CBC_mac_value_Hop4, &mac_len);
    //         memcpy(&CBC_mac_value_Hop8[4], CBC_mac_value_Hop4, sizeof(uint32_t) * 4);
    //     }

    //     // for(int i = 0; i < 4; i++){
    //     //     printf("CBC_mac_value_Hop8[ %d ]: ", i);
    //     //     print_binary_32(CBC_mac_value_Hop8[i]);
    //     // }

    //     if (current_size >= MAX_ENTRIES){
    //         current_size = 0;
    //     }
    //     id_mac_table[current_size].id = (in -> PVhd.group_ID);
    //     memcpy(id_mac_table[current_size].mac_value_Hop8, CBC_mac_value_Hop8, sizeof(the_CBC_mac_value_Hop8));
    //     current_size++;
    // }
   
    /* Validate the POT shards of the current node of the packet */
    int index_hop_POT_1 = (in -> PVhd.pkt_seq) * fragment_size;
    uint32_t fragment = (CBC_mac_value_Hop8[0] >> index_hop_POT_1) & ((1 << fragment_size) - 1);
    if ((in -> PVhd.POT[current_node - 1]) != fragment){
        printf("!!!!!!!! POT error, group_ID = %d, pkt_seq = %d \n", (in -> PVhd.group_ID), (in -> PVhd.pkt_seq));
    }

    /* Update the POT shards of subsequent nodes */
    int mac_value_index = 1;
    for(int i = current_node; i<N; i++){
        fragment = (CBC_mac_value_Hop8[mac_value_index] >> index_hop_POT_1) & ((1 << fragment_size) - 1);
        in -> PVhd.POT[i] = (in -> PVhd.POT[i]) ^ fragment;
        mac_value_index++;
    }

}

/* verify before sign! */
class Signer
{
private:
    
public:
    int id;
    
    Signer(int portid)
    {
        id = portid;
    }
     
    void generateUpdate(DataPackage *in, int portid){

        // printf("hd_length = %d \n", (in -> PVhd.hd_length));
        // printf("group_size = %d \n", (in -> PVhd.group_size));
        // printf("pot_length = %d \n", (in -> PVhd.pot_length));
        // printf("group_size = %d \n", (in -> PVhd.group_size));
        // printf("flag = %d \n", (in -> PVhd.flag));
        // printf("packet_number = %d \n", packet_number);
        // printf("group_ID = %d, pkt_seq = %d \n", (in -> PVhd.group_ID), (in -> PVhd.pkt_seq));
        

        /* If it is a destination node, verify the pktID */
        tag_1 = rdtsc();
        if(current_node == N){
            calculate_pkt_ID(in);
        }

        /* When this set of packets is first seen, the proof is extracted or calculated */

        calculate_and_update_POT(in);
      
        // tag_2 = rdtsc();
        // tag_con_1 += (double)(tag_2 - tag_1) / 2.7;

        // if(packet_number == 500){
        //     printf("tag_con_1 = %f ns\n", tag_con_1 / packet_number);
        //     // printf("tag_con_2 = %f ns\n", tag_con_2 / packet_number);
        //     // printf("tag_con_3 = %f ns\n", tag_con_3 / packet_number);
        // }
    }

};
