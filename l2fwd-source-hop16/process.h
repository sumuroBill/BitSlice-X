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
#include <pthread.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

 

/*Please set the following parameters according to the actual situation of your POT scenario */
#define N 10           /* path length */ //1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
#define G 16          /* Group size */ //1,2,4,8,16,32
#define current_node 0 //Mark the current number of nodes.

extern uint8_t pktseq;
extern uint64_t global_groupID; 
extern int packetCount;                
extern int packet_number[RTE_MAX_ETHPORTS];
int max_global_groupID = 600 / G - 1;

unsigned long long tag_1;
unsigned long long tag_2;
double tag_con_1 = 0;
double tag_con_2 = 0;
double tag_con_3 = 0;
double tag_con_4 = 0; 
double tag_con_5 = 0;
double tag_con_6 = 0;
double tag_con_7 = 0;
double tag_begin = 0;
double tag_end = 0; 

double tag_accumulate = 0;

// #define datalength 1000 //500,1000
#define datalength 500 //500,1000
#define keylength 16 //
#define dhlength 32  //datahash
#define FALSE_PACKAGE -16
#define CBCMAC_len 512           /* CBC MAC length */ //128, 256
#define proof_frag_len 32 /* proof fragment length*/



uint8_t payload[datalength] = {
        0x7a, 0xb5, 0x60, 0x4c, 0xb9, 0xa6, 0x53, 0xf7, 0x71, 0xa8, 0xe2, 0x14, 0x02, 0xba, 0xf4, 0x03, 0x80, 0x9d, 0x96, 0xba, 0xe7, 0x75, 0x78, 0xf0, 0x5a, 0x68, 0xab, 0x54, 0xa0, 0xd5, 0xdd, 0x82, 0x9b, 0xb2, 0x7d, 0x4a, 0xcd, 0x17, 0x01, 0x4d, 0xfb, 0xcd, 0x37, 0x8f, 0xa4, 0x84, 0x80, 0x59, 0x4f, 0x24, 0x24, 0x4a, 0x0a, 0x8a, 0x9e, 0xb7, 0x9d, 0xb9, 0x4b, 0x3b, 0x96, 0xe9, 0x12, 0x0d, 0x4a, 0xa6, 0x3f, 0x1b, 0x4b, 0x40, 0x88, 0x32, 0x95, 0xa6, 0xd4, 0x7d, 0xe7, 0x7e, 0x86, 0x0e, 0x3e, 0x77, 0xc2, 0xac, 0x94, 0x8a, 0x66, 0xeb, 0x73, 0x46, 0xcb, 0x85, 0xbd, 0xae, 0xa1, 0xc2, 0x5b, 0x67, 0x9f, 0xf5
};
// uint8_t payload[datalength] = {0x7a, 0xb5, 0x60, 0x4c, 0xb9, 0xa6, 0x53};
uint8_t target_buffer[1024] = {0};  
uint8_t proof_target_buffer[32] = {0}; 
uint32_t CBC_mac_value_H1[4] = {0};
uint8_t CBC_mac_value_H1_tmp[16] = {0};
uint32_t CBC_mac_value_H2[4] = {0};
uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x09,0xcf,0x4f,0x3c,0xe9,0x2e,0x7e,0x11,0x2e,0x40,0x9b,0x96};
uint8_t fragment_size = proof_frag_len/G;
int POT_byte_length = (fragment_size*N + 7) / 8;

uint32_t tmp_POT_frag[N][CBCMAC_len/proof_frag_len] = {0};
uint32_t hop_POT[N] = {0};
uint32_t tmp_TS = 0;

CMAC_CTX *ctx2 = CMAC_CTX_new();
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

using namespace std;


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
//   printf("in: ");
//   for (int i = 0; i < sizeof(in); i++) {
//     printf("%02X ", in[i]);
//   }
//   printf("\n");
  size_t outlen;
//   CMAC_CTX *ctx2 = CMAC_CTX_new();
  CMAC_Init(ctx2, key, length, EVP_aes_128_cbc(), NULL);
  CMAC_Update(ctx2, in, sizeof(in));
  CMAC_Final(ctx2, out, &outlen);
//   CMAC_CTX_free(ctx2);
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
    // uint8_t POT[N][(4 + G - 1) / G]; 
    uint32_t POT[N];
};

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

void calculate_pkt_ID(void *arg) {
    DataPackage *in = (DataPackage *)arg;

    DataPacket Mypacket;
    Mypacket.fld_1 = rte_cpu_to_be_32(0xAC113C99);
    Mypacket.fld_2 = rte_cpu_to_be_32(0xAC113C98);
    Mypacket.fld_3 = (in -> PVhd.group_ID);
    Mypacket.fld_4 = (uint8_t)G;
    Mypacket.fld_5 = (in -> PVhd.pkt_seq);
    Mypacket.fld_6 = (in -> PVhd.timestamp);
    // printf("pktID group_ID = %d\n", (in -> PVhd.group_ID));
    // printf("pktID pkt_seq = %d\n", (in -> PVhd.pkt_seq));
    // printf("pktID uint32_t tmp_TS: %u\n", (in -> PVhd.timestamp)); 
    memcpy(Mypacket.fld_7, payload, sizeof(payload));
    
    memcpy(target_buffer, &Mypacket, sizeof(DataPacket));

    // printf("target_buffer: ");
    // for (int i = 0; i < sizeof(target_buffer); i++) {
    //     printf("%02X ", target_buffer[i]);
    // }
    // printf("\n");
    
    unsigned char mac_value[16] = {0};
    size_t mac_len = 0;

    calculate_CMAC(key, keylength, target_buffer, mac_value);
    // printf("mac_value (16 bytes): ");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", mac_value[i]);  // %02X 
    // }
    // printf("\n");
    memcpy(in->PVhd.pkt_ID, mac_value, sizeof(mac_value));
    // printf("second in->PVhd.pkt_ID (16 bytes): ");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", in->PVhd.pkt_ID[i]);  // %02X 
    // }
    // printf("calculate_pkt_ID done\n");
    // return NULL;
}

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

/* Calculate POT, write it to tmp_POT_frag */
void calculatePOTAndStorePOT(void *arg) {
    DataPackage *in = (DataPackage *)arg;

    //calculatePOT
    if((in -> PVhd.pkt_seq) == 0){
        ProofData Myproof;
        Myproof.fld_1 = 0;
        Myproof.fld_2 = 0;
        Myproof.fld_3 = 0;
        Myproof.fld_4 = rte_cpu_to_be_32(0xAC113C99);
        Myproof.fld_5 = rte_cpu_to_be_32(0xAC113C98);
        Myproof.fld_6 = 23 + POT_byte_length;
        Myproof.fld_7 = in->PVhd.group_ID;
        Myproof.fld_8 = (uint8_t)G;
        Myproof.fld_9 = fragment_size;
        Myproof.fld_0 = tmp_TS;
        Myproof.append = 0;
        memcpy(proof_target_buffer, &Myproof, sizeof(ProofData));

        for (int i = 0; i < N; i++) {
            size_t mac_len = 0;
            calculate_CBCMAC(key, keylength, proof_target_buffer, sizeof(proof_target_buffer), CBC_mac_value_H1, &mac_len);
            for (int j = 0; j < 4; j++) {
                tmp_POT_frag[i][j] = CBC_mac_value_H1[j];
                // printf("tmp_POT_frag[ %d ][ %d ]: \n", i, j);
            }
            if(N >= 5 && (N - i) > 4){
                
                memcpy(CBC_mac_value_H1_tmp, CBC_mac_value_H1, 16);
                for(int k = 0; k<((N - i + 3) / 4)-1; k++){

                    calculate_CBCMAC(key, keylength, CBC_mac_value_H1_tmp, sizeof(CBC_mac_value_H1_tmp), CBC_mac_value_H2, &mac_len);
                    for (int j = 4*(k+1); j < 4*(k+2); j++) {
                        tmp_POT_frag[i][j] = CBC_mac_value_H2[j-4*(k+1)];
                        // printf("tmp_POT_frag[ %d ][ %d ]: \n", i, j);
                    }
                    memcpy(CBC_mac_value_H1_tmp, CBC_mac_value_H2, 16);
                }
            }
            
       
        }

        for (int i = 0; i < N; i++) {
            if (i == 0) {
                hop_POT[i] = tmp_POT_frag[i][0];
            } else {
                hop_POT[i] = tmp_POT_frag[0][i];
                int tmp_i = i;
                for (int j = 0; j < i; j++) {
                    hop_POT[i] = hop_POT[i] ^ tmp_POT_frag[j + 1][tmp_i - 1];
                    tmp_i = tmp_i - 1;
                }
            }
            // printf("hop_POT[ %d ]: ", i);
            // print_binary_32(hop_POT[i]);
        }
    }

    //store_POT
    // tag_1 = rdtsc();
    int index_hop_POT_1 = (in -> PVhd.pkt_seq) * fragment_size;
    for(int i=0; i<N; i++){
        in -> PVhd.POT[i] = (hop_POT[i] >> index_hop_POT_1) & ((1 << fragment_size) - 1);
        // printf("in -> PVhd.POT[ %d ]: ", i);
        // print_binary_32(in -> PVhd.POT[i]);
    }
    // tag_2 = rdtsc();
    // tag_con_2 = (double)(tag_2 - tag_1) / 2.7;
    // printf("store_POT = %f ns\n", tag_con_2);

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

   void generateConstruction(DataPackage *in){

        tag_1 = rdtsc();
        in -> PVhd.hd_length = 23 + POT_byte_length;

        /* assigns and updates the group ID of the next packet */
        in -> PVhd.group_ID = global_groupID;
        packetCount++;
        if (packetCount >= G) {
            packetCount = 0;
            global_groupID++;
        }

        /* set group_size */
        in -> PVhd.group_size = G;

        /* set and update pktSeq  */
        in -> PVhd.pkt_seq = pktseq;
        pktseq = (pktseq + 1) % G;
    
        /* set pot_length */
        in -> PVhd.pot_length = fragment_size;

		/* set flag */
        in -> PVhd.flag = 0;

        /* set timestamp */
        if((in -> PVhd.pkt_seq) == 0){
            uint64_t tsc = rte_get_tsc_cycles();
            tmp_TS = (uint32_t)(tsc & 0xFFFFFFFF);
        }
        in -> PVhd.timestamp = tmp_TS;





     
    
        calculate_pkt_ID(in);
        calculatePOTAndStorePOT(in);
    
        // tag_2 = rdtsc();
        // tag_con_2 += (double)(tag_2 - tag_1) / 2.7;
        // if((in -> PVhd.group_ID) == (500/G-1)){
        //     printf("calculate_pkt_ID = %f μs\n", tag_con_2 / 500000);
        // }


        // printf("group_ID = %d, pkt_seq = %d \n", (in -> PVhd.group_ID), (in -> PVhd.pkt_seq));

    }
 
};
