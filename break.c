#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include <openssl/rc4.h>

typedef unsigned char u8;

char err[PCAP_ERRBUF_SIZE];

// Function to print hexadecimal representation of buffer
static void PrintHex(char *s, u8 *buf, int len){
    printf("%s", s);
    for (int i = 0; i < len; ++i)
        printf("%02x ", buf[i]);
    printf("\n");
}

int main(int argc, char **argv){
    // Open the pcap file in offline mode
    pcap_t *pcap = pcap_open_offline("wep.pcap", err);

    // Initialize variables to store packet information
    struct pcap_pkthdr header;
    const u8 *packet;
    
    // The following lines have been commented out, as they are not needed.
    //packet = pcap_next(pcap, &header);
    //PrintHex("Message 1: ", packet, 20);
    //packet = pcap_next(pcap, &header);
    //PrintHex("Message 2: ", packet, 20);
     

    // Loop over incoming packets until a data package is found
    while ((packet = pcap_next(pcap, &header)) != NULL) {
        // Check if the packet is a data package
        if (packet[0] == 0x08) {
            break;  // Exit the loop once the first data package is found
        }
    }

    // Copy the IV and the first 4 bytes of the data to local variables
    u8 IV[3] ,Data[4];
    memcpy(IV, packet+24, 3);
    memcpy(Data, packet+28, 4);

    // Search all the possible keys whose bytes are in the range 0x20..0x7f
    u8 secretKey[8];
    
    //Find second Data package
    while ((packet = pcap_next(pcap, &header)) != NULL) {
        // Check if the packet is a data package
        if (packet[0] == 0x08) {  
            break;  // Exit the loop once the first data package is found
        }
    }
    u8 IV2[3] ,Data2[4];
    memcpy(IV2, packet+24, 3);
    memcpy(Data2, packet+28, 4);

    // Iterate over all possible keys
    for(secretKey[3]=0x20; secretKey[3]<= 0x7f; ++secretKey[3]){
        for(secretKey[4]=0x20; secretKey[4]<= 0x7f; ++secretKey[4]){
            for(secretKey[5]=0x20; secretKey[5]<= 0x7f; ++secretKey[5]){
                for(secretKey[6]=0x20; secretKey[6]<= 0x7f; ++secretKey[6]){
                    for(secretKey[7]=0x20; secretKey[7]<= 0x7f; ++secretKey[7]){
                        
                        //setting the IV to the secretKey
                        secretKey[0] =  IV[0];  
                        secretKey[1] =  IV[1]; 
                        secretKey[2] =  IV[2];     

                        RC4_KEY key;
                        RC4_set_key(&key, 8, secretKey); 
                        //where secretKey is an 8-byte key composed of the IV and K

                        u8 p[4];
                        RC4(&key, 4, Data, p);
                        //where Data is a pointer to the first 4 bytes of the packet's data
               
                          
                        //If after decryption you get the correct 4 bytes,
                        if(p[0]==  0xaa && p[1]== 0xaa && p[2]== 0x03 && p[3]== 0x00) {
                            printf("\nkey found 1 !\n");  
                            PrintHex("p1 :", p, 4);
                            printf("\n\n");

                            secretKey[0] =  IV2[0];  
                            secretKey[1] =  IV2[1]; 
                            secretKey[2] =  IV2[2]; 
                            
                            RC4_KEY key2;
                            RC4_set_key(&key2, 8, secretKey); 
                            //where secretKey2 is an 8-byte key composed of the IV and K

                            u8 p2[4];
                            RC4(&key2, 4, Data2, p2);
                            //where Data2 is a pointer to the first 4 bytes of the packet's data
                               
                            PrintHex("p2 :", p2, 4);

                            //try if K given the correct bytes on the second data packet.
                            //If so, print K.                             
                            if(p2[0]== 0xaa && p2[1]== 0xaa && p2[2]== 0x03 && p2[3]== 0x00) {
                                printf("key found 2 !\n");
                                PrintHex("output2 :", p2, 4);
                                printf("\n\n");

                                //Print Key and exit .
                                printf("KEY: %02x-%02x-%02x-%02x-%02x \n", secretKey[3],secretKey[4],secretKey[5],secretKey[6],secretKey[7]);
                            }
                        }                       
                    } 
                }
            }   
        }
    } 
}