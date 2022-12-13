#include <stdio.h>
#include <malloc.h>
#include <string.h>
struct pcap_convo_list
{
    struct pcap_frame *pcap_frame;
    struct pcap_convo_list *next;
};
struct pcap_frame
{
    unsigned int id;
    unsigned int seconds;
    unsigned int microseconds;
    unsigned int captured_length;
    unsigned int original_length;
    unsigned char* packet;
    struct pcap_frame* next_timeline; // a pointer to the next packet as in arrival order
    struct pcap_frame* next_convo; // a pointer to the next packet as in conversation order
};
struct ethdr
{ //
    unsigned char h_dest[6];
    unsigned char h_source[6];
    unsigned short h_proto;
} __attribute__((packed));
struct iphr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl : 4;
    unsigned int version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN // order is crucial so when printed it wont print opposite values for version and ihl.
    unsigned int version : 4;
    unsigned int ihl : 4;
#endif
    unsigned int TypeOfService : 8;
    unsigned int TotalLength : 16; // Total length of the datagram.
    unsigned int Identification : 16;
    unsigned int Flags : 3;
    unsigned int FragmentOffset : 13;
    unsigned int Ttl : 8;
    unsigned int Protocol : 8;
    unsigned int HeaderChecksum : 16;
    unsigned int SourceAddr;
    unsigned int DestAddr;
} __attribute__((packed));
struct udpheader
{
    unsigned int SourcePort : 16;
    unsigned int DestinationPort : 16;
    unsigned int Length : 16;
    unsigned int Checksum : 16;
} __attribute__((packed));
struct tcpheader
{
    unsigned short int SourcePort;
    unsigned short int DestinationPort;
    unsigned int SequenceNumber;
    unsigned int AckNumber;
    unsigned int DataOffset : 4;
    unsigned int Reserved : 6;
    unsigned int Urg : 1;
    unsigned int Ack : 1;
    unsigned int Psh : 1;
    unsigned int Rst : 1;
    unsigned int Syn : 1;
    unsigned int Fin : 1;
    short int Window;
    short int Checksum;
    short int UrgentPointer;
} __attribute__((packed)); // compresses the information to save memory.x
// fills a char buffer with the file's contents, and returns the file length
char *read_file(const char *filename, long *len)
{
    FILE *fileptr;
    long filelen;
    char *buffer;

    fileptr = fopen(filename, "rb"); // Open the file in binary mode
    fseek(fileptr, 0, SEEK_END);     // Jump to the end of the file
    filelen = ftell(fileptr);        // Get the current byte offset in the file
    rewind(fileptr);                 // Jump back to the beginning of the file
    *len = filelen;
    buffer = (char *)malloc(filelen * sizeof(char)); // Enough memory for the file
    fread(buffer, filelen, 1, fileptr);              // Read in the entire file
    fclose(fileptr);                                 // Close the file
    printf("file len is %d\n", filelen);
    return buffer;
}
void printingPackets(unsigned char *buffer)
{
    struct ethdr *eth = (struct ethhdr *)(buffer);
    if (ntohs(eth->h_proto) == 2048)
    {
        printf("Ethernet Header \n"); // printing mac addresses in hexa
        printf("Source As : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        printf("Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        printf("Protocol : %x \n", htons(eth->h_proto)); // converting byte order to match protocol 0x0800
        printf("\n");
        struct iphr *iph = (struct iphr *)(buffer  + sizeof(struct ethdr));
        printf("IP header\n");
        printf("\t\t\t |- Version : %d\n", iph->version);
        printf("\t\t\t |- Inter Header Length : %d DWORDS or %d BYTES\n", (unsigned int)iph->ihl, (unsigned int)iph->ihl * 4);
        printf("\t\t\t |- Type Of Service : %d\n", (unsigned char)iph->TypeOfService);          // Also can be called Qos(Quality Of Service)
        printf("\t\t\t |- Total Length : %d Bytes\n", (unsigned short)ntohs(iph->TotalLength)); // Length of the datagram
        printf("\t\t\t |- Identification : %d\n", (unsigned short)ntohs(iph->Identification));         // Identification of the packet
        printf("\t\t\t |- Time To Live : %d\n", (unsigned char)iph->Ttl);                       // Indicated the maximum time a data is allowed to be on the network.
        printf("\t\t\t |- Protocol : %d\n", (unsigned char)iph->Protocol);                      // Protocol of the packet
        printf("\t\t\t |- Header Checksum : %x\n", (unsigned short)ntohs(iph->HeaderChecksum));
        if (iph->Protocol == 6)
        {
            struct tcpheader *tcph = (struct tcpheader *)(buffer + (4*iph->ihl)+sizeof(struct ethdr));
            printf("\nTcp Header\n");
            printf("\t\t\t |- Source Port\t : %u\n", (unsigned short)htons(tcph->SourcePort));
            printf("\t\t\t |- Destination Port\t : %u\n", (unsigned short)htons(tcph->DestinationPort));
            printf("\t\t\t |- Sequence Number\t : %u\n", (unsigned int)ntohs(tcph->SequenceNumber));
            printf("\t\t\t |- Acknowledge Number\t : %u\n", (unsigned int)ntohs(tcph->AckNumber));
            printf("\t\t\t |-Header Length : %d DWORDS or %d BYTES\n", (unsigned int)tcph->DataOffset, (unsigned int)tcph->DataOffset * 4);
            printf("\n------------------------------------------------------flags------------------------------------------------------\n");
            printf("\t\t\t\t |-Urgent flag : %d\n", (unsigned int)tcph->Urg); // Printing flags, each flag represent a different purpose and it's 1 bit in size
            printf("\t\t\t\t |-Acknowledgement flag : %d\n", (unsigned int)tcph->Ack);
            printf("\t\t\t\t |-push flag : %d\n", (unsigned int)tcph->Psh);
            printf("\t\t\t\t |-Reset flag : %d\n", (unsigned int)tcph->Rst);
            printf("\t\t\t\t |-Synchronise flag : %d\n", (unsigned int)tcph->Syn);
            printf("\t\t\t\t |-Finish flag : %d\n", (unsigned int)tcph->Fin);
            printf("\t\t\t |-Window size  :%d\n", (unsigned short)ntohs(tcph->Window));
            printf("\t\t\t |- checksum  :%x\n", (unsigned short)ntohs(tcph->Checksum));
            printf("\t\t\t |- Urgent pointer  :%d\n", (unsigned short)ntohs(tcph->UrgentPointer));
            char *remain;
            remain = buffer + sizeof(struct ethdr) + iph->ihl * 4 + tcph->DataOffset * 4;
            while (*remain)
            {
                printf("%.2x\t", (unsigned)*remain);
                remain++;
            }
        }
        /* if protocol is UDP */
        if (iph->Protocol == 17)
        {
            struct udpheader *udph = (struct udpheader *)buffer + (4 * sizeof(int));
            printf("\nUdp Header\n");
            printf("\t\t\t |- Source Port\t : %d\n", (unsigned short)ntohs(udph->SourcePort));
            printf("\t\t\t |- Destination Port\t : %d\n", (unsigned short)ntohs(udph->DestinationPort));
            printf("\t\t\t |- Total Length : %d Bytes\n", (unsigned short)ntohs(udph->Length)); // Length of the datagram
            printf("\t\t\t |- Checksum : %d\n", (unsigned short)ntohs(udph->Checksum));
            char *remain;
            remain = buffer + (4 * sizeof(int)) + sizeof(eth) + iph->ihl * 4 + sizeof(udph);
            while (*remain)
            {
                printf("%.2x\t", (unsigned)*remain);
                remain++;
            }
        }
    }
}
// get the packets from the pcap file, also printing it's contents.
// int* size - fill with the pcap file's length - not including the header
// int* snaplen - fill with the snap length specified in the pcap file header.
// return the pcap file's contents
char *get_buffer(int *size)
{
    int i;
    char *buffer;
    FILE *fileptr;
    long filelen;

    // file header
    unsigned int magic_number;
    unsigned short maj_value;
    unsigned short min_value;
    unsigned int snap_len;
    unsigned int link_type;

    buffer = read_file("check.pcap", &filelen);
    // header
    magic_number = *((unsigned int *)buffer);
    maj_value = *((unsigned short *)buffer + 2);
    min_value = *((unsigned short *)buffer + 3);
    snap_len = *((unsigned int *)buffer + 4);
    link_type = *((unsigned int *)buffer + 5);
    printf(\
        "----------------------------------------------------------------header----------------------------------------------------------------\n"\
        "magic number is %x\n"\
        "major value is %x\n"\
        "minor value is %x\n"\
        "snap length is %x\n"\
        "link type is %x\n\n",\
        magic_number, maj_value, min_value, snap_len, link_type);

    buffer += 6 * sizeof(int);
    *size = (filelen - (6 * sizeof(int))); // the buffer length minus the file header
    //printingPackets(buffer + 4*sizeof(int));
    return buffer;
}