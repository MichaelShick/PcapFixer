// a basic implementation of a single pcap packet data, a more basic version of what is seen in wireshark
struct pcap_data
{
    unsigned int id;
    unsigned int seconds;
    unsigned int microseconds;
    unsigned int captured_length;
    unsigned int original_length;
    unsigned char *packet;
} __attribute__((packed));
// a strcut which should be used as a double linked list, pointing both to the next packet by order of arrival, and the next packet of the same conversation.
// refer for pcap_convo_list below for better understanding
// struct pcap_frame* next_timeline; // a pointer to the next packet as in arrival order
// struct pcap_frame* next_convo; // a pointer to the next packet as in conversation order
struct pcap_frame
{
    struct pcap_data data; // the data of the packet itself
    struct pcap_frame *next_timeline; // a pointer to the next packet as in arrival order
    struct pcap_frame *next_convo;    // a pointer to the next packet as in conversation order
};
// this one is a bit tricky -
// the intention is to have a list where the pcap_frame field is pointing at an already established node in a list which sorted the packets by their arrival time.
// more than that, each packet convo_list points to should be a start of a network conversation
// to illustrae how this works :
// this is how the timeline list should look like
// packet(1 1)->packet(2 2)->packet(3 1)->packet(4 3)->packet(5 2)->packet(6 1) etc...
// where the first number of each packet is the order of its arrival, and the second is its conversation ID.
// using the timeline_list, i should be able to to traverse the list like this:
// packet(1 1) -> packet(2 2) -> packet(3 1) (simply by the order of arrival)
// or like this
// packet(1 1) -> packet(3 1) -> packet(6 1) (only traverse the conversation itself)
// what convo list should be traversable like this:
// packet(1 1) -> packet(2 2) -> packet(4 3) (only traverse to the first packet of each conversation)
// this allows for easy search of specific conversation, as for example converstaion number 234 could begin after 50000 packets, but in convo list it will be located after 234 nodes.
struct pcap_convo_list
{
    struct pcap_frame *pcap_frame;
    unsigned int count; // how many packets are in this convo
    unsigned int size;  // convo size;
    struct pcap_convo_list *next;
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
} __attribute__((packed));
int check_if_convo(struct pcap_frame *pcap1, struct pcap_frame *pcap2);
// check if the packet is related to the prot
// return 0 if it isn't, 1 if it's the source port and 2 if it's the destination port
int check_if_convo_port(struct pcap_frame *pcap, int port);
int pcap_to_lists(struct pcap_frame *timeline_list, struct pcap_convo_list *convo_list, char *filename);