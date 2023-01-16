// for testing unexpected stuff
#include "playground.h"
int main()
{
    struct pcap_frame timeline_list;
    struct pcap_convo_list convo;
    pcap_to_lists(&timeline_list,&convo,"pcaps/bigger_pcap.pcap");
    //TODO free
    return 0;
}