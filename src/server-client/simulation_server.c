#include <stdio.h>
#include <malloc.h>
#include "simulation_server.h"

// the server uses the pcap_editor file to aquire the timeline and convo lists


// serialize a pcap_data struct for sending over the net
// return 0 on success, 1 on failure
int serialize_pcap_data(unsigned char *serialized, struct pcap_data *pd)
{
    // Allocate memory for the serialized data
    serialized = malloc(sizeof(struct pcap_data)+pd->captured_length);
    if (serialized == 0)
    {
        perror("malloc");
        return 1;
    }
    while(pd)
    {
    // Copy the values from the pcap_data struct into the serialized data
    memcpy(serialized, &pd->id, sizeof(unsigned int));
    memcpy(serialized + sizeof(unsigned int), &pd->seconds, sizeof(unsigned int));
    memcpy(serialized + 2 * sizeof(unsigned int), &pd->microseconds, sizeof(unsigned int));
    memcpy(serialized + 3 * sizeof(unsigned int), &pd->captured_length, sizeof(unsigned int));
    memcpy(serialized + 4 * sizeof(unsigned int), &pd->original_length, sizeof(unsigned int));
    memcpy(serialized + 5 * sizeof(unsigned int), &pd->packet,pd->captured_length);
    }
    return 0;
}
// locate a conversation between port1 and port2 and export it to an array-
// convo_arr - fill with all the packets in the convo
// must free convo_arr after usage
// return list size on success, -1 if no matching convo was found
int list_to_arr(struct pcap_convo_list *convo_list, int port1, int port2, struct pcap_data *convo_arr)
{
    int i;
    struct pcap_frame *res = 0;
    struct pcap_frame *tmp;
    int arr_size = 0; // size of the convo, to be used in the array creationS
    while (convo_list)
    {
        if (check_for_convo_port(convo_list, port1))
        {
            res = convo_list->pcap_frame;
            convo_list = 0;
            // nullify to exit the loop
        }
    }
    // build the array using res and all of his next_convo nodes and return 0, otherwise if no convo was found return 1
    if (res == 0)
    {
        return -1;
    }
    tmp = res;
    while (tmp)
    {
        tmp = tmp->next_convo;
        arr_size++;
    }
    convo_arr = malloc(arr_size);
    for (i = 0; res; i++)
    {
        *(convo_arr + i) = res->data;
    }
    return arr_size;
}
int main()
{
    int res, i;
    struct pcap_frame *tmp_frame;       // used for freeing
    struct pcap_convo_list *tmp_convo; // used for freeing
    struct pcap_frame *timeline_list;
    struct pcap_convo_list *convo_list;
    struct pcap_frame *buffer_send; // buffer used to send arrays
    int timeline_size;
    char filename[100];
    puts("please enter the desired pcap name");
    gets(filename);
    timeline_size = pcap_to_lists(timeline_list, convo_list, filename);
    // edit the lists somehow if needed
    //...
    //  convert lists to arrays for easier transportation via net after all editing is done
    // get promt from user asking which convos to send
    // TODO implement choosing which convos to send

    res = list_to_arr(convo_list, 1, 2, buffer_send); // TODO run this for diffrent ports
    if (res == -1)
    {
        for(i = 0;i < res;i++)
        {
            // sum all the
        }
    }

    // end of program - free stuff
    free(buffer_send);
    tmp_frame = timeline_list;
    while (timeline_list)
    {
        timeline_list = timeline_list->next_timeline;
        free(tmp_frame->data.packet);
        free(tmp_frame);
        tmp_frame = timeline_list;
    }
    while(convo_list)
    {
        // as convo list is pointing to dat from timeline_list, there's no need to free all of it
        tmp_convo = convo_list->next;
        free(tmp_convo);
        tmp_convo = convo_list;
    }
    return 0;
}