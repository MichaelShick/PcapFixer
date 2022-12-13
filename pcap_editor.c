#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#include "pcapreader.c"

// TODO save all packets in a data structure
// TODO create a packet struct

/// Convert seconds to microseconds
#define SEC_TO_US(sec) ((sec)*1000000)
/// Convert nanoseconds to microseconds
#define NS_TO_US(ns) ((ns) / 1000)
int matchcount = 0;
/// Get a time stamp in microseconds.
uint64_t micros()
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  uint64_t us = SEC_TO_US((uint64_t)ts.tv_sec) + NS_TO_US((uint64_t)ts.tv_nsec);
  return us;
}
int count = 0; // counter for id naming - debug
// build and return the timeline list, which is a list of all the packets sorted by arrival order
struct pcap_frame build_timeline_node(char *pcap_buffer)
{
  struct pcap_frame tmp1;
  tmp1.id = count++;
  tmp1.seconds = *((unsigned int *)pcap_buffer);
  tmp1.microseconds = *((unsigned int *)pcap_buffer + 1);
  tmp1.original_length = *((unsigned int *)pcap_buffer + 2);
  tmp1.captured_length = *((unsigned int *)pcap_buffer + 3);
  printf("original length : %d", tmp1.original_length);
  tmp1.packet = malloc(*((unsigned int *)pcap_buffer + 2));
  memcpy(tmp1.packet, (pcap_buffer + 4 * sizeof(unsigned int)), tmp1.original_length);
  tmp1.next_timeline = malloc(sizeof(struct pcap_frame));
  tmp1.next_convo = 0;
  return tmp1;
}
// check if two pcap frames contain packets that belong to the same conversation
// TODO add checks other than ip
// 1 - succesful match on ip
// 0 - unsuccessful match
int check_if_convo(struct pcap_frame *pcap1, struct pcap_frame *pcap2)
{
  // if either frame is null or the packet has the same id there can be no match
  printf("comparing %d and %d\n", pcap1->id, pcap2->id);
  if ((!pcap1 || !pcap2) || (pcap1->id == pcap2->id))
  {
    return 0;
  }
  struct ethdr *eth1 = (struct ethhdr *)(pcap1->packet);
  struct ethdr *eth2 = (struct ethhdr *)(pcap2->packet);
  if (ntohs(eth1->h_proto) == 2048 && ntohs(eth2->h_proto) == 2048)
  {
    struct iphr *iph1 = (struct iphr *)(pcap1->packet + (sizeof(struct ethdr)));
    struct iphr *iph2 = (struct iphr *)(pcap2->packet + (sizeof(struct ethdr)));
    if (iph1->Protocol == 6 && iph2->Protocol == 6)
    {
      struct tcpheader *tcph1 = (struct tcpheader *)(pcap1->packet + (4 * iph1->ihl) + sizeof(struct ethdr));
      struct tcpheader *tcph2 = (struct tcpheader *)(pcap1->packet + (4 * iph2->ihl) + sizeof(struct ethdr));
      printf("comparing adresses %u and %u, as well as %u and %u\n", htons(tcph1->SourcePort), htons(tcph2->DestinationPort), htons(tcph1->DestinationPort), htons(tcph2->SourcePort));
      if ((htons(tcph1->SourcePort) == htons(tcph2->SourcePort)) || (htons(tcph1->DestinationPort) == htons(tcph2->DestinationPort)) || ((htons(tcph1->SourcePort) == htons(tcph2->DestinationPort)) || (htons(tcph1->DestinationPort) == htons(tcph2->SourcePort))))
      {
        printf("match %d\n\n", ++matchcount);
        return 1;
      }
    }
  }
  return 0;
}
// TODO add null checks
//  build the convo list using a pre-built timeline_list as well as its size
//  convo_size - fill with the amount diffrent convos
//  for this extracting the transport layer and comparing adresses is requiered.
//  find a matching conversation to append a node from timeline_list to it.
//  as the packets in timeline_list are sorted chronologically, all that is needed to keep conversation order is appending to the end.
struct pcap_convo_list build_convo_list(struct pcap_frame *timeline_list, int size, int *convo_size)
{
  struct pcap_convo_list convo_list = {};
  struct pcap_frame *tmp1_conv = 0; // for traversing timeline_list's next_convo;
  struct pcap_convo_list *tmp2;     // for traversing convo_list
  int res;
  // first packet is appended right away, as convo list is initialy empty and there is no need to check for matches
  convo_list.pcap_frame = timeline_list;
  convo_list.next = 0;
  timeline_list = timeline_list->next_timeline;
  size--;
  // pass all the packets in the timeline list;
  while (size)
  {
    printf("working on packet %d\n", timeline_list->id);

    // printf("working on packet %d\n", timeline_list->id);
    // for each packet in timeline_list try to find an already existing conversation (same ports)
    // when such a conversation is found break the loop.
    tmp2 = &convo_list;
    while (tmp2)
    {
      res = check_if_convo(tmp2->pcap_frame, timeline_list);
      if (res)
      {
        // found a match, append to the end of the local convo_list
        printf("found a match, appending\n");
        tmp1_conv = tmp2->pcap_frame;
        while (tmp1_conv->next_convo)
        {
          tmp1_conv = tmp1_conv->next_convo;
        }
        tmp1_conv->next_convo = timeline_list;
        break;
      }
      // continue to traverse convo_list
      // if at end of the list, add the packet as a start of a new convo and null tmp2 to break the loop
      else if (tmp2->next)
      {
        tmp2 = tmp2->next;
      }
      else
      {
        tmp2->next = malloc(sizeof(struct pcap_convo_list));
        tmp2->next->pcap_frame = timeline_list;
        tmp2->next->next = 0;
        (*convo_size)++;
        printf("no match, creating new node..\n");
        break;
      }
    }
    timeline_list = timeline_list->next_timeline;
    size--;
  }
  printf("done convo list\n");
  return convo_list;
}
// TODO add dependancy on the magic number in the head of the pcap file
// get diffrent variables consernging the pcap file packets, and construct the timeline and conversation lists.
//  char *pcap_buffer - the buffer with the packets - MUST NOT BE NULL
//  unsigned int *pcap_pkt_count - fill with the count of all the packets in the file
//  unsigned int *pcap_session_length - fill with first packet time stamp minus last packet time stamp
//  unsigned int *biggest_packet - fill with the biggest packet size
//  struct pcap_frame timeline_list - fill with the packets one after another by their arrival time
void pcap_stats(char *pcap_buffer, unsigned int *pcap_packet_count, unsigned int *pcap_convo_count, unsigned int *pcap_session_length, unsigned int *biggest_packet, struct pcap_frame *timeline_list, struct pcap_convo_list *convo_list)
{
  // in the pcap_packet struct ther are two links - timeline and convo. first i create a separate the timeline list, and then try to make the convo_list based on the timeline_list
  // this means that initialy convo_list is null as well as next_convo

  struct pcap_frame *tmp1;  // for traversing timeline_list
  unsigned int biggest = 0; // to look for the biggest packet size
  unsigned int first_packet_time = SEC_TO_US(*((unsigned int *)pcap_buffer)) + *((unsigned int *)pcap_buffer + 1);
  // pcap files are weird. the buffer contains lots of zeroes, so the loop stops when a zero sized packet is encountered
  // TODO put all this in a build_timeline_list function
  tmp1 = timeline_list;
  while (pcap_buffer)
  {
    //  pcap files are weird. the buffer contains lots of zeroes, so the loop stops when a zero sized packet is encountered
    (*pcap_packet_count)++;
    *tmp1 = build_timeline_node(pcap_buffer);
    *pcap_session_length = SEC_TO_US(*((unsigned int *)pcap_buffer)) + *((unsigned int *)pcap_buffer + 1);
    if (biggest < *((unsigned int *)pcap_buffer + 2))
    {
      biggest = *((unsigned int *)pcap_buffer + 2);
    }
    pcap_buffer += *((unsigned int *)pcap_buffer + 2) + 4 * sizeof(int);
    printf("working on packet %d\n", tmp1->id);
    if (*((unsigned int *)pcap_buffer + 2) == 0)
    {
      printf("found zero size packet, breaking\n");
      tmp1->next_timeline = 0;
      break;
    }
    tmp1 = tmp1->next_timeline;
  }
  *pcap_session_length -= first_packet_time;
  *convo_list = build_convo_list(timeline_list, *pcap_packet_count, pcap_convo_count);
  printf("there are %d packets, and the pcap lasted %d microseconds/%d seconds\n", *pcap_packet_count, *pcap_session_length, *pcap_session_length / 1000000);
}
int main()
{
  int input;
  unsigned int size;
  char *pcap_buffer; // this is the pcap file buffer. it is filled with the pcap file content.
  // First, collect all the information possible and orginize it.
  unsigned int pcap_packet_count = 0; // how many packets there are in the recording.
  unsigned int pcap_convo_count = 0;  // how many convos there are in the recording.
  unsigned int pcap_time_length = 0;  // last packet arrival time minus first packet arrival time in microseconds
  unsigned int biggest_size = 0;      // biggest packet size - maybe irrelevant
  struct pcap_frame timeline_list;
  struct pcap_frame *tmp;
  struct pcap_convo_list convo_list; // the list of all packets convos, sorted by arrival time. points to frames from timeline_list
  pcap_buffer = get_buffer(&size);
  printf("gonna print some shit\n");
  pcap_stats(pcap_buffer, &pcap_packet_count, &pcap_convo_count, &pcap_time_length, &biggest_size, &timeline_list, &convo_list);
  tmp = &timeline_list;
  while (tmp)
  {
    // printf("seconds %d\n"
    //        "microseconds %d\n"
    //        "original_length %d\n"
    //        "captured_length %d\n",
    //        timeline.seconds, timeline.microseconds, timeline.original_length, timeline.captured_length);
    printf("%d -> ", tmp->id);
    // printingPackets(tmp->packet);
    tmp = (tmp->next_timeline);
  }
  printf("\n\n now doing convos \n");
  do
  {
    tmp = convo_list.pcap_frame;
    while (tmp)
    {
      printf("%d ->", tmp->id);
      tmp = tmp->next_convo;
    }
    printf("\n\n");
    if (convo_list.next != NULL)
    {
      convo_list = *convo_list.next;
    }
  } while ((convo_list.next));
  // introducing the frame editor -------------------------------- --------------------------------
  // what is needed is a live editor that allows to rewind, foward and edit values in a pcap record.
  // REWINDING EDITING FORWADRING - to do that i will use the tframe (time frame) struct
  //--------------------------- it will contain the state of the pcap record in a specific point of it's lifetime; frame 0 is the start of the recording, and the last frame is the end of the recording.
  //--------------------------- the user should be able to freely choose which frame to view, as well as see and edit all information contained within.
  //--------------------------- the user also should be able to add and remove frames with the system reacting correctly (deleting sent questions removes answers)
  //--------------------------- each frame will contain the data available to the pcap record at a specific point of time.
  //--------------------------- there should be at least as much frames as there are packets, but in practice there should be many more to allow free packet editing and addition.
  //--------------------------- packet records are saved in frames using linked lists - each frame will be a node of a list, and will point to the next node in the pcap timeline as well as to the next packet in the convesation

  puts("done");
  return 1;
}