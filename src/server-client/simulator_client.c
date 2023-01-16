#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include "simulator_client.h"
// this file describes a basic simulation asset.
// the simulations asset task is to send packets to another asset based on the instructions provided by simulation_server
// mb i should rename it to simulation_asset? idk

//deserialize data after receving from the net.
void deserialize_pcap_data(const unsigned char *bytes, struct pcap_data *data)
{

    // Read the fields from the byte stream
    data->id = ntohl(*((unsigned int *)bytes));
    data->seconds = ntohl(*((unsigned int *)(bytes + 4)));
    data->microseconds = ntohl(*((unsigned int *)(bytes + 8)));
    data->captured_length = ntohl(*((unsigned int *)(bytes + 12)));
    data->original_length = ntohl(*((unsigned int *)(bytes + 16)));
}

//int* sock - a pointer to an integer that will store the socket descriptor returned by the socket() function.
//struct sockaddr_in* addr - a pointer to a sockaddr_in structure that will store the destination address." 
void openSocket(int *sock, struct sockaddr_in *addr)
{
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0)
    {
        perror("socket error");
        return 1;
    }

    // Set the destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr("192.168.1.1");

    // Create the data to be sent
    *sock = sockfd;
    *addr = dest_addr;
}
// wait for the server to send simulation instructions.
// open a socket in recieve mode for that.
// as there could be numerous packets, first recieve the amount of packets that are going to be received, as well basic data.
// struct pcap_data* data_to_send - fill with data that the asset is required to send
// struct pcap_data* data_to_recv - fill with data that the asset is expected to receive
// int* sim_speed - a number indicating the speed of the simulation. used to modify the time delay between sending packets.
// int* sim_trash - 1 if the asset is to send trash along with "data_to_send", 0 otherwise.
// return 1 on faliure, 0 on success
int standby(struct pcap_data *data_to_send, struct pcap_data *data_to_recv, unsigned short *sim_speed, unsigned short *sim_trash)
{
    int i;
    int socket_desc;
    int packets_to_send_count;
    int packets_to_recv_count;
    int packets_count; // send_count + recv+count;
    struct pcap_frame* convo_arr; // the array containing the full convo that needs to be played out
    ssize_t ret;
    struct sockaddr_in server;
    char server_data[2048];
    // Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }

    server.sin_addr.s_addr = inet_addr("74.125.235.20");
    server.sin_family = AF_INET;
    server.sin_port = htons(80);

    // Connect to server
    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        puts("connect error");
        return 1;
    }

    puts("Connected");
    // wait for server to send data. recieve the packets_to_send_count,packets_to_recv_count,sim_speed,sim_trash in a single buffer;
    // expected size = sizeof(int + int + short+short) = 4+4+2+2=12
    if (recv(socket_desc, &server_data, 12, 0) < 0)
    {
        puts("recv failed");
        return 0;
    }

    // Parse the data from the buffer
    memcpy(&packets_to_send_count, &server_data[0], 4);
    packets_to_send_count = ntohl(packets_to_send_count); // Convert to host byte order
    memcpy(&packets_to_recv_count, &server_data[4], 4);
    packets_to_recv_count = ntohl(packets_to_recv_count); // Convert to host byte order
    memcpy(sim_speed, &server_data[8], 2);
    *sim_speed = ntohs(*sim_speed); // Convert to host byte order
    memcpy(sim_trash, &server_data[10], 2);
    *sim_trash = ntohs(*sim_trash); // Convert to host byte order

    // Print the parsed data
    printf("packets_to_send_count: %d\n", packets_to_send_count);
    printf("packets_to_recv_count: %d\n", packets_to_recv_count);
    printf("sim_speed: %hd\n", *sim_speed);
    printf("sim_trash: %hd\n", *sim_trash);
    // get the array containing the conversation.
    convo_arr = malloc(packets_to_recv_count * packets_to_send_count);
    // for (i = 0; i < packets_to_send_count; i++)
    // {
    //     // receive all but the packet itself in pcap_data
    //     //  expected size - sizeof(int)*5 = 20
    //     if (recv(socket_desc, &server_data, 20, 0) < 0)
    //     {
    //         puts("recv failed");
    //         return 0;
    //     }
    //     deserialize_pcap_data(server_data, data_to_send + i * sizeof(struct pcap_data));
    //     // receive the packet itself
    //     if (recv(socket_desc, &server_data, (data_to_send + i)->captured_length, 0) < 0)
    //     {
    //         puts("recv failed");
    //         return 0;
    //     }
    //     (data_to_send + i)->packet = malloc((data_to_send + i)->captured_length);
    //     memcpy((data_to_send + i)->packet, server_data, (data_to_send + i)->captured_length);
    // }
    // //fill all data to recv
    // data_to_recv = malloc(sizeof(data_to_recv) * packets_to_recv_count);
    // for (i = 0; i < packets_to_recv_count; i++)
    // {
    //     // receive all but the packet itself in pcap_data
    //     //  expected size - sizeof(int)*5 = 20
    //     if (recv(socket_desc, &server_data, 20, 0) < 0)
    //     {
    //         puts("recv failed");
    //         return 0;
    //     }
    //     deserialize_pcap_data(server_data, data_to_recv + i * sizeof(struct pcap_data));
    //     // receive the packet itself
    //     if (recv(socket_desc, &server_data, (data_to_recv + i)->captured_length, 0) < 0)
    //     {
    //         puts("recv failed");
    //         return 0;
    //     }
    //     (data_to_recv + i)->packet = malloc((data_to_recv + i)->captured_length);
    //     memcpy((data_to_recv + i)->packet, server_data, (data_to_recv + i)->captured_length);
    // }
    return 1;
}
// couple of things to do -
//  check if this client is supposed to initiate the communication
//  for the pcap file needs to be compared against the recieved data
int main(int argc, char *argv[])
{
    int err;
    // Create a raw socket
    int flag_init;
    // socket info
    int sockfd;
    struct sockaddr_in dest_addr;
    // array of packets required to send and expected to recieve
    struct pcap_data *data_to_send;
    struct pcap_data *data_to_recv;
    unsigned short sim_speed; // speed multiplier for the simulation. divivde it by the packet send time delay. recieved from the server
    unsigned short sim_trash; // send random data along with packets from "data_to_send".
    while (standby(data_to_send, data_to_recv, &sim_speed, &sim_trash))
        ; // wait for a server to send orders.
    openSocket(&sockfd, &dest_addr);
    // if (bytes_sent < 0)
    // {
    //     perror("sendto error");
    //     return 1;
    // }

    // Close the socket
    close(sockfd);

    return 0;
}