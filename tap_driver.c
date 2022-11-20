#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include "pcapreader.c"

#include <net/if.h>       // ifreq
#include <linux/if_tun.h> // IFF_TUN, IFF_NO_PI
#include <linux/if_arp.h>

#include <sys/ioctl.h>

/// Convert seconds to microseconds
#define SEC_TO_US(sec) ((sec)*1000000)
/// Convert nanoseconds to microseconds
#define NS_TO_US(ns) ((ns) / 1000)

int tun_alloc(char *dev, int flags)
{

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  /* Arguments taken by the function:
   *
   * char *dev: the name of an interface (or '\0'). MUST have enough
   *   space to hold the interface name if '\0' is passed
   * int flags: interface flags (eg, IFF_TUN etc.)
   */
  /* open the clone device */
  if ((fd = open(clonedev, O_RDWR)) < 0)
  {
    return fd;
  }
  /* preparation of the struct ifr, of type "struct ifreq" */
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags; /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */
  if (*dev)
  {
    /* if a device name was specified, put it in the structure; otherwise,
     * the kernel will try to allocate the "next" device of the
     * specified type */
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }
  /* try to create the device */
  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
  {
    perror("creation faliure\n");
    close(fd);
    return err;
  }
  /* if the operation was successful, write back the name of the
   * interface to the variable "dev", so the caller can know
   * it. Note that the caller MUST reserve space in *dev (see calling
   * code below) */
  strcpy(dev, ifr.ifr_name);
  printf("Created device named %s\n", ifr.ifr_name);
  /* this is the special file descriptor that the caller will use to talk
   * with the virtual interface */
  return fd;
}
/// Get a time stamp in microseconds.
uint64_t micros()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    uint64_t us = SEC_TO_US((uint64_t)ts.tv_sec) + NS_TO_US((uint64_t)ts.tv_nsec);
    return us;
}
int main()
{
  int fdesc;
  char *dev = malloc(256);
  char input;
  unsigned int size;
  char *pcap_buffer = get_buffer(&size);

  int simulation_rate = -1;
  int count = 1;
  uint64_t time_to_wait_us = 0; // time to wait, in microseconds

  uint64_t time_last_us = 0; // the time on the previous packet in microseconds

  unsigned  long timestamp_us; // template for timestapms in microseconds

  unsigned  long time_tmp_us; // time buffer in microseconds

  uint64_t simulation_timer; // simulation timer in seconds

  strcpy(dev, "test");
  fdesc = tun_alloc(dev, IFF_TAP);
  // setup_tun(fdesc);
  system("ip link set test up");
  system("ip addr add 10.0.0.1/24 dev test");

  printf("working buffer size is %d. specify simulation rate (acceptable values are between 1 - 5)\n", size);
  while (simulation_rate <= 0 || simulation_rate >= 5)
  {
    scanf("%d", &simulation_rate);
    if (simulation_rate <= 0 || simulation_rate >= 5)
    {
      printf("invalid simulation rate, reenter\n");
    }
  }
  printf("chosen simulation rate is %d . type y to begin\n", simulation_rate);

  while (input != 'y')
  {
    scanf("%c", &input);
  }
  // recored simulation start
  simulation_timer = micros();
  printf("starting simulation at %lu  seconds\n", simulation_timer);

  // since pcap file structure is weird, sometimes there are zero sized packets.
  // therefore writing to tap stops either once the file buffer is ended or when a zero sized packet is encountered.
  while (size > 0)
  {
    // where there any packets before this one? if yes, the last packet time should have been saved
    if (time_last_us)
    {
      printf("packet %d arrived at %u. last packet arrived at %lu microseconds\n", count++, SEC_TO_US(*((unsigned int *)pcap_buffer))+*((unsigned int *)pcap_buffer + 1), time_last_us);
      time_to_wait_us = (SEC_TO_US(*((unsigned int *)pcap_buffer))+(*((unsigned int *)pcap_buffer + 1)) - time_last_us)/simulation_rate; // (the time packet A arrived - the time the packet before A arrived)/simulation rate = time to wait before writing packet A
      if(time_to_wait_us > 100000000 )
      {
        printf("weird waiting time, skipping this one....\n");
        break;  
      } 
      do
      {
        time_tmp_us = micros();
        printf("%lu microseconds timestamp --- current timstamp %lu ,waiting for %lu microsecnds\n", time_to_wait_us + timestamp_us,time_tmp_us, time_to_wait_us);

        //break;
      } while ( time_tmp_us < time_to_wait_us+timestamp_us);
    }
    else
    {
      puts("first packet!!");
    }
    //PrintingPackets(pcap_buffer);
    // printf("packet size -  %d\n", *((int *)pcap_buffer + 2));

    // check if packet size is zero.
    // if is, don't write it
    if (*((int *)pcap_buffer + 2) > 0)
    {

      if (write(fdesc, pcap_buffer, *((unsigned int *)pcap_buffer + 2)) < 0)
      {
        perror("error\n");
        exit(1);
      }
    }
    else
    {
      printf("zero packet, enough\n");
      break;
    }
    time_last_us = SEC_TO_US(*((unsigned int *)pcap_buffer))+*((unsigned int *)pcap_buffer + 1); // packet timestamp in microseconds(the seconds field is converted to microseconds)
    timestamp_us = micros();
    pcap_buffer += (4 * sizeof(int)) + *((int *)pcap_buffer + 2); // on to the next packet
    size -= ((4 * sizeof(int)) + *((int *)pcap_buffer + 2));

    printf("wrote packet. size left ---- %d\n", size);
  } 
  printf("ending simulation. lasted %lu microseconds\n", micros()-simulation_timer);

  puts("done");
  sleep(100);
  return 1;
}