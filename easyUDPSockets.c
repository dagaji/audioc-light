/* Unicast_multicast communication
THIS IS CODE for host2
compile with
	gcc -Wall -o host2 mcast_example_host2.c
execute as
	./host2

host1 uses an unicast localSAddr address.
host2 receives data in a multicast address. It receives from ANY sender.
(If you are testing with many of your mates, you should CHANGE the multicast address to avoid collisions)

host2 should be started first, then start host1.
	packet1: host1 (unicast) -> host2(multicast)
	packet2: host2 (unicast) -> host1(unicast)
In all cases, PORT is used both as source and destination (just as stated in RFC 4961)

host1 and host2 can be executed in any host with multicast connectivity between them (preferrably from the same link, 163.117.144/24
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>

#include "easyUDPSockets.h"

int result;         /* for storing results from system calls */
struct sockaddr_in remToSendSAddr, remToRecvSAddr; /* to build address/port info for local node and remote node */

struct ip_mreq mreq;/* for multicast configuration */
socklen_t sockAddrInLength;/* to store the length of the address returned by recvfrom */
int sockId;

int easy_init(struct in_addr multicastIp, unsigned short int destination_port){
    /* preparing bind */
    // bzero(&localSAddr, sizeof(localSAddr));
    // localSAddr.sin_family = AF_INET;
    // localSAddr.sin_port = htons(PORT); /* besides filtering, this assures that info is being sent with this PORT as local port */
    // multicastAddr.sin_addr = multicastIp;
    // /* fill .sin_addr with multicast address */
    // if (inet_pton(AF_INET, GROUP, &localSAddr.sin_addr) < 0) {
    //     printf("inet_pton error\n");
    //     return -1;
    // }

    bzero(&remToSendSAddr, sizeof(remToSendSAddr));
    remToSendSAddr.sin_family = AF_INET;
    remToSendSAddr.sin_port = htons(destination_port);
    remToSendSAddr.sin_addr = multicastIp;

    // if (inet_pton(AF_INET, GROUP, &remToSendSAddr.sin_addr) < 0) {
    //     printf("inet_pton error\n");
    //     return -1; /* failure */
    // }

    /* creating socket */
    if ((sockId = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("socket error\n");
        return -1;
    }

    /* configure SO_REUSEADDR, multiple instances can bind to the same multicast address/port */
    int enable = 1;
    if (setsockopt(sockId, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed");
        return -1;
    }

    /* binding socket - using mcast localSAddr address */
    if (bind(sockId, (struct sockaddr *)&remToSendSAddr, sizeof(struct sockaddr_in)) < 0) {
        printf("bind error\n");
        return -1;
    }

    /* setsockopt configuration for joining to mcast group */
    mreq.imr_multiaddr = multicastIp;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    // if (inet_pton(AF_INET, GROUP, &mreq.imr_multiaddr) < 0) {
    //     printf("inet_pton");
    //     return -1;
    // }


    if (setsockopt(sockId, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        printf("setsockopt error");
        return -1;
    }

    /* building structure to identify address/port of the remote node in order to send data to it */


    unsigned char loop=0;

    setsockopt(sockId, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(unsigned char));

    return sockId;

}

int easy_send(void * message, int size){
    /* Using sendto to send information. Since I've made a bind to the socket, the localSAddr (source) port of the packet is fixed.
       In the remoteSAddr structure I have the address and port of the remote host, as returned by recvfrom */
    /* Using sendto to send information. Since I've bind the socket, the local (source) port of the packet is fixed. In the rem structure I set the remote (destination) address and port */
    if ( (result = sendto(sockId, message, size, /* flags */ 0, (struct sockaddr *) &remToSendSAddr, sizeof(remToSendSAddr)))<0) {
        printf("sendto error\n");
    } else {
        //printf("Message sent to group\n");
    }

    return result;
}


int easy_receive(char * buff, int sockId){
    sockAddrInLength = sizeof (struct sockaddr_in); /* remember always to set the size of the rem variable in from_len */

    buff[result] = 0;

    if ((result = recvfrom(sockId, buff, MAXBUF, 0, (struct sockaddr *) &remToRecvSAddr, &sockAddrInLength)) < 0) {
        printf ("recvfrom error\n");
    } else {
        buff[result] = 0; /* convert to 'string' by appending a 0 value (equal to '\0') after the last received character */
        //printf("Message received from group\nMessage is: %s\n", buff); fflush (stdout);
    }

    return result;
}
