/*******************************************************/
/* easyUDPSockets.h */
/*******************************************************/

//#define PORT 5000
// #define GROUP "225.0.1.29"
#define MAXBUF 512

int easy_init(struct in_addr multicastIp, unsigned short int destination_port);

int easy_send(void * message, int size);

//int easy_receive(char * buff, int sockId);
