/*******************************************************/
/* audiocArgs.h */
/*******************************************************/

/* Parses arguments for audioc application */

/* audioc MULTICAST_ADDR  LOCAL_SSRC  [-pLOCAL_RTP_PORT] [-lPACKET_DURATION] [-yPAYLOAD] [-kACCUMULATED_TIME] [-vVOL] [-c]  */
/* payload options, to be included in RTP packets */
enum payload {PCMU=100,  L16_1=11};

/* Parses arguments from command line 
 * Returns  EXIT_FAILURE if it finds an error when parsing the args. In this
 * case, the returned values are meaningless. It prints a message indicating
 * the problem observed.
 * Returns EXIT_SUCCESS if it could parse the arguments correctly */
int  args_capture_audioc ( int argc, char *argv[], 
	struct in_addr *multicastIp, 	/* Does not use the initial value of the variable.
						Returns a 'struct in_addr *' which points to the 32-bit int 
						containing the multicast address, already in Network Byte Order
						(since it is the result of calling to inet_pton). 
						Can be used the following way:
							struct in_addr mcastIP;
							struct sockaddr_in mcast;
							...
							args_capture_audioc(argc, argv, &mcastIP...)
							...
							mcast.sin_addr = mcastIP;
						Note that args_capture_audioc ensures that the returned value is a 
						multicast address (otherwise, it returns EXIT_FAILURE) */
	unsigned int *ssrc, /* Does not use the initial value of the variable. 
						Returns local SSRC value */
	int *port,          /* Does not use the initial value of the variable.
						Returns port to be used in the communication */ 
	int *vol,           /* Does not use the initial value of the variable. 
						Returns volume requested (for both playing and 
                        recording). Value in range [0..100] */
	int *packetDuration,/* Does not use the initial value of the variable.
						Returns requested duration of the playout of an UDP packet.
                        Measured in ms */
	int *verbose,       /* Does not use the initial value of the variable.
						Returns 1 if the user wants to show detailed traces, 0 otherwise */
	int *payload,       /* Does not use the initial value of the variable.
						Returns the requested payload for the communication. 
                        This is the payload to include in RTP packets (see 'enum payload'). */
	int *bufferingTime  /* Does not use the initial value of the variable.
						Returns the buffering time requested before starting playout.
                        Time measured in ms. */
	);

/* prints current values, can be used for debugging */
void  args_print_audioc (struct in_addr multicastIpStr, unsigned int ssrc, int port, int packetDuration, int payload, int bufferingTime, int vol, int verbose);



