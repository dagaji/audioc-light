/*******************************************************/
/* audiocArgs.h */
/*******************************************************/

/* Parses arguments for audioc application */

/* audioc MULTICAST_ADDR  LOCAL_SSRC  [-pLOCAL_RTP_PORT] [-lPACKET_DURATION] [-yPAYLOAD] [-kACCUMULATED_TIME] [-vVOL] [-c]  */
/* payload options, to be included in RTP packets */
enum payload {PCMU=100,  L16_1=11};

/* Parses arguments from command line 
 * Returns  EXIT_FAILURE if it finds an error when parsing the args. In this
 * case the returned values are meaningless. It prints a message indicating
 * the problem observed.
 * Returns EXIT_SUCCESS if it could parse the arguments correctly */
int args_capture_audioc ( int argc, char *argv[], 
	int *multicastIp, /* 32-bit int containing the multicast addr. */
	unsigned int *ssrc,          /* Returns local SSRC value */
	int *port,          /* Returns port to be used in the communication */ 
	int *vol,           /* Returns volume requested (for both playing and 
                               recording). Value in range [0..100] */
	int *packetDuration,/* Returns requested duration of the playout of an UDP packet.
                               Measured in ms */
	int *verbose,       /* Returns if the user wants to show detailed traces (value 1) 
                               or not (value 0) */
	int *payload,       /* Returns the requested payload for the communication. 
                               This is the payload to include in RTP packets (see enum payload). 
                               */
	int *bufferingTime  /* Returns the buffering time requested before starting playout.
                               Time measured in ms. */
	);

/* prints current values, can be used for debugging */
void  args_print_audioc (int multicastIpStr, unsigned int ssrc, int port, int packetDuration, int payload, int bufferingTime, int vol, int verbose);



