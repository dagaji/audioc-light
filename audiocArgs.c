/* parses arguments from command line for audioc */

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h> 
#include <arpa/inet.h>
#include "audiocArgs.h"


/*=====================================================================*/
void args_print_audioc (struct in_addr multicastIp, unsigned int ssrc, int port, int packetDuration, int payload, int accumulatedTime, int vol, int verbose)
{
    char multicastIpStr[16];
    if (inet_ntop(AF_INET, &multicastIp, multicastIpStr, 16) == NULL) {
        printf("Error converting multicast address to string\n");
        exit(-1);
    }
    printf ("Multicast IP address \'%s\'\n", multicastIpStr);
    printf ("Local SSRC (hex) %x, port %d, packet duration %d, payload %d, accumulated time %d\n", ssrc, port, packetDuration, payload, accumulatedTime);
    printf ("Volume %d\n", vol);
    if (verbose==1) {
        printf ("Verbose ON\n"); }
    else   {
        printf ("Verbose OFF\n");}
};

/*=====================================================================*/
static void _printHelp (void)
{
    printf ("\naudioc v1.0");
    printf ("\naudioc  MULTICAST_ADDR  LOCAL_SSRC  [-pLOCAL_RTP_PORT] [-lPACKET_DURATION] [-yPAYLOAD] [-kACCUMULATED_TIME] [-vVOL] [-c]\n\n");
}


/*=====================================================================*/
static void _defaultValues (int *port, int *vol, int *packetDuration, int *verbose, int *payload, int *bufferingTime)
{
    *port = 5004;
    *vol = 90;
    *packetDuration = 20; /* 20 ms */

    *payload = PCMU;
    *verbose = 0; 
    *bufferingTime = 100; /* 100 ms */
};


/*=====================================================================*/
int args_capture_audioc(int argc, char * argv[], struct in_addr *multicastIp, unsigned int *ssrc, int *port, int *vol, int *packetDuration, int *verbose, int *payload, int *bufferingTime)
{
    int index;
    char car;
    int numOfNames=0;

    /*set default values */
    _defaultValues (port, vol, packetDuration, verbose, payload, bufferingTime);

    if (argc < 3 )
    { 
        printf("\n\nNot enough arguments\n");
        _printHelp ();
        return(EXIT_FAILURE);
    }

    for ( index=1; argc>1; ++index, --argc)
    {
        if ( *argv[index] == '-')
        {   

            car = *(++argv[index]);
            switch (car)	{ 

                case 'p': /* RTP PORT*/ 
                    if ( sscanf (++argv[index],"%d", port) != 1)
                    { 
                        printf ("\n-p must be followed by a number\n");
                        exit (1); /* error */
                    }		
                    if (  !  (( (*port) >= 1024) && ( (*port) <= 65535)  ))
                    {	    
                        printf ("\nPort number (-p) is out of the requested range, [1024..65535]\n");
                        exit (1); /* error */
                    }
                    break;

                case 'v': /* VOLUME */
                    if ( sscanf (++argv[index],"%d", vol) != 1)
                    { 
                        printf ("\n-v must be followed by a number\n");
                        return(EXIT_FAILURE);
                    }
                    if (  ! ( ( (*vol) >= 0) && ((*vol) <= 100)) )
                    {	    
                        printf ("\n-v must be followed by a number in the range [0..100]\n");
                        return(EXIT_FAILURE);
                    }
                    break;

                case 'l': /* Packet duration */
                    if ( sscanf (++argv[index],"%d", packetDuration) != 1)
                    { 
                        printf ("\n-l must be followed by a number\n");
                        exit (1); /* error */
                    }
                    if (  ! ( ((*packetDuration) >= 0)  ))
                    {	    
                        printf ("\nPacket duration (-l) must be greater than 0\n");
                        exit (1); /* error */
                    }
                    break;

                case 'c': /* VERBOSE  */
                    (*verbose) = 1;
                    break;

                case 'y': /* Initial PAYLOAD */
                    if ( sscanf (++argv[index],"%d", payload) != 1)
                    { 
                        printf ("\n-y must be followed by a number\n");
                        exit (1); /* error */
                    }
                    if (  ! ( ((*payload) == PCMU) || ( (*payload) == L16_1)  ))
                    {	    
                        printf ("\nUnrecognized payload number. Must be either 11 or 100.\n");
                        exit (1); /* error */
                    }
                    break;

                case 'k': /* Accumulated time in buffers */
                    if ( sscanf (++argv[index],"%d", bufferingTime) != 1)
                    { 
                        printf ("\n-k must be followed by a number\n");
                        exit (1); /* error */
                    }

                    if (  ! ( ((*bufferingTime) >= 0)  ))
                    {	    
                        printf ("\nThe buffering time (-k) must be equal or greater than 0\n");
                        return(EXIT_FAILURE); /* error */
                    }
                    break;

                default:
                    printf ("\nI do not understand -%c\n", car);
                    _printHelp ();
                    return(EXIT_FAILURE);
            }

        }

        else /* There is a name */
        {
            if (numOfNames == 0) {
                if (strlen (argv[index]) > 15) 
                {
                    printf("\nInternet address (IPv4) should not have more than 15 chars\n");
                    exit (1); /* error */	
                }
                int res = inet_pton(AF_INET, argv[index], multicastIp);
                if (res < 1) {
                    printf("\nInternet address string not recognized\n");
                    return(EXIT_FAILURE);
                }
                if (!IN_CLASSD(ntohl(multicastIp ->s_addr))) {
                    printf("\nNot a multicast address\n");
                    return(EXIT_FAILURE);
                }

            }
            else if (numOfNames == 1) {
                if (sscanf (argv[index],"%u", ssrc) != 1) {
                    printf ("\nSecond argument must be a number (the local SSRC)\n");
                    return(EXIT_FAILURE);
                }
            }
            else {
                printf ("\nToo many fixed parameters - only multicastIPStr and SSRC were expected\n");
                _printHelp ();
                return(EXIT_FAILURE);
            }

            numOfNames += 1;
        }
    }

    if (numOfNames != 2)
    {
        printf("\nNeed boh multicast address and SSRC value.\n");
        _printHelp();
        return(EXIT_FAILURE);
    }
    return(EXIT_SUCCESS);
};


/* Fast test of args, uncoment the following, compile with
 * gcc -o testArgs audioArgs.c 
 * Test different entries and check the results */

// int main(int argc, char *argv[])
// {
//     struct in_addr  multicastIp;
//     unsigned int ssrc;
//     int port, vol, packetDuration, verbose, payload, bufferingTime;

//     if (EXIT_SUCCESS == args_capture_audioc (argc, argv, &multicastIp, &ssrc, &port, &vol, &packetDuration,  &verbose,  &payload, &bufferingTime )) {
//         /* print arguments only if success */
//         args_print_audioc(multicastIp, ssrc, port, packetDuration, payload, bufferingTime, vol, verbose);
//     }
    

//     return (EXIT_SUCCESS);
// }

