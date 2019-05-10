/*

gcc -Wall -Wextra -o audioc audiocArgs.c circularBuffer.c configureSndcard.c easyUDPSockets.c audioc.c

./audioc 227.3.4.5 4532 -l100 -c
*/

#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/soundcard.h>

#include "audiocArgs.h"
#include "circularBuffer.h"
#include "configureSndcard.h"
#include "easyUDPSockets.h"
#include "rtp.h"

void update_buffer(int descriptor, void *buffer, int size);
void play(int descriptor, void *buffer, int size, unsigned int * current_blocks);
int ms2bytes(int duration, int rate, int channelNumber, int sndCardFormat);
void insert_repeated_packets(void* circular_buf, void* buf, int requestedFragmentSize, unsigned int K, unsigned int numberOfBlocks, unsigned int * current_blocks, int verbose_c);
void create_comfort_noise(void* noise_pointer, int fragmentSize, int sndCardFormat);
int check_write_cbuf(void* circular_buf, void* content_pointer, int size, unsigned int * current_blocks, int verbose_c);
float get_diff_times(struct timeval* last_timeval);
void reset_timer(int descriptorSnd, int rate, int channelNumber, int sndCardFormat, struct timeval* timer, unsigned int current_blocks, int requestedFragmentSize);
void hton_audio(void * audioData, int requestedFragmentSize);
void ntoh_audio(void * audioData, int requestedFragmentSize);
void terminar();
void print_playouts();
void validate_packet(unsigned long int remote_ssrc, unsigned int remote_pt);

const int BITS_PER_BYTE = 8;
const float MILI_PER_SEC = 1000.0;
const float MICRO_PER_MILI = 1000.0;

const uint8_t ZERO_U8 = 128;
const uint8_t MA_U8 = 4;
const int16_t ZERO_S16 = 0;
const int16_t MA_S16 = 150;
const float PMA = 0.7;

const int SIZE_NOISE = 16;
const uint8_t NOISE_FRAGMENT_U8[] = {127,127,127,127,127,127,128,128,128,128,128,127,127,127,128,127};
const int16_t NOISE_FRAGMENT_S16[] = {22,1,-14,-2,-1,6,12,19,24,21,7,4,-8,-12,0,-4};

const int INSERT = 0;
const int SILENCE = 1;
const int TIMER = 2;
const int X = 3;


/* only declare here variables which are used inside the signal handler */
void *buf_rcv = NULL;
void *last_audioData = NULL;
void *buf_send = NULL;
void *bufheader = NULL;
char *fileName = NULL;     /* Memory is allocated by audioSimpleArgs, remember to free it */
void *circular_buf = NULL;
void *noise_pointer = NULL;

unsigned int local_silences = 0;
unsigned int remote_silences = 0;
unsigned long int timeStamp_timer = 0;
struct timeval first_packet_timeval;
int sndCardFormat;
int channelNumber;
int rate;
int verbose;
unsigned long int ssrc = 0;
unsigned long int first_timeStamp;


/* activated by Ctrl-C */
void signalHandler (int sigNum __attribute__ ((unused)))  /* __attribute__ ((unused))   -> this indicates gcc not to show an 'unused parameter' warning about sigNum: is not used, but the function must be declared with this parameter */
{
	terminar();
}


void main(int argc, char *argv[])
{
    struct sigaction sigInfo; /* signal conf */
    int descriptorSnd;
    int requestedFragmentSize;
    int port;
    int vol;
    int packetDuration;
    int payload;
    int bufferingTime;
    int numberOfBlocks;
    fd_set reading_set, writing_set;
    int sockId;
    struct in_addr multicastIp;
    int res;
    int buffering = 1;
    unsigned int nseq = 0;
    unsigned long int timeStamp = 0;
    unsigned int seqNum_anterior = 0;
    unsigned int seqNum_actual = 0;
		unsigned int seqNum_timer = 0;
    rtp_hdr_t * hdr_message = NULL;
    char * audioData = NULL;
    unsigned int K = 0;
    unsigned int K_t = 0;
    struct timeval silence_timer;
    struct timeval last_timeval;
    unsigned int current_blocks = 0;
    unsigned int num_blocks_to_write;
	unsigned int num_times_timer = 0;


    /* we configure the signal */
    sigInfo.sa_handler = signalHandler;
    sigInfo.sa_flags = 0;
    sigemptyset(&sigInfo.sa_mask); /* clear sa_mask values */
    if ((sigaction (SIGINT, &sigInfo, NULL)) < 0) {
        printf("Error installing signal, error: %s", strerror(errno));
        exit(1);
    }


    /* obtain values from the command line - or default values otherwise */
    if (-1 == args_capture_audioc(argc, argv, &multicastIp, &ssrc,
            &port, &vol, &packetDuration, &verbose, &payload, &bufferingTime))
    { exit(1);  /* there was an error parsing the arguments, the error type
                   is printed by the args_capture function */
    };

    channelNumber = 1;
    if(payload == PCMU){
        rate = 8000;
        sndCardFormat = U8;
    }else if(payload == L16_1){
        rate = 44100;
        sndCardFormat = S16_LE;
    }

    requestedFragmentSize = ms2bytes(packetDuration, rate, channelNumber, sndCardFormat);

    /* create snd descritor and configure soundcard to given format, rate, number of channels.

     * Also configures fragment size */
    configSndcard (&descriptorSnd, &sndCardFormat, &channelNumber, &rate, &requestedFragmentSize);

    numberOfBlocks = ms2bytes(bufferingTime + 200, rate, channelNumber, sndCardFormat) / requestedFragmentSize;
    printf("numberOfBlocks: %d\n", numberOfBlocks);

    vol = configVol (channelNumber, descriptorSnd, vol);

    args_print_audioc(multicastIp, ssrc, port, packetDuration, payload, bufferingTime, vol, verbose);
    printFragmentSize (descriptorSnd);
    printf ("Duration of each packet exchanged with the soundcard :%f\n", (float) requestedFragmentSize / (float) (channelNumber * sndCardFormat / BITS_PER_BYTE) / (float) rate);


    /****************************************/

    buf_rcv = malloc (requestedFragmentSize + sizeof(rtp_hdr_t));
    if (buf_rcv == NULL) {
        printf("Could not reserve memory for buf_rcv.\n");
        exit (1); /* very unusual case */
    }

    buf_send = malloc (requestedFragmentSize + sizeof(rtp_hdr_t));
    if (buf_send == NULL) {
        printf("Could not reserve memory for buf_send.\n");
        exit (1); /* very unusual case */
    }

    if((sockId = easy_init(multicastIp, (unsigned short int)port)) < 0){
        printf("Could not initialize socket.\n");
        exit(1);
    }

    circular_buf = cbuf_create_buffer(numberOfBlocks, requestedFragmentSize);

    noise_pointer = malloc (requestedFragmentSize);
    if (buf_send == NULL) {
        printf("Could not reserve memory for comfort noise.\n");
        exit (1); /* very unusual case */
    }
    create_comfort_noise(noise_pointer, requestedFragmentSize, sndCardFormat);


    last_audioData = malloc (requestedFragmentSize);
    if (last_audioData == NULL) {
        printf("Could not reserve memory for last_audioData.\n");
        exit (1); /* very unusual case */
    }


    while(buffering){

        FD_ZERO(&reading_set);
        FD_SET(descriptorSnd, &reading_set);
        FD_SET(sockId, &reading_set);

        if ((res = select (FD_SETSIZE, &reading_set, NULL, NULL, NULL)) < 0) {
            printf("Select failed");
            exit(1);
        }else{

            if(FD_ISSET (descriptorSnd, &reading_set) == 1){

                hdr_message = (rtp_hdr_t *) buf_send;

                (*hdr_message).version = 2;
                (*hdr_message).p = 0;
                (*hdr_message).x = 0;
                (*hdr_message).cc = 0;
                (*hdr_message).m = 0;
                if(payload == PCMU){
					(*hdr_message).pt = 0;
				}else if(payload == L16_1){
					(*hdr_message).pt = 11;
				}
                (*hdr_message).ssrc = htonl(ssrc);
                (*hdr_message).seq = htons(nseq);
                (*hdr_message).ts = htonl(timeStamp);

                audioData = (char *)(hdr_message + 1);

				update_buffer(descriptorSnd, audioData, requestedFragmentSize);

                if(sndCardFormat == S16_LE) hton_audio(audioData, requestedFragmentSize);
	            easy_send(buf_send, requestedFragmentSize + sizeof(rtp_hdr_t));

				nseq = nseq + 1;
                timeStamp = timeStamp + requestedFragmentSize;

                if(verbose) {
                    printf (".");fflush (stdout);
                }

            }

            if(FD_ISSET (sockId, &reading_set) == 1){

                update_buffer(sockId, buf_rcv, requestedFragmentSize + sizeof(rtp_hdr_t));

                hdr_message = (rtp_hdr_t *) buf_rcv;
                seqNum_actual = ntohs((*hdr_message).seq);
                validate_packet((*hdr_message).ssrc, (*hdr_message).pt);

                audioData = (char *)(hdr_message + 1);
                if(sndCardFormat == S16_LE) ntoh_audio(audioData, requestedFragmentSize);

                if(current_blocks == 0){
                    seqNum_anterior = seqNum_actual;
                    check_write_cbuf(circular_buf, audioData, requestedFragmentSize, &current_blocks, INSERT);
					if (gettimeofday (&first_packet_timeval, NULL) <0) {
        				printf("Timeval fallo\n");
        				exit(1);
    				}
                }else if(seqNum_actual > seqNum_anterior){
                    K = seqNum_actual - seqNum_anterior;
                    if(K == 1){
                        check_write_cbuf(circular_buf, audioData, requestedFragmentSize, &current_blocks, INSERT);
                    }else if(K < 4){
                        if(verbose) {
                            printf ("s");fflush (stdout);
                        }
                        insert_repeated_packets(circular_buf, last_audioData, requestedFragmentSize, K - 1, numberOfBlocks, &current_blocks, X);
                        check_write_cbuf(circular_buf, audioData, requestedFragmentSize, &current_blocks, INSERT);
                    }else {
                        if(verbose) {
                            printf ("s");fflush (stdout);
                        }
                        insert_repeated_packets(circular_buf, noise_pointer, requestedFragmentSize, K - 1, numberOfBlocks, &current_blocks, X);
                        check_write_cbuf(circular_buf, audioData, requestedFragmentSize, &current_blocks, INSERT);
                    }

                    seqNum_anterior = seqNum_actual;
                    memcpy(last_audioData, audioData, requestedFragmentSize);
                    buffering = (current_blocks < numberOfBlocks);
                }


            }


        }

    }


		// Cambiar luego
    silence_timer.tv_sec = 1;
    silence_timer.tv_usec = 0;

	//print_playouts();

    while(1){

        FD_ZERO(&reading_set);
        FD_SET(descriptorSnd, &reading_set);
        FD_SET(sockId, &reading_set);

        FD_ZERO(&writing_set);
        if(cbuf_has_block(circular_buf)){
            FD_SET(descriptorSnd, &writing_set);
        }

        if ((res = select (FD_SETSIZE, &reading_set, &writing_set, NULL, &silence_timer)) < 0) {
            printf("Select failed");
            exit(1);

        }else if(res == 0){
            if(check_write_cbuf(circular_buf, noise_pointer, requestedFragmentSize, &current_blocks, TIMER)){
				seqNum_timer++;
            }
        }else{

	       //print_playouts();

            if(FD_ISSET (descriptorSnd, &writing_set) == 1){
                play(descriptorSnd, cbuf_pointer_to_read (circular_buf), requestedFragmentSize, &current_blocks); //cambiar nombre de funcion y argumento cbuf_pointer_to_read por cbuf
            }

            if(FD_ISSET (descriptorSnd, &reading_set) == 1){

                hdr_message = (rtp_hdr_t *) buf_send;

                (*hdr_message).version = 2;
                (*hdr_message).p = 0;
                (*hdr_message).x = 0;
                (*hdr_message).cc = 0;
                (*hdr_message).m = 0;
                if(payload == PCMU){
					(*hdr_message).pt = 0;
				}else if(payload == L16_1){
					(*hdr_message).pt = 11;
				}
                (*hdr_message).ssrc = htonl(ssrc);
                (*hdr_message).seq = htons(nseq);
                (*hdr_message).ts = htonl(timeStamp);

                audioData = (char *)(hdr_message + 1);

                update_buffer(descriptorSnd, audioData, requestedFragmentSize);

                    if(sndCardFormat == S16_LE) hton_audio(audioData, requestedFragmentSize);
                    easy_send(buf_send, requestedFragmentSize + sizeof(rtp_hdr_t));
                    nseq = nseq + 1;
                    if(verbose){
						printf (".");fflush (stdout);
					}


				timeStamp = timeStamp + requestedFragmentSize;

            }

            if(FD_ISSET (sockId, &reading_set) == 1){

                update_buffer(sockId, buf_rcv, requestedFragmentSize + sizeof(rtp_hdr_t));

                hdr_message = (rtp_hdr_t *) buf_rcv;
		        seqNum_actual = ntohs((*hdr_message).seq);
                validate_packet((*hdr_message).ssrc, (*hdr_message).pt);

                audioData = (char *)(hdr_message + 1);
                if(sndCardFormat == S16_LE) ntoh_audio(audioData, requestedFragmentSize);

                if(seqNum_actual > seqNum_anterior && seqNum_actual > seqNum_timer){

                    K = seqNum_actual - seqNum_anterior;

                    if(K > 1) num_blocks_to_write = seqNum_actual - seqNum_timer;

                        if(K == 1){

                            check_write_cbuf(circular_buf, audioData, requestedFragmentSize, &current_blocks, INSERT);

                        }else{

                            if(verbose){
                                printf ("s");fflush (stdout);
                            }

                            if(K < 4 ){
                                    insert_repeated_packets(circular_buf, last_audioData, requestedFragmentSize, num_blocks_to_write, numberOfBlocks, &current_blocks, X);
                                    check_write_cbuf(circular_buf, audioData, requestedFragmentSize, &current_blocks, INSERT);
                                }else {
                                    insert_repeated_packets(circular_buf, noise_pointer, requestedFragmentSize, num_blocks_to_write, numberOfBlocks, &current_blocks, X);
                                    check_write_cbuf(circular_buf, audioData, requestedFragmentSize, &current_blocks, INSERT);
                                }

                        }

                        memcpy(last_audioData, audioData, requestedFragmentSize);

                    }else{
                    	if(verbose){
                            printf ("d");fflush (stdout);
                        }
                	}

                    seqNum_timer = seqNum_actual;
                    seqNum_anterior = seqNum_actual;

                }


        }

        reset_timer(descriptorSnd, rate, channelNumber, sndCardFormat, &silence_timer, current_blocks, requestedFragmentSize);

    }


};




void play(int descriptor, void *buffer, int size, unsigned int * current_blocks){
    int n_bytes;

    n_bytes = write (descriptor, buffer, size);
    if (n_bytes!= size){
        printf ("Different number of bytes ( %d bytes, expected %d)\n", n_bytes, size);
    }else{
        (*current_blocks)--;
        if(verbose){
					printf ("-");fflush (stdout);
				}
    }
}

void update_buffer(int descriptor, void *buffer, int size){
    int n_bytes;
    n_bytes = read (descriptor, buffer, size);
    if (n_bytes!= size) printf ("Different number of bytes ( %d bytes, expected %d)\n", n_bytes, size);

}

int ms2bytes(int duration, int rate, int channelNumber, int sndCardFormat){
    int numberOfSamples = (int) (((float) duration / MILI_PER_SEC) * (float) rate);
    int bytesPerSample = channelNumber * sndCardFormat / BITS_PER_BYTE;
    return numberOfSamples * bytesPerSample;
}


void reset_timer(int descriptorSnd, int rate, int channelNumber, int sndCardFormat, struct timeval* timer, unsigned int current_blocks, int requestedFragmentSize){

    int numBytes;
    int numberOfSamples;
    float bytesDuration;

    ioctl(descriptorSnd, SNDCTL_DSP_GETODELAY, &numBytes);
    numBytes = numBytes + current_blocks * requestedFragmentSize;
    numberOfSamples = numBytes / (channelNumber * sndCardFormat / BITS_PER_BYTE);
    bytesDuration = (float) numberOfSamples / (float) rate;
    bytesDuration = bytesDuration - 10 / MILI_PER_SEC;

    if(bytesDuration > 0){
        (*timer).tv_sec = (long) bytesDuration;
        (*timer).tv_usec = (long)((bytesDuration - (float) (*timer).tv_sec) * MILI_PER_SEC * MICRO_PER_MILI);
    }else{
        (*timer).tv_sec = 0;
        (*timer).tv_usec = 0;
    }

}


void insert_repeated_packets(void* circular_buf, void* buf, int requestedFragmentSize, unsigned int K, unsigned int numberOfBlocks, unsigned int * current_blocks, int verbose_c){

    unsigned int i;
    int inserted_block;

    if((numberOfBlocks - (*current_blocks)) == 1){
        return;
    }else if((numberOfBlocks - (*current_blocks)) < K){
        K = numberOfBlocks - (*current_blocks) - 1;
    }


    for(i=0; i<K; i++){
        inserted_block = check_write_cbuf(circular_buf, buf, requestedFragmentSize, current_blocks, verbose_c);
        if(inserted_block == 0){
            break;
        }
    }

}

void create_comfort_noise(void* noise_pointer, int fragmentSize, int sndCardFormat){

    int i;
    const void* noise_fragment;
    int size;

    if(sndCardFormat == U8){
        size = sizeof(uint8_t) * SIZE_NOISE;
        noise_fragment = NOISE_FRAGMENT_U8;
    }else if(sndCardFormat == S16_LE){
        size = sizeof(int16_t) * SIZE_NOISE;
        noise_fragment = NOISE_FRAGMENT_S16;
    }

    for(i=0; i<fragmentSize; i= i + size){
        memcpy(noise_pointer, noise_fragment, size);
        noise_pointer = noise_pointer + size;
    }


}

int check_write_cbuf(void* circular_buf, void* content_pointer, int size, unsigned int * current_blocks, int verbose_c){

    void* to_write_pointer = cbuf_pointer_to_write (circular_buf);
    int inserted_block = 0;

    if (to_write_pointer != NULL){
        memcpy(to_write_pointer, content_pointer, size);
        inserted_block = 1;
        (*current_blocks)++;

        if(verbose){
            if(verbose_c == INSERT){
                printf ("+");fflush (stdout);
            }else if(verbose_c == SILENCE){
                printf ("~");fflush (stdout);
            }else if(verbose_c == TIMER){
                printf ("t");fflush (stdout);
            }else if(verbose_c == X){
                printf ("x");fflush (stdout);
            }
        }


    }else{
        printf ("cbuf_lleno");fflush (stdout);
    }

    return inserted_block;
}

void hton_audio(void * audioData, int requestedFragmentSize){

    int i;
    int num_samples;
    int16_t* s16_pointer = (int16_t*) audioData;

    num_samples = requestedFragmentSize / sizeof(int16_t);
    for(i=0; i<num_samples; i= i + 1){
        s16_pointer[i] = htons(s16_pointer[i]);
    }

}

void ntoh_audio(void * audioData, int requestedFragmentSize){

    int i;
    int num_samples;
    int16_t* s16_pointer = (int16_t*) audioData;

    num_samples = requestedFragmentSize / sizeof(int16_t);
    for(i=0; i<num_samples; i= i + 1){
        s16_pointer[i] = ntohs(s16_pointer[i]);
    }

}

float get_diff_times(struct timeval* last_timeval){

    struct timeval current_timeval;
	struct timeval diff_times;
    float secs;
    float micro_secs;

    if (gettimeofday (&current_timeval, NULL) <0) { //cambiar para checkear posible error en gettimeofday
        printf("asdf\n");
    }

    timersub(&current_timeval, last_timeval, &diff_times);

    secs = (float) diff_times.tv_sec;
    micro_secs = ((float) diff_times.tv_usec) / (MILI_PER_SEC * MICRO_PER_MILI);

    return secs + micro_secs;

}

void print_playouts(){

    float actual_playout = get_diff_times(&first_packet_timeval);
    int numberOfSamples = (timeStamp_timer - first_timeStamp) / (channelNumber * sndCardFormat / BITS_PER_BYTE);
    float theoretical_playout = (float) numberOfSamples / (float) rate;

    printf(">>>> Actual playout duration = %f\n", actual_playout);
		printf(">>>>Theoretical playout duration = %f\n", theoretical_playout);
    printf(">>>> Difference between playouts = %f\n", actual_playout - theoretical_playout);
		printf("\n");
}

void terminar(){
	float actual_playout = get_diff_times(&first_packet_timeval);
	int numberOfSamples = (timeStamp_timer - first_timeStamp) / (channelNumber * sndCardFormat / BITS_PER_BYTE);
	float theoretical_playout = (float) numberOfSamples / (float) rate;

    printf ("\naudioc was requested to finish\n");
    if (buf_rcv) free(buf_rcv);
    if (buf_send) free(buf_send);
    if (fileName) free(fileName);
    if (circular_buf) cbuf_destroy_buffer (circular_buf);
    if (noise_pointer) free(noise_pointer);
    if (last_audioData) free(last_audioData);

    if(verbose){

       printf("Number of local silences = %d\n", local_silences);
       printf("Number of remote silences = %d\n", remote_silences);
       printf("Theoretical playout duration = %f\n", theoretical_playout);
       printf("Actual playout duration = %f\n", actual_playout);
       printf("Difference between playouts = %f\n", actual_playout - theoretical_playout);

    }

		exit (0);
}

void validate_packet(unsigned long int remote_ssrc, unsigned int remote_pt){

    if(ntohl(remote_ssrc) == ssrc){
		printf("Fallo igual SSRC\n");
        exit(0);

    }else{
        if(sndCardFormat == U8 && remote_pt != 0){
			printf("Fallo distinto Payload\n");
            exit(0);
        }else if(sndCardFormat == S16_LE && remote_pt !=11){
			printf("Fallo distinto Payload\n");
            exit(0);
        }
    }

}
