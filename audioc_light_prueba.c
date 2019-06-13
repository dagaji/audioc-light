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
#include "rtp.h"

int escribir_en_cbuf(void* circular_buf, void* src_ptr, int size);
void liberar_recursos();
int crear_socket(struct in_addr multicastIp, struct sockaddr_in * remToSendSAddr, unsigned short int destination_port);
int escribir_en_socket(int descriptor_socket, struct sockaddr_in * remToSendSAddr ,void * message, int size);
int leer_de_socket(int descriptor_socket, char * buff, int size);
void verbose_print(int verbose, char *codigo);
int pasar_a_bytes(int duration, int rate);


const int BITS_POR_BYTE = 8;
const float MILI_POR_SEC = 1000.0;
const float MICRO_POR_SEC = 1000.0 * 1000.0;

const int16_t FRAGMENTO_SILENCIO[] = {12,5,-10,-2,-10,5,2,9,4,24,7,5,-9,-13,0,1};


/* only declare here variables which are used inside the signal handler */
void *ptr_recibir = NULL;
void *ptr_enviar = NULL;
void *circular_buf = NULL;
void *ptr_ultimo_audio = NULL;
void *ptr_silencio = NULL;


/* activated by Ctrl-C */
void signalHandler (int sigNum __attribute__ ((unused)))  /* __attribute__ ((unused))   -> this indicates gcc not to show an 'unused parameter' warning about sigNum: is not used, but the function must be declared with this parameter */
{
  liberar_recursos();
}


void main(int argc, char *argv[])
{
struct sigaction sigInfo; /* signal conf */
int descriptor_snd;
int num_bytes_fragmento;
int port;
int vol;
int duracion_fragmento;
int payload;
int duracion_buffering;
int num_bloques_cbuf;
fd_set reading_set, writing_set;
int descriptor_socket;
struct in_addr multicastIp;
int res;
int buffering = 1;
unsigned int nseq = 0;
unsigned long int timeStamp = 0;
unsigned int nseq_rcv_anterior = 0;
unsigned int nseq_rcv_actual = 0;
unsigned int nseq_timer = 0;
rtp_hdr_t * ptr_cabecera = NULL;
unsigned int diff_nseq= 0;
unsigned int bloques_en_cbuf = 0;
unsigned int num_muestras_fragmento;
int16_t* ptr_audio = NULL;
struct timeval timer;
int rate;
int verbose;
unsigned long int ssrc = 0;

/* we configure the signal */
sigInfo.sa_handler = signalHandler;
sigInfo.sa_flags = 0;
sigemptyset(&sigInfo.sa_mask); 
if ((sigaction (SIGINT, &sigInfo, NULL)) < 0) {
  printf("Error installing signal, error: %s", strerror(errno));
  exit(1);
}


/* obtain values from the command line - or default values otherwise */
if (-1 == args_capture_audioc(argc, argv, &multicastIp, &ssrc,
                              &port, &vol, &duracion_fragmento, &verbose, &payload, &duracion_buffering))
{ exit(1);  /* there was an error parsing the arguments, the error type
 is printed by the args_capture function */
};

int channelNumber = 1;
int sndCardFormat;

if(payload == L16_1){
  rate = 44100;
  sndCardFormat = S16_LE;
}else{
  printf("Formato no valido");
  liberar_recursos();
}

num_bytes_fragmento = pasar_a_bytes(duracion_fragmento, rate);

/* create snd descritor and configure soundcard to given format, rate, number of channels.
 
 * Also configures fragment size */
configSndcard (&descriptor_snd, &sndCardFormat, &channelNumber, &rate, &num_bytes_fragmento);

num_bloques_cbuf = pasar_a_bytes(duracion_buffering + 200, rate) / num_bytes_fragmento;
printf("num_bloques_cbuf: %d\n", num_bloques_cbuf);

vol = configVol (channelNumber, descriptor_snd, vol);

args_print_audioc(multicastIp, ssrc, port, duracion_fragmento, payload, duracion_buffering, vol, verbose);
printFragmentSize (descriptor_snd);
printf ("Duration of each packet exchanged with the soundcard :%f\n", (float) num_bytes_fragmento / (float) (channelNumber * sndCardFormat / BITS_POR_BYTE) / (float) rate);

num_muestras_fragmento = (int)((float) num_bytes_fragmento / (float) (channelNumber * sndCardFormat / BITS_POR_BYTE));


/****************************************/

ptr_recibir = malloc (num_bytes_fragmento + sizeof(rtp_hdr_t));
if (ptr_recibir == NULL) {
  printf("Could not reserve memory for ptr_recibir.\n");
  exit (1); /* very unusual case */
}

ptr_enviar = malloc (num_bytes_fragmento + sizeof(rtp_hdr_t));
if (ptr_enviar == NULL) {
  printf("Could not reserve memory for ptr_enviar.\n");
  exit (1); /* very unusual case */
}
struct sockaddr_in remToSendSAddr;
if((descriptor_socket = crear_socket(multicastIp, &remToSendSAddr, (unsigned short int)port)) < 0){
  printf("Could not initialize socket.\n");
  exit(1);
}

circular_buf = cbuf_create_buffer(num_bloques_cbuf, num_bytes_fragmento);

ptr_silencio = malloc (num_bytes_fragmento);
if (ptr_enviar == NULL) {
  printf("Could not reserve memory for comfort noise.\n");
  exit (1); /* very unusual case */
}

{
  int size = sizeof(int16_t) * 16;
  int i;
  for(i=0; i<num_bytes_fragmento; i= i + size){
  memcpy(ptr_silencio, FRAGMENTO_SILENCIO, size);
  ptr_silencio = ptr_silencio + size;
  }
}


ptr_ultimo_audio = malloc (num_bytes_fragmento);
if (ptr_ultimo_audio == NULL) {
  printf("Could not reserve memory for ptr_ultimo_audio.\n");
  exit (1); /* very unusual case */
}

while(1){
  
  FD_ZERO(&reading_set);
  FD_SET(descriptor_snd, &reading_set);
  FD_SET(descriptor_socket, &reading_set);
  
  FD_ZERO(&writing_set);
  if(cbuf_has_block(circular_buf) && !buffering){
    FD_SET(descriptor_snd, &writing_set);
  }
  
  if ((res = select (FD_SETSIZE, &reading_set, &writing_set, NULL, (buffering) ?  NULL : &timer)) < 0) {
    printf("Select failed");
    exit(1);
    
  }else if(res == 0){
    if(escribir_en_cbuf(circular_buf, ptr_silencio, num_bytes_fragmento)){
      bloques_en_cbuf++;
      nseq_timer++;
      verbose_print(verbose, "t");
    }
  }else{
    
    //print_playouts();
    
    if(FD_ISSET (descriptor_snd, &writing_set) == 1){
      
      void* ptr_leer_cbuf = cbuf_pointer_to_read (circular_buf);
      write (descriptor_snd, ptr_leer_cbuf, num_bytes_fragmento);
      bloques_en_cbuf--;
      verbose_print(verbose, "-");
    }
    
    if(FD_ISSET (descriptor_snd, &reading_set) == 1){
      
      ptr_cabecera = (rtp_hdr_t *) ptr_enviar;// puntero cabecera 
      
      (*ptr_cabecera).version = 2;
      (*ptr_cabecera).m = 0;
      (*ptr_cabecera).x = 0;
      (*ptr_cabecera).p = 0;
      (*ptr_cabecera).cc = 0;
      (*ptr_cabecera).pt = 11;
      (*ptr_cabecera).ssrc = htonl(ssrc);
      (*ptr_cabecera).ts = htonl(timeStamp);
      (*ptr_cabecera).seq = htons(nseq);
      
      read (descriptor_snd, (void*)(ptr_cabecera + 1), num_bytes_fragmento);
      ptr_audio = (int16_t*) (ptr_cabecera + 1);
      {
        int i;
        for(i=0; i<num_bytes_fragmento; i++){
        *(ptr_audio + i) = htons(*(ptr_audio + i));
        }
      }
      
      int _n = 3;
      if ((nseq < 50) || (nseq % _n == 0)){
        escribir_en_socket(descriptor_socket, &remToSendSAddr, ptr_enviar, num_bytes_fragmento + sizeof(rtp_hdr_t));
      }

      nseq++;
      timeStamp += num_muestras_fragmento;
  
      verbose_print(verbose, ".");
      
    }
    
    if(FD_ISSET (descriptor_socket, &reading_set) == 1){
      
      
      leer_de_socket(descriptor_socket, ptr_recibir, num_bytes_fragmento + sizeof(rtp_hdr_t));
      
      ptr_cabecera = (rtp_hdr_t *) ptr_recibir;
      nseq_rcv_actual = ntohs((*ptr_cabecera).seq);
      
      if(ntohl((*ptr_cabecera).ssrc) == ssrc){
        printf("Fallo igual SSRC\n");
        liberar_recursos();
      }else if((*ptr_cabecera).pt != 11){
        printf("Fallo distinto Payload\n");
        liberar_recursos();
      }
      
      ptr_audio = (int16_t*)(ptr_cabecera + 1);
      {
        int i;
        for(i=0; i<num_bytes_fragmento; i++){
        *(ptr_audio + i) = ntohs(*(ptr_audio + i));
        }
      }

      if(buffering){

        escribir_en_cbuf(circular_buf, ptr_audio, num_bytes_fragmento);
        bloques_en_cbuf++;
        verbose_print(verbose, "+");
        memcpy(ptr_ultimo_audio, ptr_audio, num_bytes_fragmento);

      }else if(nseq_rcv_actual > nseq_rcv_anterior && nseq_rcv_actual > nseq_timer){
        
        diff_nseq = nseq_rcv_actual - nseq_rcv_anterior;
        
        if(diff_nseq > 1){

          verbose_print(verbose, "s");
          
          void * aux_buf = (diff_nseq < 4) ?  ptr_ultimo_audio : ptr_silencio;
          int num_repetidos = nseq_rcv_actual - nseq_timer - 1;
          {
            int i;
            for(i=0; i<num_repetidos; i++){
              if(!escribir_en_cbuf(circular_buf, aux_buf, num_bytes_fragmento)) break;
              bloques_en_cbuf++;
              verbose_print(verbose, "x");
            }
          } 
        }
        
        escribir_en_cbuf(circular_buf, ptr_audio, num_bytes_fragmento);
        bloques_en_cbuf++;
        verbose_print(verbose, "+");
        memcpy(ptr_ultimo_audio, ptr_audio, num_bytes_fragmento);
        
      }else{
         verbose_print(verbose, "d");
      }
      
      nseq_timer = nseq_rcv_actual;
      nseq_rcv_anterior = nseq_rcv_actual;
      
    }
    
  }

  if (buffering){
    buffering = (bloques_en_cbuf < num_bloques_cbuf);
  }else{
    
      int bytes_en_snd;
      int muestras_en_snd;
      float playout_en_snd;
      
      ioctl(descriptor_snd, SNDCTL_DSP_GETODELAY, &bytes_en_snd);
      muestras_en_snd = (bytes_en_snd + bloques_en_cbuf * num_bytes_fragmento) / sizeof(int16_t);
      playout_en_snd = ((float) muestras_en_snd / (float) rate);
      
      if(playout_en_snd < 10 / MILI_POR_SEC){
        timer.tv_sec = 0;
        timer.tv_usec = 0;
      }else{
        playout_en_snd -= 10 / MILI_POR_SEC;
        timer.tv_sec = (long) playout_en_snd;
        timer.tv_usec = (long)((playout_en_snd - (float) timer.tv_sec) * MICRO_POR_SEC);
        
      }
    
  }
  
}

};


int pasar_a_bytes(int duration, int rate){
  int muestras_en_snd = (int) (((float) duration / MILI_POR_SEC) * (float) rate);
  return muestras_en_snd * sizeof(int16_t);
}


int escribir_en_cbuf(void* circular_buf, void* src_ptr, int size){
  
  void* to_write_pointer = cbuf_pointer_to_write (circular_buf);
  
  if (to_write_pointer != NULL){
    memcpy(to_write_pointer, src_ptr, size);
    return 1;
  }
  return 0;
  
}

int crear_socket(struct in_addr multicastIp, struct sockaddr_in * remToSendSAddr, unsigned short int destination_port){
  /* preparing bind */
  // bzero(&localSAddr, sizeof(localSAddr));
  // localSAddr.sin_family = AF_INET;
  // localSAddr.sin_port = htons(port); /* besides filtering, this assures that info is being sent with this port as local port */
  // multicastAddr.sin_addr = multicastIp;
  // /* fill .sin_addr with multicast address */
  // if (inet_pton(AF_INET, GROUP, &localSAddr.sin_addr) < 0) {
  //     printf("inet_pton error\n");
  //     return -1;
  // }
  
  bzero(remToSendSAddr, sizeof(struct sockaddr_in));
  (*remToSendSAddr).sin_family = AF_INET;
  (*remToSendSAddr).sin_port = htons(destination_port);
  (*remToSendSAddr).sin_addr = multicastIp;
  
  // if (inet_pton(AF_INET, GROUP, &remToSendSAddr.sin_addr) < 0) {
  //     printf("inet_pton error\n");
  //     return -1; /* failure */
  // }
  
  int descriptor_socket;
  /* creating socket */
  if ((descriptor_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    printf("socket error\n");
    return -1;
  }
  
  /* configure SO_REUSEADDR, multiple instances can bind to the same multicast address/port */
  int enable = 1;
  if (setsockopt(descriptor_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    printf("setsockopt(SO_REUSEADDR) failed");
    return -1;
  }
  
  /* binding socket - using mcast localSAddr address */
  if (bind(descriptor_socket, (struct sockaddr *)remToSendSAddr, sizeof(struct sockaddr_in)) < 0) {
    printf("bind error\n");
    return -1;
  }
  
  /* setsockopt configuration for joining to mcast group */
  struct ip_mreq mreq;
  mreq.imr_multiaddr = multicastIp;
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  // if (inet_pton(AF_INET, GROUP, &mreq.imr_multiaddr) < 0) {
  //     printf("inet_pton");
  //     return -1;
  // }
  
  
  if (setsockopt(descriptor_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
    printf("setsockopt error");
    return -1;
  }
  
  /* building structure to identify address/port of the remote node in order to send data to it */
  
  
  unsigned char loop=0;
  
  setsockopt(descriptor_socket, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(unsigned char));
  
  return descriptor_socket;
  
}
int escribir_en_socket(int descriptor_socket, struct sockaddr_in * remToSendSAddr ,void * message, int size){
  
  /* Using sendto to send information. Since I've made a bind to the socket, the localSAddr (source) port of the packet is fixed.
   In the remoteSAddr structure I have the address and port of the remote host, as returned by recvfrom */
  /* Using sendto to send information. Since I've bind the socket, the local (source) port of the packet is fixed. In the rem structure I set the remote (destination) address and port */
  int result;
  if ( (result = sendto(descriptor_socket, message, size, /* flags */ 0, (struct sockaddr *) remToSendSAddr, sizeof(*remToSendSAddr)))<0) {
    printf("%d\n",sizeof(*remToSendSAddr));
    printf("sendto error\n");
  }
  
  return result;
  
}


int leer_de_socket(int descriptor_socket, char * buff, int size){
  socklen_t sockAddrInLength = sizeof (struct sockaddr_in); /* remember always to set the size of the rem variable in from_len */
  struct sockaddr_in remToRecvSAddr;
  int result;
  
  if ((result = recvfrom(descriptor_socket, buff, size, 0, (struct sockaddr *) &remToRecvSAddr, &sockAddrInLength)) < 0) {
    printf ("recvfrom error\n");
  } else {
    buff[result] = 0; /* convert to 'string' by appending a 0 value (equal to '\0') after the last received character */
  //printf("Message received from group\nMessage is: %s\n", buff); fflush (stdout);
  }
  
  return result;
  
}

void liberar_recursos(){
  
  if (ptr_recibir) free(ptr_recibir);
  if (ptr_enviar) free(ptr_enviar);
  if (circular_buf) cbuf_destroy_buffer (circular_buf);
  if (ptr_silencio) free(ptr_silencio);
  if (ptr_ultimo_audio) free(ptr_ultimo_audio);
  
  exit (0);
}

void verbose_print(int verbose, char *codigo){
  if (verbose) printf("%s", codigo);fflush (stdout);
}