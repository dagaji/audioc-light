/*******************************************************/
/* configureSndcard.h */
/*******************************************************/

#ifndef SOUND_H
#define SOUND_H

enum formats {
    U8 = 8,         /* unsigned 8 bits */ 
    S16_LE = 16     /* signed 16 bits, little endian */
};


/* This function changes the configuration for the descSnd provided to the parameters 
 * stated in dataSndQuality. 
 * If an error is found in the configuration of the soundcard, the process is stopped 
 * and an error message reported.
 * It alwasy opens the sound card, and return the corresponding soundcard descriptor */
void configSndcard (int *descSnd, /* Returns number of soundcard descriptor */
        int *sndCardFormat,     /* Returns format to be used by the soundcard, 
                                   see 'enum formats'*/
        int *channelNumber,     /* Returns number of channels, 1 or 2 */
        int *rate,              /* Returns sampling rate, Hz */
	int *fragmentSize       /* Receives the requested fragment size in bytes.
                                   Returns the actual fragment size (always a power of 2 
                                   value equal or lower to the requested value) */
	);

/* configures volume for descSnd. 
 * If it is stereo, it configures both channels. 
 * The function returns the volume actually configured in the device after performing 
 * the operation (could be different than requested).
 * If an error is found in the configuration of the soundcard, the process is stopped 
 * and an error message reported. */
int configVol (int stereo, int descSnd, int vol); /* */

/* prints fragment size configured for sndcard */
void printFragmentSize (int descriptorSnd);

#endif /* SOUND_H */


