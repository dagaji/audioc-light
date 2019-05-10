/* circularBuffer.c */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "circularBuffer.h"


void *cbuf_create_buffer (int numberOfBlocks, int blockSize)
{
    void *buffer;
    int *pointerToInt;

    /* Reserve space for 5 integers at the beginning, to store 
       - number of blocks of the buffer
       - size of each block
       - index (0 to [numberOfBlocks - 1]) pointing to the first spare block
       - index pointing to the first full block
       - number of filled blocks  */

    if ( (buffer= malloc (numberOfBlocks * blockSize  + 5 * sizeof (int)) )== NULL) 
    {
        printf ("Error reserving memory in circularBuffer\n");
        return (NULL);
    }


    /* initiallizing structure */
    pointerToInt = (int *) buffer;
    *(pointerToInt ) = numberOfBlocks;
    *(pointerToInt + 1) = blockSize;
    *(pointerToInt + 2) = 0; 
    *(pointerToInt + 3) = 0; 
    *(pointerToInt + 4) = 0; 

    return buffer;
}


void *cbuf_pointer_to_write(void * buffer)
{
    int *ptrNextFreeBlock, *ptrBlockNumber, *ptrBlockSize; 
    int *ptrFullBlockNmb;
    int *returnPtr;

    ptrBlockNumber = (int *) buffer;
    ptrBlockSize = (int *) (buffer + 1 * sizeof (int));
    ptrNextFreeBlock = (int *) (buffer + 2 * sizeof (int));
    /* ptrNextFullBlock is not used */
    ptrFullBlockNmb = (int *) (buffer + 4 * sizeof (int));

    returnPtr = buffer + 5 * sizeof (int) + (* ptrNextFreeBlock) * (* ptrBlockSize);

    if ( (*ptrFullBlockNmb) == (* ptrBlockNumber) )
    { /* buffer is full*/
        return (NULL);
    } else { /* normal condition  */
        (* ptrNextFreeBlock) = ((* ptrNextFreeBlock) + 1) % (* ptrBlockNumber);  /* updates free block state */
        (*ptrFullBlockNmb) = (*ptrFullBlockNmb) + 1;
        return (returnPtr);
    }
};


int cbuf_has_block (void *buffer)
{
    int *ptrFullBlockNmb;
    ptrFullBlockNmb = (int *) (buffer + 4 * sizeof (int));

    if ( (*ptrFullBlockNmb) == 0)
    { /* circular buffer is empty */
        return (0);
    }
    else return (1);
}


void *cbuf_pointer_to_read(void *buffer)
{
    int *ptrNextFullBlock, *ptrBlockNumber, *ptrBlockSize; 
    int *ptrFullBlockNmb;
    int *returnPtr;

    ptrBlockNumber = (int *) buffer;
    ptrBlockSize = (int *) (buffer + 1 * sizeof (int));
    /* ptrNextFreeBlock is not used */
    ptrNextFullBlock = (int *) (buffer + 3 * sizeof (int));
    ptrFullBlockNmb = (int *) (buffer + 4 * sizeof (int));

    returnPtr = buffer + 5 * sizeof (int) + (* ptrNextFullBlock) * (* ptrBlockSize);

    if ( (*ptrFullBlockNmb) == 0)
    { /* circular buffer is empty */
        return (NULL);
    }
    else
    { /* normal condition */
        (* ptrNextFullBlock) = ((*ptrNextFullBlock) + 1) % (* ptrBlockNumber); 
        (*ptrFullBlockNmb) = (*ptrFullBlockNmb) - 1;
        return (returnPtr);
    }
}


void cbuf_destroy_buffer (void *buffer)
{
    free (buffer);
}


/* TEST vectors for cbuf functions. 
 * To execute them, use following code  */

/* #include "circularBuffer.h" 
void _cbuf_test_buffer(void);  
void main (void) 
{
    _cbuf_test_buffer();
} */


void _cbuf_test_buffer(void) 
{
    typedef void *FUNC(void *);
    enum test_vector_pos {FUNC_NAME, RETURN, DATA, HAS}; /* Test vector components */
    enum function_names {POINTER_WRITE, POINTER_READ, POINTER_HAS};
    FUNC *func_ptr[2] = {cbuf_pointer_to_write, cbuf_pointer_to_read};
    /* So that 'func_ptr[POINTER_WRITE]' is the cbuf_pointer_to_write() function */
    
    
    int buffer_blocks = 5; /* test_vector1 assumes that buffer_blocks=5 */
    int test_vector1[][4] = {
        /* Each liºne contains 
         *  Function to execute (POINTER_READ, POINTER_WRITE), 
         *  Expected pointer returned (0=NULL, 1=not null), 
         *  Integer to write/read (when read, it is checked)
         *  Has_result check (0 no block in buffer; 1, block in buffer*/
        {POINTER_READ,  0, 1, 0}, /* buffer empty */
        {POINTER_READ,  0, 1, 0}, /* buffer empty */
        {POINTER_WRITE, 1, 1, 1}, 
        {POINTER_READ,  1, 1, 0},
        {POINTER_READ,  0, 1, 0}, /* buffer empty */
        {POINTER_READ,  0, 1, 0}, /* buffer empty */
        {POINTER_WRITE, 1, 2, 1},
        {POINTER_WRITE, 1, 3, 1},
        {POINTER_WRITE, 1, 4, 1},
        {POINTER_READ,  1, 2, 1},
        {POINTER_WRITE, 1, 5, 1},
        {POINTER_READ,  1, 3, 1},
        {POINTER_READ,  1, 4, 1},
        {POINTER_READ,  1, 5, 0},
        {POINTER_WRITE, 1, 6, 1},
        {POINTER_WRITE, 1, 7, 1},
        {POINTER_WRITE, 1, 8, 1},
        {POINTER_WRITE, 1, 9, 1},
        {POINTER_WRITE, 1, 10, 1},
        {POINTER_WRITE, 0, 11, 1}, /* buffer full */
        {POINTER_WRITE, 0, 12, 1}, /* buffer full */
        {POINTER_READ, 1, 6, 1},
        /* you can add more tests here */
    };


    int expected_result;
    void *buffer;
    int *data_pointer;
    buffer = cbuf_create_buffer(buffer_blocks, sizeof(int));

    int tests = sizeof(test_vector1)/(4*sizeof(int)); /* number of tests in test_vector1) */

    int test; /* current test number */    
    for (test=0; test < tests; test++) {

        /* check if return data is NULL or not - as expected */
        data_pointer = (int *) func_ptr[test_vector1[test][FUNC_NAME]](buffer);
        if (test_vector1[test][RETURN] == 0) {
            /* expect NULL return */
            if (data_pointer != NULL) {
                printf("_cbuf_test_buffer RETURN error at test number %d\n", test);
                cbuf_destroy_buffer(buffer);
                exit(1);
            }
        } else {
            /* expect non-NULL return */
            if (data_pointer == NULL) {
                printf("_cbuf_test_buffer RETURN error at test number %d\n", test);
                cbuf_destroy_buffer(buffer);
                exit(1);
            }
        }

        /* write/read data test */
        if (data_pointer && test_vector1[test][FUNC_NAME] == POINTER_WRITE) {
            *data_pointer = test_vector1[test][DATA];
        }
        if (data_pointer && test_vector1[test][FUNC_NAME] == POINTER_READ) {
            if (*data_pointer != test_vector1[test][DATA]) {
                printf("_cbuf_test_buffer DATA error at test number %d\n; expected %d, returned %d", test, test_vector1[test][DATA], *data_pointer);
                cbuf_destroy_buffer(buffer);
                exit(1);
            }
        }

        /* test cbuf_has_block function */
        if (cbuf_has_block(buffer) != test_vector1[test][HAS]) {
            printf("_cbuf_test_buffer HAS_BLOCK error at test number %d\n", test);
            cbuf_destroy_buffer(buffer);
            exit(1);
        }
    }
    cbuf_destroy_buffer(buffer);

    printf("Tests PASSED (number of tests: %d)\n", tests);
}
