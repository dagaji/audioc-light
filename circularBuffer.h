/* circularBuffer.h */

/* Manages a circular buffer.
 * Restrictions
 * - Use only in single-process code, such as one managing concurrency by select.
 *   (do not use it in a multithreaded or multiprocess environment.
 *
 * However, it allows many buffers to exist at the same time.
 */


#ifndef CIRCULAR_BUFFER_H
#define CIRCULAR_BUFFER_H


/* Returns a pointer which represents the circular buffer, to be used by the 
 * rest of functions. This function ALLOCATES the memory used by the circular buffer.
 * cbuf_create_buffer(3, 4); -> creates a buffer with 3 blocks, 4 bytes each.
 * On error, memory could not be allocated, returns NULL. 
 */
void *cbuf_create_buffer (
        int numberOfBlocks, 
        int blockSize           /* size in bytes of each block */
        );


/* Takes buffer pointer created by cbuf_create_buffer.
 * Returns a pointer to the first ("empty") available block to write on it, 
 * or NULL if there are no blocks (be sure that this 
 * case is considered in your code!). 
 * Moves pointer after operation to point to the NEXT empty block. */
void *cbuf_pointer_to_write (void *buffer);


/* Takes buffer pointer created by cbuf_create_buffer.
 * Returns a pointer to the first available block to be read, 
 * or NULL if there are no blocks (be sure that this case is considered in 
 * your code!). 
 * Moves pointer after operation to point to the NEXT block with data. */
void *cbuf_pointer_to_read (void *buffer);


/* Checks if there is any available data (to be read) in the buffer. 
 * Returns 1 if there is at least one available block, 0 otherwise.
 * It DOES NOT move the pointer to the next block; to read the data 
 * and move the pointer, use cbuf_pointer_to_read(). */
int cbuf_has_block (void *buffer);


/* Frees memory of the buffer. 
 * Must be executed before exiting from the process */
void cbuf_destroy_buffer (void *buffer);

#endif /* CIRCULAR_BUFFER_H */
