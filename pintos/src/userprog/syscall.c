#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/init.h"
#include "userprog/process.h"

#include "devices/input.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "lib/syscall-nr.h"

#define ONE_BYTE_MASK ( 0xFF )              /* Mask for keeping only the lower 8 bits       */

#define FD_STDIN  ( 0 )                     /* Standard Input                               */
#define FD_STDOUT ( 1 )                     /* Standard Output                              */
#define FD_STDERR ( 2 )                     /* Error message output                         */
#define FD_START  ( 3 )                     /* first number able to be used as a descriptor */

#define RET_ERROR ( -1 )                    /* Error return value                           */

#define STACK_ALIGNMENT_SINGLE ( 4 )        /* Alignment of first parameter on stack        */
#define STACK_ALIGNMENT_DOUBLE ( 8 )        /* Alignment of second parameter on stack       */
#define STACK_ALIGNMENT_TRIPLE ( 12 )       /* Alignment of third parameter on stack        */


static void syscall_handler (struct intr_frame *);

/******************** System call prototypes *********************/
void      syscall_close   ( int fd                                      );
int       syscall_filesize( int fd                                      );
int       syscall_open    ( const char * file                           );
int       syscall_read    ( int fd, void * buffer, unsigned size        );
void      syscall_seek    ( int fd, unsigned position                   );
unsigned  syscall_tell    ( int fd                                      );
int       syscall_write   ( int fd, const void * buffer, unsigned size  );
struct lock lock_file;

/******************** Helper function prototypes *************************/
static void               call_fail     ( void );
static void               check_user_mem( const uint8_t *addr );
static struct file_desc * find_file_dsc ( thread * thrd, int fd );
static int                read_usr_mem  ( void * src, void * dst, size_t byte_cnt );


/* Reads a byte at user virtual address UADDR.

   UADDR must be below PHYS_BASE. -1 is return if it is not

   Returns the byte value if successful, -1 if a segfault

   occurred. */

static int

get_user (const uint8_t *uaddr){

  int result;

  if( ( void * ) uaddr > PHYS_BASE )
  {
    result = RET_ERROR;
  }
  else
  {
    asm ("movl $1f, %0; movzbl %1, %0; 1:"       : "=&a" (result) : "m" (*uaddr));
  }
  return result;

} 

 

/* Writes BYTE to user address UDST.

   UDST must be below PHYS_BASE. -1 is returned if not

   Returns true if successful, false if a segfault occurred.

*/

static bool

put_user (uint8_t *udst, uint8_t byte){

  int error_code;
  if( ( void * ) udst > PHYS_BASE )
  {
    error_code = RET_ERROR;
  }
  else
  {
    asm ("movl $1f, %0; movb %b2, %1; 1:"       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  }
  return error_code != RET_ERROR;

}

static int read_usr_mem( void * src, void * dst, size_t byte_cnt )
{
  //We read one byte at a time, but our function to read one byte return an int

  int byte;
  size_t i;

  for( i = 0; i < byte_cnt; i++ )
  {
    byte = get_user( src + i );

    if( byte == RET_ERROR )
      call_fail();

    //Mask off anything above our lower byte
    byte &= ONE_BYTE_MASK;
    *( char * )( dst + i ) = byte;
  }
  return byte_cnt;
}



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f ) 
{
  int syscall_num;
  //May need to do some sanity asserty stuff for x86

  read_usr_mem( f->esp, &syscall_num, sizeof( syscall_num ) );

  switch (syscall_num)
  {
  case SYS_HALT:
    break;

  case SYS_EXIT:
    /* code */
    break;
  case SYS_EXEC:
    /* code */
    break;
  case SYS_WAIT:
    /* code */
    break;
  case SYS_CREATE:
    /* code */
    break;  
  case SYS_REMOVE:
    /* code */
    break;
  case SYS_OPEN:
    /* code */
    break;

  case SYS_FILESIZE:
  {
    int fd, ret_val;

    read_usr_mem( f->esp + STACK_ALIGNMENT_SINGLE, &fd, sizeof( fd ) );
    ret_val = syscall_filesize( fd );
    
    f->eax = ret_val;
    break;
  }
  case SYS_READ:
  {
    int fd, ret_val;
    void * buffer;
    unsigned size;

    read_usr_mem( f->esp + STACK_ALIGNMENT_SINGLE, &fd,     sizeof( fd )      );
    read_usr_mem( f->esp + STACK_ALIGNMENT_DOUBLE, &buffer, sizeof( buffer )  );
    read_usr_mem( f->esp + STACK_ALIGNMENT_TRIPLE, &size,   sizeof( size )    );

    ret_val = syscall_read( fd, buffer, size );

    f->eax = ret_val;
    break;
  }
  case SYS_WRITE:
  {
    int fd, ret_val;
    void * buffer;
    unsigned size;

    read_usr_mem( f->esp + STACK_ALIGNMENT_SINGLE, &fd,     sizeof( fd )      );
    read_usr_mem( f->esp + STACK_ALIGNMENT_DOUBLE, &buffer, sizeof( buffer )  );
    read_usr_mem( f->esp + STACK_ALIGNMENT_TRIPLE, &size,   sizeof( size )    );

    ret_val = syscall_write( fd, buffer, size );

    f->eax = ret_val;
    break;
  }
  case SYS_SEEK:
  {
    int fd;
    unsigned pos;

    read_usr_mem( f->esp + STACK_ALIGNMENT_SINGLE, &fd,     sizeof( fd )   );
    read_usr_mem( f->esp + STACK_ALIGNMENT_DOUBLE, &pos,    sizeof( pos )  );

    syscall_seek( fd, pos );
    break;  
  }
  case SYS_TELL:
  {
    int fd; 
    unsigned ret_val;

    read_usr_mem( f->esp + STACK_ALIGNMENT_SINGLE, &fd, sizeof( fd ) );
    ret_val = syscall_tell( fd );
    
    f->eax = ret_val;
    break;
  }
  case SYS_CLOSE:
  {
    int fd;

    read_usr_mem( f->esp + STACK_ALIGNMENT_SINGLE, &fd, sizeof( fd ) );
    syscall_close( fd );
    break;
  }
  default:
      printf ("Unknown Sytem Call!\n");
      thread_exit ();
    break;
  }

}
/**************************** Kelcie's Code now ********************/

/****************************** Helper functions *******************************/


/**********************************************************************
 * 
 * Procedure: check_user_mem
 * 
 * 
 *    Use: Releases locks and then returns and error
 * 
**********************************************************************/
static void call_fail( void )
{
  if( lock_held_by_current_thread( &lock_file ) )
    lock_release( &lock_file );

  //exit( RET_ERROR );
  thread_exit();
} 

/**********************************************************************
 * 
 * Procedure: check_user_mem
 * 
 * 
 *    Use: checks the provided address to verify it is within an
 *         acceptable memory space
 * 
**********************************************************************/
static void check_user_mem( const uint8_t *addr )
{
  if( get_user( addr ) == RET_ERROR )
    call_fail();
}

/**********************************************************************
 * 
 * Procedure: find_file_dsc
 * 
 * 
 *    Use: Finds the descriptor for the provided file number.
 *         Returns NULL if file is not opened for the thread
 * 
**********************************************************************/
static struct file_desc * find_file_dsc( thread * thrd, int fd )
{
  struct file_desc * ret_desc;
  ASSERT( thrd != NULL );

  if( fd < FD_START )
  {
    ret_desc = NULL;
  }

  struct list_elem * el;

  if( !list_empty( &thrd->file_descriptors ) )
  {
    for(  el = list_begin( &thrd->file_descriptors ); 
          el != list_end( &thrd->file_descriptors ); 
          el = list_next( el ) )
    {
      struct file_desc * fl_desc = list_entry( el, struct file_desc, elem );

      if( fl_desc->id == fd )
      {
        ret_desc = fl_desc;
      }
    }
  }
  return ret_desc;
}

/********************************* System Calls **********************************/


/**********************************************************************
 * 
 * Procedure: syscall_close
 * 
 * 
 *    Use: Closes a file specified by fd if it is open
 * 
**********************************************************************/
void syscall_close( int fd )
{
  lock_acquire( &lock_file );
  
  struct file_desc * file_info = find_file_dsc( thread_current(), fd );

  if( file_info )
  {
    if( file_info && file_info->file)
    {
      file_close( file_info->file );
    }
    list_remove( &( file_info->elem ) );
  }
  lock_release( &lock_file );
}

/**********************************************************************
 * 
 * Procedure: syscall_filesize
 * 
 * 
 *    Use: Returns the size of the file specified by fd
 * 
**********************************************************************/
int syscall_filesize( int fd )
{
  int ret_val = RET_ERROR;
  struct file_desc * file_info;

  lock_acquire( &lock_file );

  file_info = find_file_dsc( thread_current(), fd );

  if( file_info != NULL )
  {
    ret_val = file_length( file_info->file );
  }
  lock_release( &lock_file );

  return ret_val;
}

/*************************************************************************
 * 
 * Procedure: syscall_open
 * 
 * 
 *    Use: Opens the file and returns the fd
 * 
*************************************************************************/
int syscall_open( const char * file )
{
  check_user_mem( ( const uint8_t * ) file );

  struct file * opened_file;
  struct file_desc * file_info = palloc_get_page( 0 );

  /*-------------------------------------------------------------------
  Multiple return path Justification
    In the case we are not able to acquire a page, we would not want
    to do any further processing
  -------------------------------------------------------------------*/
  if( !file_info )
  {
    return RET_ERROR;
  }

  lock_acquire( &lock_file );

  opened_file = filesys_open( file );

  if( !opened_file )
  {
    palloc_free_page( file_info );
    lock_release( &lock_file );
    return RET_ERROR;
  }

  file_info ->file = opened_file;

  struct list * desc_list = &(thread_current()->file_descriptors);

  if( list_empty( desc_list ) )
  {
    file_info->id = FD_START;
  }
  else
  {
    file_info->id = ( list_entry( list_back( desc_list ), struct file_desc, elem)->id ) + 1;
  }

  //list_push_back( desc_list, &( file_info->elem ) );
  lock_release( &lock_file );

  return file_info->id;
}

/**********************************************************************
 * 
 * Procedure: syscall_read
 * 
 * 
 *    Use: Reads size amount of bytes from fd into the buffer. Number
 *         of bytes read is returened. 
 * 
**********************************************************************/
int syscall_read( int fd, void * buffer, unsigned size )
{
  //Verify the buffer is entire within correct memory space
  check_user_mem( ( const uint8_t* ) buffer );
  check_user_mem( ( const uint8_t* ) buffer + size - 1 );

  int ret_val = RET_ERROR;
  lock_acquire(&lock_file);

  if( fd == FD_STDIN )
  {
    unsigned byte_num;
    for( byte_num = 0; byte_num < size; byte_num++ )
      // put_user returns false if there is a seg fault
      if( !put_user( buffer + byte_num, input_getc() ) )
      {
        call_fail();
      }
    ret_val = size;
  }
  else{
    struct file_desc *  file_info = find_file_dsc( thread_current(), fd );

    //Only read from the file if the description was found. I.E. the file has been opened
    if( file_info && file_info->file )
    {
      ret_val = file_read( file_info->file, buffer, size );
    }
  }

  lock_release( &lock_file );
  return ret_val;

}

/*************************************************************************
 * 
 * Procedure: syscall_seek
 * 
 * 
 *    Use: Sets the current byte of the file fd to position
 * 
*************************************************************************/
void syscall_seek( int fd, unsigned position )
{
  lock_acquire( &lock_file );
  struct file_desc * file_info = find_file_dsc( thread_current(), fd );
  if( file_info && file_info->file )
  {
    file_seek( file_info->file, position );
  }
  lock_release( &lock_file );
}

/*************************************************************************
 * 
 * Procedure: syscall_tell
 * 
 * 
 *    Use: Returns the current byte of the file fd 
 * 
*************************************************************************/
unsigned syscall_tell( int fd )
{
  lock_acquire( &lock_file );
  int ret_val = RET_ERROR;

  struct file_desc * file_info = find_file_dsc( thread_current(), fd );
  if( file_info && file_info->file )
  {
    ret_val = file_tell( file_info->file );
  }

  lock_release( &lock_file );
  return ret_val;
}

/*************************************************************************
 * 
 * Procedure: syscall_write
 * 
 * 
 *    Use: Writes the size number of bytes from the buffer to the file
 *         fd
 * 
*************************************************************************/
int syscall_write( int fd, const void * buffer, unsigned size )
{
  /*-------------------------------------------------------------------
  Verify the buffer is completemy within expected memory
  -------------------------------------------------------------------*/
  check_user_mem( ( const uint8_t * ) buffer );
  check_user_mem( ( const uint8_t * ) buffer + size);

  lock_acquire( &lock_file );
  
  int ret_val = RET_ERROR;

  /*-------------------------------------------------------------------
  Print out to stdout
  -------------------------------------------------------------------*/
  if( fd == FD_STDOUT )
  {
    putbuf( buffer, size );
    ret_val = size;
  }
  else
  {
    /*-----------------------------------------------------------------
    Write to the file specified by fd if the file exists
    -----------------------------------------------------------------*/
    struct file_desc * file_info = find_file_dsc( thread_current(), fd );
    if( file_info && file_info->file )
    {
      ret_val = file_write( file_info->file, buffer, size );
    }
  } 
  lock_release( &lock_file );
  return ret_val;
}