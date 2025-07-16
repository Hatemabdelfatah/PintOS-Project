#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "pagedir.h"
#include "process.h"

#include "filesys/filesys.h"      

#include "threads/synch.h"    
struct lock file_lock;       
          



static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  lock_init(&file_lock);        
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}



static void
syscall_handler (struct intr_frame *f UNUSED) 
{
    //getting system call code 
    int syscall_code;

    validate_user_range((const void *) f->esp,sizeof(int));
    syscall_code = *(int*)f->esp;
    
    
    int args[3];
    if(!pull_args(syscall_code, f->esp, &args[0]))exit(-1);
    

    switch (syscall_code) {
        case SYS_HALT:
        // Halt the operating system.
        halt();
        break;

        case SYS_EXIT:
        // Terminate this process.
        exit((int)args[0]);
        break;

        case SYS_EXEC:{
            // Start another process.
            const char * cmd_line =(const char *) args[0]; 
            validate_string(cmd_line); 
            f->eax = exec(cmd_line); //store the result in eax
            break;
        }

        case SYS_WAIT:{
        // Wait for a child process to die.
        int exit_status = wait((pid_t)args[0]);
        f->eax = exit_status;
        break;
        }

        case SYS_CREATE: {
            const char *file = (const char *)args[0];  // Get the file path from args
            unsigned initial_size = (unsigned)args[1]; // Get the initial size of the file
            validate_string(file);
            lock_acquire(&file_lock);  // Acquire the file lock to avoid race conditions
            bool success = filesys_create(file, initial_size);  // Call the create function
            lock_release(&file_lock);  // Release the file lock
        
            f->eax = success;  // Return the success/failure result to the user
            break;
        }

        case SYS_REMOVE: {
            const char *file = (const char *)args[0];
            validate_string(file);
            lock_acquire(&file_lock);
            bool success = filesys_remove(file);
            lock_release(&file_lock);
            f->eax = success;
            break;
        }

        case SYS_OPEN:{
            // Open a file.
		    char *file_name = (char *) args[0];
            validate_string(file_name);
            //check if the file doesnot exist
            if (file_name == NULL) 
            exit(-1);     
		        f->eax = sys_open(file_name);
            break;
        }

        case SYS_FILESIZE:{
            // Obtain a file's size.
            int fd = (int) args[0];
		        f->eax = file_size(fd);
            break;
        }

        case SYS_READ:{
        // Read from a file.

            int fd = (int) args[0];;
            void *buffer = (const void*) args[1];
            int size = (unsigned) args[2];
            validate_user_range(buffer, size);
            f->eax = sys_read(fd, buffer, size);
            break;
        }

        case SYS_WRITE:{
      
            int fd = (int) args[0];
            void *buffer = (const void*) args[1];
            int size = (unsigned) args[2];
            if(buffer==NULL) exit(-1);
            validate_user_range(buffer, size);
            f->eax = sys_write(fd, buffer, size);
            break;
        }
        case SYS_SEEK:{
            int fd = (int) args[0];
            int pos = (unsigned) args[1];
            sys_seek(fd, pos);
            break;
        }    
        case SYS_TELL:{
            int fd = (int) args[0];
            f->eax = sys_tell(fd);
            break;
        }

        case SYS_CLOSE: {
            int fd = args[0];  // Get the file descriptor
            struct open_file *my_file = get_file(fd);
            if (my_file == NULL) return;
        	lock_acquire(&file_lock);
  			file_close(my_file->ptr);
  			lock_release(&file_lock);
  			list_remove(&my_file->elem);
 		 	palloc_free_page(my_file);
            break;
        }

        default:
        // Unknown system call
        break;
        }
    }

void halt(){
    shutdown_power_off();
}


bool pull_args(int syscall_code , int esp ,int *args){
    int* usr_ptr =  (int*) esp;
    int args_count = get_args_count(syscall_code); // get number of arguments 
    
    if(args_count < 0)return false;
    if(!is_valid_ptr(usr_ptr))return false; //validate user stack pointer
    
    //get arguments 
    for (int i = 0; i < args_count; i++)
    {
        int* arg_ptr =(int*) usr_ptr+1+i; 

        validate_user_range(arg_ptr , sizeof(int));
        args[i]= *arg_ptr;
    }
    
    return true;
}

int get_args_count(int syscall_code ){
    switch (syscall_code) {
        case SYS_HALT:    /* void halt(void) */
            return 0;

        case SYS_EXIT:     /* void exit(int status) */
        case SYS_EXEC:     /* pid_t exec(const char *cmd_line) */
        case SYS_WAIT:     /* int wait(pid_t pid) */
        case SYS_REMOVE:   /* bool remove(const char *file) */
        case SYS_OPEN:     /* int open(const char *file) */
        case SYS_FILESIZE: /* int filesize(int fd) */
        case SYS_TELL:     /* unsigned tell(int fd) */
        case SYS_CLOSE:    /* void close(int fd) */
            return 1;

        case SYS_CREATE:   /* bool create(const char *file, unsigned initial_size) */
        case SYS_SEEK:     /* void seek(int fd, unsigned position) */
            return 2;

        case SYS_READ:     /* int read(int fd, void *buffer, unsigned size) */
        case SYS_WRITE:    /* int write(int fd, const void *buffer, unsigned size) */
            return 3;

        default:
            return -1;     /* Invalid system call number */
    }
}

/*validate each address byte in range start->size*/
void validate_user_range(const void *start, size_t size) {
  uint8_t *p = start;
  for (size_t i = 0; i < size; i++) {
    if (!is_valid_ptr(p + i)) {
      exit(-1);  // Kill the process safely
    }
  }
}

/*validate each character address in a string*/
void validate_string(const char *str) {
    if (str == NULL || str == '\0')
        exit(-1);
    //for each byte
    for (; ; str++) {
        //validate byte
         if (!is_valid_ptr(str))exit(-1);
        if (*str == '\0')
            return;
    }
}

/*validate is pointer in user vritual space*/
bool is_valid_ptr(const void * ptr){
    return (ptr != NULL && ptr > USER_VADDR_BOTTOM_LIMIT && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) != NULL); 
}

int sys_open(char *file_name){	

    //try to allocates memeory for open_file struct 
    struct open_file* openFile = palloc_get_page(0);
    if (openFile == NULL) 
    {
      palloc_free_page(openFile);
      return -1;
    }
  
    lock_acquire(&file_lock);
    openFile->ptr = filesys_open(file_name);
    lock_release(&file_lock);
  
    if (openFile->ptr == NULL) return -1;
    
    openFile->fd = ++thread_current()->fileDir;
    list_push_back(&thread_current()->files_list,&openFile->elem);
    return openFile->fd;
  }

int file_size(int fd){
	struct file* my_file = get_file(fd)->ptr;

  if (my_file == NULL)
		return -1;
	
	lock_acquire(&file_lock);
	int fileSize = file_length(my_file);
	lock_release(&file_lock);
	return fileSize;
}


int sys_read(int fd, void *buffer, int length){
  if (fd == 0){  //input stream
    
    for (size_t i = 0; i < length; i++){
      lock_acquire(&file_lock);
      ((char*)buffer)[i] = input_getc();
      lock_release(&file_lock);
    }
    return length;
    
  }
  else if (fd == 1){ //output stream
    //negative area cant happened cuz the validation that happened before
    return -1 ;
  }
  else {
    struct file* my_file = get_file(fd)->ptr;

    if (my_file == NULL){return -1;}

    //Returns the number of bytes actually read

    int res;
    lock_acquire(&file_lock);
    res = file_read(my_file,buffer,length);
    lock_release(&file_lock);
    return res;
  }
}

struct open_file* get_file(int fd){

    struct thread* t = thread_current();

    // go throught open files in that thread and return fd if founded
    for (struct list_elem* e = list_begin (&t->files_list); e != list_end (&t->files_list);
    e = list_next (e))
    {
      struct open_file* opened_file = list_entry (e, struct open_file, elem);
      if (opened_file->fd == fd)
      {
        return opened_file;
      }
    }
    return NULL;
}

int sys_write (int fd, const void *buffer, unsigned size){
    
    int size_written = 0;

	if (fd == 1){ /// output stream
		lock_acquire(&file_lock);
		putbuf(buffer, size);
		size_written = (int)size;
		lock_release(&file_lock);
	}
	else if (fd == 0){ //input stream
    //negative area cant happened cuz the validation that happened before
    return -1 ;
  }
  else{ //// writing normally to an open file
		
    struct file* my_file = get_file(fd)->ptr;

    if (my_file == NULL){return -1;}

		lock_acquire(&file_lock);
		size_written = (int)file_write(my_file, buffer, size);
		lock_release(&file_lock);
	}
	return size_written;
    
}
//Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file
void sys_seek(int fd, unsigned position){
	struct file *my_file = get_file(fd)->ptr;
	if (my_file == NULL || position < 0) return;

	lock_acquire(&file_lock);
	file_seek(my_file, position);
	lock_release(&file_lock);
}

// Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
int sys_tell(int fd){
	struct file *my_file = get_file(fd)->ptr;
	if (my_file == NULL) return -1;

	lock_acquire(&file_lock);
	int pos = (int)file_tell(my_file);
	lock_release(&file_lock);
	return pos;
}

pid_t exec(const char *cmd_line){
    return  process_execute(cmd_line);  
}

void exit(int status){
    struct thread* t=thread_current();
    t->my_info->exit_status = status; /*store the exit status for the parent to pick it up after exitting*/
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit();
}


int wait(pid_t tid){
    return process_wait(tid);
}