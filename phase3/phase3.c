    /*
     * Create first user-level process and wait for it to finish.
     * These are lower-case because they are not system calls;
     * system calls cannot be invoked from kernel mode.
     * Assumes kernel-mode versions of the system calls
     * with lower-case names.  I.e., Spawn is the user-mode function
     * called by the test cases; spawn is the kernel-mode function that
     * is called by the syscall_handler; spawn_real is the function that
     * contains the implementation and is called by spawn.
     *
     * Spawn() is in libuser.c.  It invokes usyscall()
     * The system call handler calls a function named spawn() -- note lower
     * case -- that extracts the arguments from the sysargs pointer, and
     * checks them for possible errors.  This function then calls spawn_real().
     *
     * Here, we only call spawn_real(), since we are already in kernel mode.
     *
     * spawn_real() will create the process by using a call to fork1 to
     * create a process executing the code in spawn_launch().  spawn_real()
     * and spawn_launch() then coordinate the completion of the phase 3
     * process table entries needed for the new process.  spawn_real() will
     * return to the original caller of Spawn, while spawn_launch() will
     * begin executing the function passed to Spawn. spawn_launch() will
     * need to switch to user-mode before allowing user code to execute.
     * spawn_real() will return to spawn(), which will put the return
     * values back into the sysargs pointer, switch to user-mode, and
     * return to the user code that called Spawn.
     */

#include <usloss.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>
#include <usyscall.h>
#include "sems.h"

typedef struct UserProcessTable UserProcessTable;
typedef struct UserProcessTable *UserProcessTable_ptr;

typedef struct UserProcessTable {
    UserProcessTable_ptr *next;
    UserProcessTable_ptr *prev;
    UserProcessTable_ptr parent;
    UserProcessTable_ptr childprocessptr;
    char name[MAX_MESSAGE];
    int status; //int PROCESS_STATE;
    int pid;
    int parent_pid;
    int child_pid;
    int process_priority;
    int stackSize;
    int (*startFunc)(char*); //void *entry_point;
    char *args;
    int semaphore;
    int mbox_id;
    int cpu_time;
} UserProcessTable;

typedef struct SemaphoreStructure {
    UserProcessTable_ptr pBlocked;
    int status;
    int semaphore;
    int mbox_id;
} SemaphoreStructure;

//func definitions
//extern int start2(char *);
int start2 (char *);
extern int start3 (char *);
extern void (*sys_vec[])(sysargs *args);
static void nullsys(sysargs *args);
void check_kernel_mode(char *str);

//assignment funcs
int spawn_real(char *name, int (*func)(char*), char *arg, int stack_size, int priority);
int terminate_real(int exit_code);
int wait_real(int *status);
int getPID(int *pid);
int cputime(int *pid);
void ActivateUserMode();
static void spawn(sysargs *args);
static void wait(sysargs *args);
static void terminate(sysargs *args);

//globals arrays
UserProcessTable pTable[MAXPROC];
SemaphoreStructure pSemtable[MAX_SEMS];

//function start
static void nullsys3(sysargs *args_ptr) {
   console("nullsys3(): Invalid syscall %d\n", args_ptr->number);
   console("nullsys3(): process %d terminating\n", getpid());
   terminate_real(1);
} /* nullsys3 */

static void gettimeofday(systemArgs *args)
{
	args->arg1 = USLOSS_Clock();
	ActivateUserMode();
}

int readCurrentStartTime()
{
	//unsigned int current_time = sys_clock(); // Get current system time
	//unsigned int time_since_start = current_time - Current->startTime;
	//return USLOSS_Clock() - Current->startTime;
	//return time_since_start;
	return Current->startTime;
}

static void cputime(systemArgs *args)
{
	args->arg1 = USLOSS_Clock() - readCurrentStartTime();
	ActivateUserMode();
}

static void getPID(systemArgs *args)
{
	args->arg1 = getpid();
	ActivateUserMode();
}

static void terminate(sysargs *args_ptr)
{
	int exit_code;
	exit_code = (int)args_ptr->arg1;
	terminate_real(exit_code);
}

int start2(char *arg)
{
    int		pid;
    int		status;
    /*
     * Check kernel mode here.
     */
	    check_kernel_mode("start2");
      /*
      if(!(USLOSS_PSR_CURRENT_MODE & USLOSS_PsrGet()))
      {
          console("we are not in kernel mode...halting\n");
          halt(1);
      }*/

    /*
     * Data structure initialization as needed...
     */
     int i;

     //init sys_vec to nullsys3
    for (i = 0; i < MAXSYSCALLS; i++) {
        sys_vec[i] = nullsys3;
    }

    //init proc table
    for (i = 0; i < MAXPROC; i++)
    {
      //pid % MAXPROC;
      strcpy(pTable[i].name, ""); //char name[MAX_MESSAGE];
      pTable[i].next = NULL;
      pTable[i].prev = NULL;
      pTable[i].status = INACTIVE;       //pTable[i].PROCESS_STATE = INACTIVE;
      pTable[i].pid = -1;
      pTable[i].parent_pid = -1;
      pTable[i].child_pid = -1;
      pTable[i].process_priority = -1;
      pTable[i].startFunc = NULL;
      pTable[i].args = NULL;
      //pTable[i].mbox = NULL;
      pTable[i].semaphore = INACTIVE;
      pTable[i].mbox_id = -1;
      pTable[i].cpu_time = -1;

      //ProcessTable[i].startFunc = NULL;
      //ProcessTable[i].nextProcPtr = NULL;
    }

    // initialize semaphore table
    for (int i = 0; i < MAXSEMS; i++) {
        pSemtable[i].status = INACTIVE; //EMPTY;
	pSemtable[i].pBlocked = NULL;
    }

    //activate system call handlers
    sys_vec[SYS_SPAWN] = spawn;
    sys_vec[SYS_WAIT] = wait;
    sys_vec[SYS_TERMINATE] = terminate;
    sys_vec[SYS_SEMCREATE] = semCreate;
    sys_vec[SYS_SEMP] = semP;
    sys_vec[SYS_SEMV] = semV;
    sys_vec[SYS_SEMFREE] = semFree;
    sys_vec[SYS_GETTIMEOFDAY] = gettimeofday;
    sys_vec[SYS_CPUTIME] = cputime;
    sys_vec[SYS_GETPID] = getPID;

    pid = spawn_real("start3", start3, NULL, 4*USLOSS_MIN_STACK, 3);
    pid = wait_real(&status);

    quit(0);

    //return pid;
} /* start2 */

void wait(systemArgs *args)
{
  int kid_pid;
  int status = (int)args->arg2;

  kid_pid = wait_real(&status);

  pTable[getpid() % MAXPROC].status = ACTIVE;

   if (kid_pid == -2) {
        args->arg1 = (void *) 0;
        args->arg2 = (void *) -2;
    } else {
        args->arg1 = (void *) kid_pid;
        args->arg2 = ((void *) status);
    }

    ActivateUserMode();
}

int wait_real(int *status)
{
  //check kernel mode
  check_kernel_mode("wait_real");

  //pTable[getpid() % MAXPROC].status = WAIT_BLOCK;
  return join(status);
}

// check if process is running in kernel mode
void check_kernel_mode(char *str) {
   /* psr_get() returns current processes mode: 1 = kernel mode, 0 = user mode. */
   int current_mode = psr_get();
   if ((current_mode & PSR_CURRENT_MODE) == 0) {
      console("Kernel mode expected, but function %s called in user mode.\n", str);
      halt(1);
   }
}

void ActivateUserMode()
{
    if(debugFlag){
        USLOSS_Console("ActivateUserMode(): Changing to user mode\n");
    }
   /* set the user mode */
    psr = psr_get();
    psr &= ~PSR_CURRENT_MODE;
    psr_set(psr);
}

void Dev_ActivateUserMode()
{
    if(debugFlag){
        USLOSS_Console("ActivateUserMode(): Changing to user mode\n");
    }
    USLOSS_PsrSet(USLOSS_PsrGet() & ~USLOSS_PSR_CURRENT_MODE);
}

void spawn(systemArgs *args)
{
    int pid;
    pid = spawn_real((char *)args->arg5, args->arg1, args->arg2,args->arg3, args->arg4);

    args->arg1 = (int *) pid;
    args->arg4 = (int *) 0;

    ActivateUserMode();
}

int spawn_real(char *name, int (*func)(char*), char *arg, int stack_size, int priority)
{
  int pid;
  int mbox_id;

  //check kernel mode
  check_kernel_mode("spawn_real");

  pid = fork1(name, spawn_launcher, arg, stack_size, priority);
  if(pid < 0)
  {
    console("spawn_real(): PID error with fork function\n");
    halt(1);
  }

  int proc_table_slot = pid % MAXPROC;
  if(pTable[proc_table_slot].status = INACTIVE)
  {
    pTable[proc_table_slot].status = ACTIVE;
    mbox_id = MboxCreate(0,0);
    pTable[proc_table_slot].mbox_id = mbox_id;
  } else {
    mbox_id = pTable[proc_table_slot].mbox_id;
  }

  strcpy(pTable[proc_table_slot].name, name);
  pTable[process_slot].pid = pid;             // get child pid
  pTable[process_slot].parent_pid = getpid();  // get parent pid
  pTable[process_slot].entrypoint = func;     // pass launch_usermode function to call
  pTable[proc_table_slot].stack_size = stack_size;
  pTable[proc_table_slot].priority = priority;

  MboxCondSend(pTable[process_slot].mbox_id, NULL, 0);

  return pid;
}

int terminate_real(int exit_code)
{
   //check kernel mode
   check_kernel_mode("terminate_real");

    // if the process has children, zap them
    if (parent->childprocessptr != NULL) {
        while (parent->childprocessptr != NULL) {
            zap(parent->childprocessptr->pid);
        }
    }
    quit(exit_code);
}

static void terminate(systemArgs *args)
{
  //check kernel mode
  check_kernel_mode("terminate");
  //UserProcessTable parent =  &pTable[getpid() % MAXPROC];

  int exit_code = (int)args_ptr->arg1;
  terminate_real(exit_code);

  ActivateUserMode();
}

static void semCreate(systemArgs *args)
{
	//check kernel mode
  	check_kernel_mode("semCreate");
}

static void semP(systemArgs *args)
{
	//check kernel mode
  	check_kernel_mode("semP");
}

static void semV(systemArgs *args)
{
	//check kernel mode
  	check_kernel_mode("semV");
}

static void semFree(systemArgs *args)
{
	//check kernel mode
  	check_kernel_mode("semFree");
}
