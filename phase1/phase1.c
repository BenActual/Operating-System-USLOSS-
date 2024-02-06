/* ------------------------------------------------------------------------
   phase1.c

   CSCV 452

   ------------------------------------------------------------------------ */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <phase1.h>
#include "kernel.h"

/* ------------------------- Prototypes ----------------------------------- */
int sentinel (void *);
extern int start1 (char *);
void dispatcher(void);
void launch();
static void enableInterrupts();
static void check_deadlock();
int kernel_or_user(void);
void disableInterrupts();

/* -------------------------- Globals ------------------------------------- */

/* Patrick's debugging global variable... */
int debugflag = 1;

/* the process table */
proc_struct ProcTable[MAXPROC];


/* Process lists  */

/* current process ID */
proc_ptr Current;

/* the next pid to be assigned */
unsigned int next_pid = SENTINELPID;

int num_procs = 0;


/* -------------------------- Functions ----------------------------------- */
/* ------------------------------------------------------------------------
   Name - startup
   Purpose - Initializes process lists and clock interrupt vector.
	     Start up sentinel process and the test process.
   Parameters - none, called by USLOSS
   Returns - nothing
   Side Effects - lots, starts the whole thing
   ----------------------------------------------------------------------- */
void startup()
{
  
   int result; /* value returned by call to fork1() */

   /* initialize the process table */
   for (int i = 0; i < 50; i++)
   {
      ProcTable[i].next_proc_ptr = NULL;
      ProcTable[i].child_proc_ptr = NULL;
      ProcTable[i].next_sibling_ptr = NULL;
      ProcTable[i].pid = NULL; // Use 0 or a specific invalid pid if appropriate
      ProcTable[i].priority = NULL; // Use 0 or a default priority
      ProcTable[i].stacksize = NULL; // Use 0 or a default stack size
      ProcTable[i].status = NULL; // READY, BLOCKED, QUIT, etc. (use specific constants if you have them)
      ProcTable[i].parent_pid = NULL;  /*IF -1 NO PARENT EXISTS*/
      ProcTable[i].kids = NULL;
      ProcTable[i].kid_num = NULL;
      ProcTable[i].status = 0;
   }

   /* Initialize the Ready list, etc. */
   if (DEBUG && debugflag)
      console("startup(): initializing the Ready & Blocked lists\n");
   

   /* Initialize the clock interrupt handler */
   

   /* startup a sentinel process */
   if (DEBUG && debugflag)
       console("startup(): calling fork1() for sentinel\n");
   result = fork1("sentinel", sentinel, NULL, USLOSS_MIN_STACK,
                   SENTINELPRIORITY);
   if (result < 0) {
      if (DEBUG && debugflag)
         console("startup(): fork1 of sentinel returned error, halting...\n");
      halt(1);
   }
  
   /* start the test process */
   if (DEBUG && debugflag)
      console("startup(): calling fork1() for start1\n");
   result = fork1("start1", start1, NULL, 2 * USLOSS_MIN_STACK, 1);
   if (result < 0) {
      console("startup(): fork1 for start1 returned an error, halting...\n");
      halt(1);
   }
   

   console("startup(): Should not see this message! ");
   console("Returned from fork1 call that created start1\n");

   return;
} /* startup */

/* ------------------------------------------------------------------------
   Name - finish
   Purpose - Required by USLOSS
   Parameters - none
   Returns - nothing
   Side Effects - none
   ----------------------------------------------------------------------- */
void finish()
{
   if (DEBUG && debugflag)
      console("in finish...\n");
} /* finish */

/* ------------------------------------------------------------------------
   Name - fork1
   Purpose - Gets a new process from the process table and initializes
             information of the process.  Updates information in the
             parent process to reflect this child process creation.
   Parameters - the process procedure address, the size of the stack and
                the priority to be assigned to the child process.
   Returns - the process id of the created child or -1 if no child could
             be created or if priority is not between max and min priority.
   Side Effects - ReadyList is changed, ProcTable is changed, Current
                  process information changed
   ------------------------------------------------------------------------ */
int fork1(char *name, int (*f)(char *), char *arg, int stacksize, int priority)
{
   int proc_slot ;
   

    if (DEBUG && debugflag)
      console("fork1(): creating process %s\n", name);
   disableInterrupts();
   /* test if in kernel mode; halt if in user mode */
   if (!(kernel_or_user()))
   {
      console("Process %d -- called in user mode. Halting process.\n", Current->pid);
      halt(1);
   }
   /* Return if stack size is too small */
   if (stacksize < USLOSS_MIN_STACK)
   {
      return (-2);
   }
   /*Return if function pointer is NULL*/
   if (f == NULL)
   {
      return (-1);
   }
   /*Return if name is NULL*/
   if (name == NULL)
   {
      return (-1);
   }
   /*Return if Priority is out of range*/
   if (strcmp(name, "sentinel") && (priority < 1 || priority > 5))
   {
      return (-1);
   }
   /* Return if maximum processes reached */
   if (num_procs >= MAXPROC)
   {
      return (-1);
   }
   /* find an empty slot in the process table */

   /* fill-in entry in process table */
   if ( strlen(name) >= (MAXNAME - 1) ) {
      console("fork1(): Process name is too long.  Halting...\n");
      halt(1);
   }
   strcpy(ProcTable[proc_slot].name, name);
   ProcTable[proc_slot].start_func = f;
   if ( arg == NULL )
      ProcTable[proc_slot].start_arg[0] = '\0';
   else if ( strlen(arg) >= (MAXARG - 1) ) {
      console("fork1(): argument too long.  Halting...\n");
      halt(1);
   }
   else
      strcpy(ProcTable[proc_slot].start_arg, arg);

   ProcTable[proc_slot].stack = (char *)malloc(stacksize);
   ProcTable[proc_slot].stacksize = stacksize;
   ProcTable[proc_slot].pid = next_pid++;
   ProcTable[proc_slot].priority = priority;
   ProcTable[proc_slot].status = READY;
   ProcTable[proc_slot].proc_table_location = proc_slot;
   ProcTable[proc_slot].parent_location = -1;
   ProcTable[proc_slot].next_proc_ptr = NULL;
   ProcTable[proc_slot].child_proc_ptr = NULL;
   ProcTable[proc_slot].next_sibling_ptr = NULL;
   ProcTable[proc_slot].total_time = 0;
   ProcTable[proc_slot].startTime = 0;
   ProcTable[proc_slot].kid_num = 0;
   ProcTable[proc_slot].quit_code = 0;
   ProcTable[proc_slot].blocked_by = 0;

   /* Initialize context for this process, but use launch function pointer for
    * the initial value of the process's program counter (PC)
    */
   context_init(&(ProcTable[proc_slot].state), psr_get(),
                ProcTable[proc_slot].stack, 
                ProcTable[proc_slot].stacksize, launch);

   /* for future phase(s) */
   p1_fork(ProcTable[proc_slot].pid);

    enableInterrupts();
    return ProcTable[proc_slot].pid;
   

} /* fork1 */

/* ------------------------------------------------------------------------
   Name - launch
   Purpose - Dummy function to enable interrupts and launch a given process
             upon startup.
   Parameters - none
   Returns - nothing
   Side Effects - enable interrupts
   ------------------------------------------------------------------------ */
void launch()
{
   int result;

   if (DEBUG && debugflag)
      console("launch(): started\n");

   /* Enable interrupts */
   enableInterrupts();

   /* Call the function passed to fork1, and capture its return value */
   result = Current->start_func(Current->start_arg);

   if (DEBUG && debugflag)
      console("Process %d returned to launch\n", Current->pid);

   quit(result);

} /* launch */


/* ------------------------------------------------------------------------
   Name - join
   Purpose - Wait for a child process (if one has been forked) to quit.  If 
             one has already quit, don't wait.
   Parameters - a pointer to an int where the termination code of the 
                quitting process is to be stored.
   Returns - the process id of the quitting child joined on.
		-1 if the process was zapped in the join
		-2 if the process has no children
   Side Effects - If no child process has quit before join is called, the 
                  parent is removed from the ready list and blocked.
   ------------------------------------------------------------------------ */
int join(int *code)
{
} /* join */


/* ------------------------------------------------------------------------
   Name - quit
   Purpose - Stops the child process and notifies the parent of the death by
             putting child quit info on the parents child completion code
             list.
   Parameters - the code to return to the grieving parent
   Returns - nothing
   Side Effects - changes the parent of pid child completion status list.
   ------------------------------------------------------------------------ */
void quit(int code)
{
   printf("quit() called\n");
 if (!(kernel_or_user()))
   {
      console("Quit() called in user mode. Halting...\n");
      halt(1);
   }
   if (DEBUG && debugflag)
   {
      console("quit() has been called on process %d with exit code of %d\n", Current->pid, code);
   }
   if (Current->child_proc_ptr != NULL && Current->child_proc_ptr->status != QUIT)
   {
      console("quit() has been called while process has living children, halting...\n");
      halt(1);
   }

   if (Current->parent_pid == -1)
   {
      console("quit() has been called on a process with no parent, halting...\n");
      halt(1);
   }

   if (Current->parent_pid != -1)
   {
      proc_ptr parent = &ProcTable[Current->parent_location];
      parent->quit_children_num++;
      parent->kids_status_list[parent->kid_num] = code;
      parent->kid_num++;
   }
   

   
   p1_quit(Current->pid);
   
} /* quit */


/* ------------------------------------------------------------------------
   Name - dispatcher
   Purpose - dispatches ready processes.  The process with the highest
             priority (the first on the ready list) is scheduled to
             run.  The old process is swapped out and the new process
             swapped in.
   Parameters - none
   Returns - nothing
   Side Effects - the context of the machine is changed
   ----------------------------------------------------------------------- */
void dispatcher(void)
{
   proc_ptr next_process;

   p1_switch(Current->pid, next_process->pid);
} /* dispatcher */


/* ------------------------------------------------------------------------
   Name - sentinel
   Purpose - The purpose of the sentinel routine is two-fold.  One
             responsibility is to keep the system going when all other
	     processes are blocked.  The other is to detect and report
	     simple deadlock states.
   Parameters - none
   Returns - nothing
   Side Effects -  if system is in deadlock, print appropriate error
		   and halt.
   ----------------------------------------------------------------------- */
int sentinel (void * dummy)
{
   if (DEBUG && debugflag)
      console("sentinel(): called\n");
   while (1)
   {
      check_deadlock();
      waitint();
   }
} /* sentinel */


/* check to determine if deadlock has occurred... */
static void check_deadlock()
{
} /* check_deadlock */


/*
 * Disables the interrupts.
 */
void disableInterrupts()
{
  /* turn the interrupts OFF iff we are in kernel mode */
  if((PSR_CURRENT_MODE & psr_get()) == 0) {
    //not in kernel mode
    console("Kernel Error: Not in kernel mode, may not disable interrupts\n");
    halt(1);
  } else
    /* We ARE in kernel mode */
    psr_set( psr_get() & ~PSR_CURRENT_INT );
    
} /* disableInterrupts */

void enableInterrupts()
{
   if (kernel_or_user() == 0)
   {
      // IN USER MODE
      console("Kernel Error: Not in kernel mode, may not enable interrupts\n");
      halt(1);
   }
   else
   {
      // KERNEL MODE
      psr_set(psr_get() | PSR_CURRENT_INT);
   }
}


int kernel_or_user(void)
{
   return PSR_CURRENT_MODE & psr_get();
}
