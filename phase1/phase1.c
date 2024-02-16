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
int sentinel(void *);
extern int start1(char *);
void dispatcher(void);
void launch(void);
void enableInterrupts(void);
static void check_deadlock(void);
void add_next_proc(proc_ptr);
proc_ptr grab_next_process(void);
void proc_blocked(proc_ptr);
void removeFromBlockList(proc_ptr);
void disableInterrupts(void);
int check_mode(void);
void removeProcessWithoutRequeue(proc_ptr);
int getpid(void);
void dump_processes(void);
int block_me(int);
int unblock_proc(int);
void time_slice(void);
int join(int *);
void quit(int);
int zap(int);
int is_zapped(void);

/* -------------------------- Globals ------------------------------------- */

/* Patrick's debugging global variable... */
int debugflag = 0;

/* the process table */
proc_struct ProcTable[MAXPROC];

/* Process lists  */
proc_ptr ReadyList[7];
proc_ptr BlockedList[7];
proc_ptr Current;
proc_ptr Blocked;

/* the next pid to be assigned */
unsigned int next_pid = SENTINELPID;

/* number of processes currently in the process table */
int proc_number = 0;

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
    // Initialize pointers to NULL
    ProcTable[i].next_proc_ptr = NULL;           
    ProcTable[i].child_proc_ptr = NULL;          
    ProcTable[i].next_sibling_ptr = NULL;        

    // Initialize numeric fields to 0 or appropriate default values
    ProcTable[i].pid = 0;                         /* process id */
    ProcTable[i].priority = 0;
    ProcTable[i].stacksize = 0;
    ProcTable[i].status = 0;                      /* READY, BLOCKED, QUIT, etc. */
    ProcTable[i].total_time = 0;                  // amount of time used by the CPU
    ProcTable[i].startTime = 0;                   // time started by CPU - will change on each call
    ProcTable[i].lastRunTime = 0;                 // time ended by CPU
    ProcTable[i].parent_pid = -1;                 /* IF -1 NO PARENT EXISTS */
    ProcTable[i].zapped = 0;                      // 1 == TRUE 0 == FALSE
    ProcTable[i].kids = 0;
    ProcTable[i].kid_num = 0;
    ProcTable[i].quit_code = 0;                   // if quit, what code is it
    ProcTable[i].proc_table_location = 0;         // location on process table
    ProcTable[i].parent_location = 0;             // parent location on process table
    ProcTable[i].blocked_by = 0;                  // pid of process blocking current process
    ProcTable[i].status = 0;                      // Status initialization (redundant)
    ProcTable[i].quit_children_num = 0;           // Number of children that quit
}


   /* Initialize the Ready list, etc. */
   if (DEBUG && debugflag)
      console("startup(): initializing the Ready & Blocked lists\n");

   /* Initialize the clock interrupt handler */
   int_vec[CLOCK_INT] = time_slice;

   /* startup a sentinel process */
   if (DEBUG && debugflag)
      console("startup(): calling fork1() for sentinel\n");
   result = fork1("sentinel", sentinel, NULL, USLOSS_MIN_STACK,
                  SENTINELPRIORITY);
   if (result < 0)
   {
      if (DEBUG && debugflag)
         console("startup(): fork1 of sentinel returned error, halting...\n");
      halt(1);
   }

   /* start the test process */
   if (DEBUG && debugflag)
      console("startup(): calling fork1() for start1\n");
   result = fork1("start1", start1, NULL, 2 * USLOSS_MIN_STACK, 1);
   if (result < 0)
   {
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
   exit(0);
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
   int proc_slot = next_pid % MAXPROC;

   if (DEBUG && debugflag)
      console("fork1(): creating process %s\n", name);
   disableInterrupts();
   /* test if in kernel mode; halt if in user mode */
if (check_mode() == 0) {
    console("Error: Process %d is running in user mode. System will halt.\n", Current->pid);
    halt(1);
}

// Validate minimum stack size requirement
if (stacksize < USLOSS_MIN_STACK) return -2;

// Validate function pointer is not NULL
if (!f) return -1;

// Validate process name is provided
if (!name) return -1;

// Validate priority for non-sentinel processes
if (strcmp(name, "sentinel") != 0 && (priority < 1 || priority > 5)) return -1;

// Check if the process table has reached its maximum capacity
if (proc_number >= MAXPROC) return -1;

// Locate an empty slot in the process table, wrapping around if necessary
for (; ProcTable[proc_slot].status != QUIT && ProcTable[proc_slot].status != 0; proc_slot = (proc_slot + 1) % MAXPROC);

   /* find an empty slot in the process table */

   while (ProcTable[proc_slot].status != QUIT && ProcTable[proc_slot].status != 0)
   {
      proc_slot++;
      if (proc_slot == MAXPROC)
      {
         proc_slot = 0;
      }
   }
   /* fill-in entry in process table */
   if (strlen(name) >= (MAXNAME - 1))
   {
      console("fork1(): Process name is too long.  Halting...\n");
      halt(1);
   }
   strcpy(ProcTable[proc_slot].name, name);
   ProcTable[proc_slot].start_func = f;
   if (arg == NULL)
      ProcTable[proc_slot].start_arg[0] = '\0';
   else if (strlen(arg) >= (MAXARG - 1))
   {
      console("fork1(): argument too long.  Halting...\n");
      halt(1);
   }
   else
      strcpy(ProcTable[proc_slot].start_arg, arg);

   // initialize values to the procTable
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
   proc_number++;

   /* Initialize context for this process, but use launch function pointer for
    * the initial value of the process's program counter (PC)
    */

   context_init(&(ProcTable[proc_slot].currentContext), psr_get(),
                ProcTable[proc_slot].stack,
                ProcTable[proc_slot].stacksize, launch);

// Set default parent process ID and child number for special processes
if (strcmp(name, "sentinel") == 0 || strcmp(name, "start1") == 0) {
    ProcTable[proc_slot].parent_pid = -1;
    ProcTable[proc_slot].kid_num = -1;
} else {
    // For regular processes, link the child to its parent
    ProcTable[proc_slot].parent_pid = Current->pid;
    ProcTable[proc_slot].parent_location = Current->proc_table_location;
    Current->kids++; // Increment the parent's child count

    // Initialize as the first child if the parent has no children yet
    if (!Current->child_proc_ptr) {
        Current->child_proc_ptr = &ProcTable[proc_slot];
        ProcTable[proc_slot].kid_num = 0; // First child
    } else {
        // Otherwise, append to the end of the parent's child list
        proc_ptr lastChild = Current->child_proc_ptr;
        while (lastChild->next_sibling_ptr) {
            lastChild = lastChild->next_sibling_ptr; // Find the last child
        }
        lastChild->next_sibling_ptr = &ProcTable[proc_slot]; // Set as next sibling
        ProcTable[proc_slot].kid_num = Current->kids; // Assign kid number based on current count
    }
}


   // add process to the ready list
   p1_fork(ProcTable[proc_slot].pid);

   add_next_proc(&ProcTable[proc_slot]);

   enableInterrupts();

   if (strcmp("sentinel", ProcTable[proc_slot].name) != 0)
   {
      dispatcher();
   }

   return ProcTable[proc_slot].pid;
} /* fork1 */

int check_mode(void)
{
   return PSR_CURRENT_MODE & psr_get();
}

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
int join(int *code) {
    // Ensure we're in kernel mode
    if (!check_mode()) {
        console("The function Join() is in user mode. Halting\n");
        halt(1);
    }

    proc_ptr child = Current->child_proc_ptr;
    // No children to join with
    if (child == NULL) {
        return -2;
    }

    // If the first child has already quit
    if (child->status == QUIT) {
        *code = child->quit_code;
        Current->child_proc_ptr = child->next_sibling_ptr; // Move to the next child
        return child->pid; // Return quit child's PID
    }

    // Block current process to wait for a child to quit
    Blocked = Current;
    Blocked->status = JOIN_BLOCK;
    Blocked->blocked_by = child->pid;
    proc_blocked(Blocked); // Add process to the blocked list
    dispatcher(); // Continue with other processes

    // Handling after being unblocked
    if (Current->zapped) {
        *code = child->quit_code;
        Current->child_proc_ptr = child->next_sibling_ptr;
        return -1; // Return -1 if current process was zapped
    }

    // Find and remove the quit child from the list
    proc_ptr previous = NULL, quitChild = Current->child_proc_ptr;
    while (quitChild != NULL && quitChild->status != QUIT) {
        previous = quitChild;
        quitChild = quitChild->next_sibling_ptr;
    }

    if (quitChild == NULL) return -1; // No child has quit, should not happen due to dispatcher logic

    // Adjust pointers to remove the quit child from the list
    if (previous != NULL) {
        previous->next_sibling_ptr = quitChild->next_sibling_ptr;
    } else {
        Current->child_proc_ptr = quitChild->next_sibling_ptr; // The quit child was the first child
    }

    *code = quitChild->quit_code;
    return quitChild->pid; // Return the PID of the quit child
} /*join*/


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
   if (!(check_mode()))
   {
      console("The function Join() is in user mode. Halting\n");
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
   disableInterrupts();
   Current->status = QUIT; 
   proc_ptr next_ptr;
if (Current->parent_pid != -1) {
    int i = 0;
    // Find parent process in the process table
    while (ProcTable[i].pid != Current->parent_pid) {
        i++;
    }

    // Unblock parent if it was blocked waiting for a child process
    if (ProcTable[i].status == JOIN_BLOCK) {
        ProcTable[i].status = READY;
        removeFromBlockList(&ProcTable[i]);
    }

    // Check and unblock any processes directly blocked by the current process
    for (int j = 0; j < 7; j++) { // Assuming 7 is the number of possible blocked processes
        next_ptr = BlockedList[j];
        while (next_ptr != NULL) {
            if (next_ptr->blocked_by == Current->pid) {
                removeFromBlockList(next_ptr);
                next_ptr = BlockedList[j]; // Reset to start as the list may have changed
            } else {
                next_ptr = next_ptr->next_proc_ptr; // Move to the next in list
            }
        }
    }

    // Update the quit information for the current process
    Current->quit_code = code;
    ProcTable[i].quit_children = Current;
    ProcTable[i].quit_children_num++;
    ProcTable[i].kids_status_list[Current->kid_num] = code;
} else {
    // No parent to notify or update
}

// Finalize quitting process
p1_quit(Current->pid);
proc_number--;
enableInterrupts();
dispatcher(); // Switch to the next process

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
void dispatcher(void) {
    // Initialize a pointer for the next process and a flag for initiating a process switch.
    proc_ptr next_process = NULL;
    int process_switch = 0;
    context *pPreviousContext = NULL;

    // Check if the current process is running and needs to be preempted.
    if (Current != NULL && Current->status == RUNNING) {
        // Iterate through the ready list to check for a higher priority process.
        for (int i = 0; i <= Current->priority - 1; i++) {
            if (ReadyList[i] != NULL) {
                process_switch = 1; // A higher priority process is ready to run.
                Current->status = READY; // Mark the current process as ready.
                add_next_proc(Current); // Add the current process back to the ready list.
                break; // No need to check further once a higher priority process is found.
            }
        }
    } else {
        // If there's no current process running, ensure a switch occurs.
        process_switch = 1;
    }

    // Proceed with the process switch if determined necessary.
    if (process_switch) {
        // Fetch the next process from the ready list.
        next_process = grab_next_process();

        // If there is a currently running process, prepare for context switching.
        if (Current != NULL) {
            pPreviousContext = &Current->currentContext; // Save the current process context.
            // Record the running time for the current process before switching.
            Current->lastRunTime = sys_clock();
            Current->total_time += (Current->lastRunTime - Current->startTime); // Update total run time.
        }

        // Switch to the next process.
        Current = next_process;
        Current->status = RUNNING; // Set the new process status to RUNNING.
        Current->startTime = sys_clock(); // Record the start time of the new current process.

        enableInterrupts(); // Enable interrupts for the new process.

        // Perform the context switch from the previous (if any) to the next process's context.
        context_switch(pPreviousContext, &(next_process->currentContext));

        // Log the context switch for monitoring and debugging.
        p1_switch(Current->pid, next_process->pid);
    }
}/* dispatcher */

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
int sentinel(void *dummy)
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
static void check_deadlock() {
    // Attempt to grab the next process from the ready list.
    proc_ptr next_proc = grab_next_process();

    // If no process is ready to run, it might indicate a potential deadlock situation.
    if (next_proc == NULL) {
        // Iterate through each queue in the blocked list to check for any blocked processes.
        for (int i = 0; i < 6; i++) { // Assuming there are 6 priority levels or queues.
            next_proc = BlockedList[i];
            // If a process is found in the blocked list, it indicates system is not in deadlock.
            if (next_proc != NULL) {
                printf("Deadlock halting.\n");
                halt(1); // Halt the system as it is considered a critical issue.
                break; // Exit the loop after finding at least one blocked process.
            }
        }
        // If this point is reached, all processes have completed successfully.
        printf("All processes completed. System shutting down...\n");
        exit(0); // Gracefully exit the system indicating successful completion.
    } else {
        // If there is a process ready to run, it's a normal operation, not a deadlock.
        // However, this condition should not typically trigger a deadlock check,
        // so log and halt as it indicates an unexpected state.
        printf("Deadlock check triggered with ready processes present.. halting.\n");
        halt(1);
    }
}



void disableInterrupts()
{
   /* turn the interrupts OFF iff we are in kernel mode */
   if ((PSR_CURRENT_MODE & psr_get()) == 0)
   {
      // not in kernel mode
      console("Kernel Error: Not in kernel mode, may not disable interrupts\n");
      halt(1);
   }
   else
      /* We ARE in kernel mode */
      psr_set(psr_get() & ~PSR_CURRENT_INT);
} /* disableInterrupts */



/* ------------------------------------------------------------------------
   Name - enableInterrupts
   Purpose - Enables interrupts if the processor is in kernel mode, otherwise halts the system
   Parameters - none
   Returns - void
   Side Effects - May halt the system if not in kernel mode
   ----------------------------------------------------------------------- */
void enableInterrupts()
{
   if (check_mode() == 0)
   {
      // IN USER MODE: Print error message and halt if not in kernel mode
      console("Kernel Error: Not in kernel mode, may not enable interrupts\n");
      halt(1); // Halt the system with an error code
   }
   else
   {
      // KERNEL MODE: Enable interrupts
      psr_set(psr_get() | PSR_CURRENT_INT);
   }
}



/* ------------------------------------------------------------------------
   Name - grab_next_process
   Purpose - Removes the highest priority process from the ready list and returns it to the dispatcher
   Parameters - none
   Returns - proc_ptr: Pointer to the highest priority process removed from the ready list, or NULL if the ready list is empty
   Side Effects - Modifies the ready list
   ----------------------------------------------------------------------- */
proc_ptr grab_next_process()
{
   // Iterate through each priority level in the ready list
   for (int i = 0; i < 7; i++)
   {
      // Check if the current priority level has a process
      if (ReadyList[i] != NULL)
      {
         // If a process exists at this priority level, remove it from the ready list
         proc_ptr new_proc = ReadyList[i];
         ReadyList[i] = new_proc->next_proc_ptr; // Update ready list to point to the next process
         new_proc->next_proc_ptr = NULL; // Clear the next pointer of the removed process
         return new_proc; // Return the removed process
      }
   }
   // If no process is found in the ready list, return NULL
   return NULL;
}


/* ------------------------------------------------------------------------
   Name - add_next_process
   Purpose - Adds a process to the ready list at the appropriate priority level
   Parameters - 
      input: proc_ptr - Pointer to the process to be added to the ready list
   Returns - void
   Side Effects - Modifies the ready list
   ----------------------------------------------------------------------- */
void add_next_proc(proc_ptr input)
{
   int pri = input->priority; // Get the priority of the input process
   
   // Check if there's already a process at the same priority level
   if (ReadyList[pri] != NULL)
   {
      proc_ptr src = ReadyList[pri]; // Start from the head of the list at this priority level
      
      // Traverse the list to find the last process
      while (src->next_proc_ptr != NULL)
      {
         src = src->next_proc_ptr;
      }
      
      // Add the input process to the end of the list
      src->next_proc_ptr = input;
   }
   else
   {
      // If no process exists at this priority level, add the input process as the first process
      ReadyList[pri] = input;
   }
}


/* ------------------------------------------------------------------------
   Name - zap
   Purpose - Attempts to terminate a process with the given process ID (pid)
   Parameters - 
      pid: int - Process ID of the process to be terminated
   Returns - 
      int: 0 if successful, -1 if the current process was zapped during execution
   Side Effects - May modify process status and ready lists
   ----------------------------------------------------------------------- */
int zap(int pid)
{
   // Check if the function is called from kernel mode
if (check_mode() == 0) {
   console("Zap called in user mode. Unable to proceed. Halting execution. Process ID: %d\n", pid);
   halt(1);
}

   
   // Check if the process attempts to zap itself
   if (getpid() == pid)
   {
      console("The program attempted to terminate itself. This action is not allowed. Process ID: %d \n", pid);
      halt(1);
   }
   
   int i = 0;
   // Find the index of the process with the given process ID (pid)
   while (pid != ProcTable[i].pid)
   {
      i++;
      // If the process does not exist, halt the system
      if (i > 50)
      {
         console("The program attempted to terminate a non-existent process. Calling process ID: %d, Target process ID to terminate: %d\n", Current->pid, pid);
         halt(1);
      }
   }

   // Block the current process and update its status
   proc_blocked(Current);
   proc_ptr blocked_ptr = Current;
   proc_ptr zapped_proc = &ProcTable[i];
   blocked_ptr->blocked_by = zapped_proc->pid;
   zapped_proc->zapped = 1;

   // If the zapped process has already quit, remove it from the blocked list
   if (zapped_proc->status == QUIT)
   {
      removeProcessWithoutRequeue(blocked_ptr);
      zapped_proc->zapped = 0;
      return 0;
   }

   // Set the current process status to ZAP_BLOCK and invoke the dispatcher
   blocked_ptr->status = ZAP_BLOCK;
   dispatcher();

   // If the current process was zapped during execution, return -1
   if (Current->zapped == 1)
   {
      return -1;
   }
   
   zapped_proc->zapped = 0;
   return 0; // Return 0 indicating successful termination
}


int is_zapped(void)
{
   return Current->zapped;
}

int getpid(void)
{
   return Current->pid;
}

/* ------------------------------------------------------------------------
   Name - time_slice
   Purpose - Checks if the current process has exceeded its time slice and dispatches a new process if necessary
   Parameters - none
   Returns - void
   Side Effects - May modify process status and ready lists
   ----------------------------------------------------------------------- */
void time_slice(void) {
    unsigned int current_time = sys_clock(); // Get current system time
    unsigned int time_since_start = current_time - Current->startTime;

    // Check if the current process has exceeded its time slice
    if (time_since_start > TIME_SLICE_DURATION) {
        // Update process timing information
        Current->lastRunTime = current_time;
        Current->total_time += time_since_start;
        Current->status = READY;

        // Re-add the current process to the ready list and dispatch a new process
        add_next_proc(Current);
        dispatcher();
    }
    // If the process has not exceeded its time slice, it continues execution
}


/* ------------------------------------------------------------------------
   Name - proc_blocked
   Purpose - Adds a process to the blocked list at the appropriate priority level if it's not already present
   Parameters - 
      input: proc_ptr - Pointer to the process to be added to the blocked list
   Returns - void
   Side Effects - Modifies the blocked list
   ----------------------------------------------------------------------- */
void proc_blocked(proc_ptr input)
{

   int pri = input->priority; // Get the priority of the input process

   // Check if there's already a process at the same priority level in the blocked list
   if (BlockedList[pri] != NULL)
   {
      proc_ptr src = BlockedList[pri]; // Start from the head of the list at this priority level

      // Check if the input process is already in the blocked list
      if (src->pid == input->pid)
      {
         return; // If the process is already in the list, do nothing
      }

      // Traverse the list to find the last process
      while (src->next_proc_ptr != NULL)
      {
         // Check if the input process is already in the list
         if (src->pid != input->pid)
         {
            src = src->next_proc_ptr; // Move to the next process
         }
         else
         {
            return; // If the process is already in the list, do nothing
         }
      }
      
      // Add the input process to the end of the list
      src->next_proc_ptr = input;
   }
   else
   {
      // If no process exists at this priority level in the blocked list, add the input process as the first process
      BlockedList[pri] = input;
   }
}



/* ------------------------------------------------------------------------
   Name - remove_from_block_list
   Purpose - Removes a process from the blocked list
   Parameters - 
      input: proc_ptr - Pointer to the process to be removed from the blocked list
   Returns - void
   Side Effects - Modifies the blocked list
   ----------------------------------------------------------------------- */
void removeFromBlockList(proc_ptr input)
{
   int found = 0, i = 0;

   // Iterate through the blocked list until the process is found
   while (!found)
   {
      proc_ptr next_ptr = BlockedList[i];
      
      // Iterate through the processes at the current priority level
      while (next_ptr != NULL)
      {
         // Move to the next process until the target process is found
         while (next_ptr != NULL && next_ptr->pid != input->pid)
         {
            next_ptr = next_ptr->next_proc_ptr;
         }

         // If the target process is found
         if (next_ptr != NULL && next_ptr->pid == input->pid)
         {
            // Remove the process from the blocked list
            BlockedList[i] = next_ptr->next_proc_ptr;
            next_ptr->next_proc_ptr = NULL;
            next_ptr->blocked_by = 0;

            // Add the removed process to the ready list
            add_next_proc(next_ptr);
            return;
         }
      }
      i++; // Move to the next priority level if the process is not found
   }
}





/* ------------------------------------------------------------------------
   Name - removeProcessWithoutRequeue
   Purpose - Removes a process from the blocked list without adding it to the ready list
   Parameters - 
      input: proc_ptr - Pointer to the process to be removed from the blocked list
   Returns - void
   Side Effects - Modifies the blocked list
   ----------------------------------------------------------------------- */
void removeProcessWithoutRequeue(proc_ptr input) {
    
    for (int i = 0; BlockedList[i] != NULL; i++) { // Iterate through each entry in the BlockedList
        proc_ptr prev_ptr = NULL;
        proc_ptr current_ptr = BlockedList[i];
        
        while (current_ptr != NULL) { // Traverse through the linked list of processes
            if (current_ptr->pid == input->pid) { // Process found
                // If it's the first process in the list, adjust the head of the list
                if (prev_ptr == NULL) {
                    BlockedList[i] = current_ptr->next_proc_ptr;
                } else {
                    // Bypass the found process in the linked list
                    prev_ptr->next_proc_ptr = current_ptr->next_proc_ptr;
                }
                current_ptr->next_proc_ptr = NULL; // Disconnect the found process from the list
                current_ptr->blocked_by = 0; // Clear the blocking relationship
                return; // Exit the function as the process has been removed
            }
            prev_ptr = current_ptr; // Move prev_ptr forward
            current_ptr = current_ptr->next_proc_ptr; // Proceed to the next process
        }
    }
}




/* ------------------------------------------------------------------------
   Name - block_me
   Purpose - Changes the status of the current process to a blocked state and dispatches a new process
   Parameters - 
      new_status: int - New status to set for the current process (e.g., BLOCKED, ZAP_BLOCK, etc.)
   Returns - 
      int: 0 if successful, -1 if the current process was zapped during execution
   Side Effects - May modify process status and blocked lists
   ----------------------------------------------------------------------- */
int block_me(int new_status) {
    // Directly update the status of the current process
    Current->status = new_status;

    // Add the current process to the blocked list
    proc_blocked(Current);

    // Dispatch a new process
    dispatcher();

    // Check if the current process was zapped, return -1 if true
    return Current->zapped ? -1 : 0; // ternary operator to return -1 if zapped, 0 if not
}




/* ------------------------------------------------------------------------
   Name - unblock_proc
   Purpose - Unblocks a process with the given process ID (pid) if it's blocked and changes its status to READY
   Parameters - 
      pid: int - Process ID of the process to be unblocked
   Returns - 
      int: 0 if the process was successfully unblocked and quit normally, -1 if the calling process was zapped,
           -2 if the process was not found in the process table or if its status is not greater than 10
   Side Effects - May modify process status and blocked lists
   ----------------------------------------------------------------------- */
int unblock_proc(int pid) {
    // Validate input PID
    if (pid <= 0) {
        return -2;
    }

    for (int i = 0; i < 50; i++) {
        // Check if current entry is valid and matches the given PID
        if (&ProcTable[i] != NULL && ProcTable[i].pid == pid) {
            // Check for invalid status or if it's attempting to unblock itself
            if (ProcTable[i].status <= 10 || ProcTable[i].pid == Current->pid) {
                return -2;
            }

            // Unblock the process by removing it from the blocked list and setting its status to READY
            removeFromBlockList(&ProcTable[i]);
            ProcTable[i].status = READY;

            // Dispatch the process until it quits or gets zapped
            while (ProcTable[i].status != ZAP_BLOCK && ProcTable[i].status != QUIT) {
                dispatcher();
            }

            // Determine the return value based on the process's final status
            return ProcTable[i].status == ZAP_BLOCK ? -1 : 0;
        }
    }

    // If we reach this point, the process was not found
    return -2;
}




void dump_processes(void) {
    printf("PID\tParent\tPriority\tStatus\t\tNum Kids\tTime Used\tName\n");

    for (int i = 0; i < 50; i++) {
        char *status;

        // Determine status string
        if (ProcTable[i].status >= 10) {
            status = "SPECIAL"; // Assuming "SPECIAL" is a placeholder for statuses >= 10
        } else {
            switch (ProcTable[i].status) {
                case 0: status = "EMPTY"; break;
                case READY: status = "READY"; break;
                case RUNNING: status = "RUNNING"; break;
                case JOIN_BLOCK: status = "JOIN BLOCKED"; break;
                case ZAP_BLOCK: status = "ZAP BLOCKED"; break;
                case BLOCKED: status = "BLOCKED"; break;
                case QUIT: status = "QUIT"; break;
                default: status = "UNKNOWN"; // Handle unexpected status values
            }
        }

        // Print process details
        printf("%d\t%d\t\t%d\t%s\t%d\t\t%d\t\t%s\n",
               ProcTable[i].pid, ProcTable[i].parent_pid, ProcTable[i].priority,
               status, ProcTable[i].kids, ProcTable[i].total_time, ProcTable[i].name);
    }
}
