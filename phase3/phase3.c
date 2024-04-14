#include <usloss.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>
#include <sems.h>
#include <libuser.h>
#include <usyscall.h>
#include "main.h"
#include "usloss/include/phase2.h"



/**------------------------------ Start Functions ------------------------------**/
int start2(char *);
extern int start3();

/**------------------------------ Prototypes ------------------------------**/
int spawn_real(char *name,
               int (*func)(char *),
               char *arg,
               int stack_size,
               int priority);
int wait_real(int *status);
void terminate_real(int exit_code);
int sem_creat_real(int init_value);
int semP_real(int semaphore);
int semV_real(int semaphore);
int semFree_real(int semaphore);


static void sysSpawn(sysargs *args);
static void sysWait(sysargs *args);
static void sysTerminate(sysargs *args);
static void sysSemCreate(sysargs *args);
static void sysSemV(sysargs *args);
static void sysSemP(sysargs *args);
static void sysSemFree(sysargs *args);
static void sysGetTimeOfDay(sysargs *args);
static void sysCPUTime(sysargs *args);
static void sysGetPID(sysargs *args);


void check_kernel_mode(const char *functionName);
void DebugConsole3(char *format, ...);

void nullsys3(sysargs *args);
void enableUserMode();
static int spawn_launch(char *arg);

/** ------------------------------ Globals ------------------------------ **/

/* Flags */
int debugFlag = 1;

/* General Globals */
int start2Pid = 0;      //start2 PID

/* Process Globals */
usr_proc_struct UsrProcTable[MAXPROC];      //Process Table
int totalProc;           //total Processes
unsigned int nextPID;    //next process id

/* Semaphore Globals */
semaphore_struct SemaphoreTable[MAXSEMS];   //Semaphore Table
int totalSem;            //total Semaphores
unsigned int nextSID;    //next semaphore id

/** ----------------------------- Functions ----------------------------- **/

/* ------------------------------------------------------------------------
  Name -            start2
  Purpose -         Phase 3 entry point. Initializes UsrProcTable,
                    SemaphoreTable, and sys_vec and creates process
                    mailboxes
  Parameters -      *arg:   default arg passed by fork1
  Returns -         0:      indicates normal quit
  Side Effects -    lots since it initializes the phase3 data structures.
  ----------------------------------------------------------------------- */
int start2(char *arg) {
    /*** Function Initialization ***/
    int		pid;
    int		status;

  // Ensure this function is called in kernel mode
    check_kernel_mode(__func__);

    // Initialize user process and semaphore tables
    memset(UsrProcTable, -1, sizeof(UsrProcTable));
    memset(SemaphoreTable, -1, sizeof(SemaphoreTable));

    // Reset global counters
    totalProc = 0;
    totalSem = 0;

    // Store the PID of this process
    start2Pid = getpid();

    // Create mailboxes for each process
    for (int i = 0; i < MAXPROC; i++) {
        UsrProcTable[i].mboxID = MboxCreate(1, 4);
    }

    // Set default syscall handlers to a null operation
    for (int i = 0; i < MAXSYSCALLS; i++) {
        sys_vec[i] = nullsys3;
    }


    /*** Set sys_vec Calls ***/
    sys_vec[SYS_SPAWN] = sysSpawn;
    sys_vec[SYS_WAIT] = sysWait;
    sys_vec[SYS_TERMINATE] = sysTerminate;
    sys_vec[SYS_SEMCREATE] = sysSemCreate;
    sys_vec[SYS_SEMV] = sysSemV;
    sys_vec[SYS_SEMP] = sysSemP;
    sys_vec[SYS_SEMFREE] = sysSemFree;
    sys_vec[SYS_GETTIMEOFDAY] = sysGetTimeOfDay;
    sys_vec[SYS_CPUTIME] = sysCPUTime;
    sys_vec[SYS_GETPID] = sysGetPID;

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

    /*** Create and Run start3 ***/
    pid = spawn_real("start3", start3, NULL, 4*USLOSS_MIN_STACK, 3);
    pid = wait_real(&status);

    return 0;

} /* start2 */


/* ------------------------------------------------------------------------
  Name -            sysSpawn [spawn]
  Purpose -         Initiates a user-level process.
  Parameters -      systemArgs *args
                        args->arg1: Address of the function to spawn.
                        args->arg2: Parameter passed to the spawned function.
                        args->arg3: Stack size in bytes.
                        args->arg4: Priority.
                        args->arg5: Name of the process.
  Returns -         Void. Sets arg values:
                    args->arg1:    -1 if process creation fails,
                                    process ID otherwise.
                    args->arg4:    -1 if illegal values are input,
                                    0 otherwise.
  Side Effects -    Calls spawn_real, alters process table.
  ----------------------------------------------------------------------- */
static void sysSpawn(sysargs *args) {
    // Function pointers to the user function and local variables for process parameters
    int (*func)(char *);
    char arg[MAXARG];
    unsigned int stackSize;
    int priority;
    char name[MAXNAME];
    int kidpid;

    // Verify running in kernel mode
    check_kernel_mode(__func__);

    // Ensure the argument pointer is not NULL
    if (args == NULL) {
        DebugConsole3("Error: NULL args pointer\n");
        terminate_real(1);
    }

    // Check if the current process has been zapped (interrupted)
    if (is_zapped()) {
        DebugConsole3("Process zapped during syscall.\n");
        terminate_real(1);
    }

    // Extract the function pointer from the args
    func = args->arg1;

    // Extract the argument for the process from the args, ensuring it exists
    if (args->arg2) {
        strcpy(arg, args->arg2);
    }

    // Extract the stack size from the args
    stackSize = (unsigned int) args->arg3;

    // Extract the priority for the process from the args
    priority = (int) args->arg4;

    // Extract the name of the process, ensuring it exists
    if (args->arg5) {
        strcpy(name, args->arg5);
    }

    // Validate the priority of the process
    if (priority > LOWEST_PRIORITY || priority < HIGHEST_PRIORITY) {
        DebugConsole3("%s: Invalid priority level [%d]. Valid range is [%d - %d].\n",
                      __func__, priority, HIGHEST_PRIORITY, LOWEST_PRIORITY);
        terminate_real(1);
    }

    // Check for null function pointer
    if (func == NULL) {
        DebugConsole3("%s: Null function pointer.\n", __func__);
        terminate_real(1);
    }

    // Check for an empty process name
    if (name[0] == '\0') {
        DebugConsole3("%s: Process name is empty.\n", __func__);
        terminate_real(1);
    }

    // Validate the stack size
    if (stackSize < USLOSS_MIN_STACK) {
        DebugConsole3("%s: Stack size [%u] is below the minimum [%d].\n",
                      __func__, stackSize, USLOSS_MIN_STACK);
        terminate_real(1);
    }

    // Spawn the user process and store the returned PID
    kidpid = spawn_real(name, func, arg, stackSize, priority);

    // Set return values in args
    args->arg1 = (void *) kidpid;
    args->arg4 = (void *)(kidpid == -1 ? -1 : 0);

    // Check again if the process was zapped after system call execution
    if (is_zapped()) {
        DebugConsole3("Process zapped after syscall.\n");
        terminate_real(1);
    }

    // Transition to user mode after system call completion
    enableUserMode();

    return;
}



/* ------------------------------------------------------------------------
  Name -            spawn_real [spawnReal]
  Purpose -         Creates a user-level process. This function sets up
                    necessary structures including UsrProcTable, SemaphoreTable,
                    and sys_vec, and it also initializes process mailboxes.
  Parameters -      name:        String containing the process's name.
                    func:        Address of the function to spawn.
                    arg:         Parameter passed to the spawned function.
                    stack_size:  Stack size in bytes.
                    priority:    Process priority.
  Returns -         PID of the newly created process if successful (>0),
                    -1 if there are invalid parameters or the process could not be created.
                     0 in other cases.
  Side Effects -    Calls fork1, updates UsrProcTable and process lists.
  ----------------------------------------------------------------------- */
int spawn_real(char *name, int (*func)(char *), char *arg, int stack_size, int priority) {
    int kidPID;       // PID of the newly created child process
    int curIndex;     // Index of the current process in the process table
    int kidIndex;     // Index of the child process in the process table
    int result;       // Result from mailbox conditional send
    usr_proc_ptr pKid, pCur; // Pointers to the child and current process structures

    // Ensure the function is called in kernel mode
    check_kernel_mode(__func__);

    // Find the index of the current process
    curIndex = GetProcIndex(getpid());

    // Create the child process
    kidPID = fork1(name, spawn_launch, arg, stack_size, priority);

    // Check if the PID returned from fork1 is valid
    if (kidPID < 0) {
        DebugConsole3("%s: Fork failed to create a new process.\n", __func__);
        return -1;
    }

    // Add the child process to the process table
    AddToProcTable(STATUS_READY, name, kidPID, func, arg, stack_size, priority);

    // Create a pointer to the child process entry
    kidIndex = GetProcIndex(kidPID);
    pKid = &UsrProcTable[kidIndex];

    // Link the child process to the parent's list of children if it has a valid parent
    if (pKid->parentPID > start2Pid) {
        pCur = &UsrProcTable[curIndex];
        AddProcessLL(pKid, &pCur->children);
    }

    // Attempt to send a conditional message to the child's mailbox
    result = MboxCondSend(pKid->mboxID, NULL, 0);

    // Check the result of the conditional send
    if (result == -1) {
        DebugConsole3("%s: Illegal arguments used within MboxCondSend.\n", __func__);
        return -1;
    } else if (result == -3) {
        DebugConsole3("%s: Process was zapped or mailbox was released while the process was blocked.\n", __func__);
        return -1;
    }

    // Return the PID of the newly created process
    return kidPID;
} /* spawn_real */



/* ------------------------------------------------------------------------
  Name -            spawn_launch
  Purpose -         Executes process passed to sysSpawn
  Parameters -      arg:    function argument
  Returns -          0: Success
                    -1: Illegal arguments used within MboxSend(),
                        Sent message exceeds max size,
                        Process was zapped,
                        mailbox was released while process was blocked
  Side Effects -    Provides process error checking, synchronization,
                    function execution, and termination
  ----------------------------------------------------------------------- */
static int spawn_launch(char *arg) {
    /*** Function Initialization ***/
    int my_location;
    int result;
    usr_proc_ptr pProc;

    /*** Check for Kernel Mode ***/
    check_kernel_mode(__func__);

    /*** Create Current Pointer ***/
    my_location = getpid() % MAXPROC;
    pProc = &UsrProcTable[my_location];

    /*** Error Check: Process Not on ProcTable ***/
    if (pProc->pid != getpid()) {
        int mailboxID = MboxCreate(0, 0);
        UsrProcTable[my_location].mboxID = mailboxID;
        result = MboxReceive(mailboxID, NULL, 0);

        /*** Error Check: MboxReceive Return Value ***/
        if (result == -1) {
            DebugConsole3("%s : Illegal arguments used within MboxReceive() or message sent exceeds max size.\n",
                          __func__);
            return -1;
        }
        else if (result == -3) {
            DebugConsole3("%s : Process was zapped or mailbox was released while the process was blocked.\n",
                          __func__);
            return -1;
        }
    }
    else{
        /*** Synchronize with Parent Process ***/
        result = MboxReceive(pProc->mboxID, 0, 0);

        /*** Error Check: MboxReceive Return Value ***/
        if (result == -1) {
            DebugConsole3("%s : Illegal arguments used within MboxReceive() or message sent exceeds max size.\n",
                          __func__);
            return -1;
        }
        else if (result == -3) {
            DebugConsole3("%s : Process was zapped or mailbox was released while the process was blocked.\n",
                          __func__);
            return -1;
        }
    }

    UsrProcTable[my_location].status = STATUS_READY; // update status

    /*** Get Start Function and Arguments ***/
    if (!is_zapped()) {
        enableUserMode();

        if (*arg == -1 || *arg == 0) {
            result = pProc->startFunc(NULL);
        }
        else {
            result = pProc->startFunc(pProc->startArg);
        }

        Terminate(result);
    }
    else {
        terminate_real(0);
    }

    /*** Error Check: Termination Failure ***/
    DebugConsole3("%s : Termination Failure.\n", __func__);

    return 0;

} /* spawn_launch */


/* ------------------------------------------------------------------------
  Name -            sysWait [wait]
  Purpose -         Waits for a child process to terminate and retrieves its status.
  Parameters -      systemArgs *args
  Returns -         Void. Modifies arg values:
                    args->arg1: PID of the terminating child process.
                    args->arg2: Termination status of the child.
                    args->arg4: -1 if the process has no children,
                                 0 otherwise.
  Side Effects -    The process may terminate if it is zapped while waiting.
                    Calls wait_real to suspend execution until a child terminates.
  ----------------------------------------------------------------------- */
static void sysWait(sysargs *args) {
    int status;  // Variable to hold the termination status of the child process
    int pid;     // Variable to hold the PID of the terminated child process

    // Verify that the function is running in kernel mode
    check_kernel_mode(__func__);

    // Call wait_real to suspend the current process until one of its children terminates
    pid = wait_real(&status);

    // Check if the current process was zapped while waiting
    if (is_zapped()) {
        DebugConsole3("Process was zapped while waiting on a child.\n");
        terminate_real(1);  // Terminate the current process if it was zapped
    }

    // Package the PID and termination status of the child into the args structure
    args->arg1 = (void *) pid;
    args->arg2 = (void *) status;

    // Determine if the process had no children and set args->arg4 accordingly
    args->arg4 = (void *)(pid == -2 ? -1 : 0);

    // Transition to user mode after system call completion
    enableUserMode();

    return;
} /* sysWait */



/* ------------------------------------------------------------------------
  Name -            wait_real [waitReal]
  Purpose -         Handles the termination of a child process. This function is
                    called by sysWait to update the UsrProcTable and manage process
                    termination through the join function.
  Parameters -      status: Pointer to an integer where the termination status of the child
                    will be stored.
  Returns -         PID of the terminated child if successful (>0),
                    -1 if the process was zapped while waiting in join,
                    -2 if the process has no children.
  Side Effects -    Modifies UsrProcTable; the result is used by sysWait.
  ----------------------------------------------------------------------- */
int wait_real(int *status) {
    int index;  // Index of the current process in the UsrProcTable

    // Ensure the function is running in kernel mode
    check_kernel_mode(__func__);

    // Calculate index of the current process in the UsrProcTable using its PID
    index = getpid() % MAXPROC;

    // Set the process status to indicate it is waiting for a child to terminate
    UsrProcTable[index].status = STATUS_JOIN_BLOCK;

    // Call join to wait for a child process to terminate and retrieve its PID
    return join(status);
} /* wait_real */



/* ------------------------------------------------------------------------
  Name -            sysTerminate [terminate]
  Purpose -         Terminates the invoking process along with all of its children.
                    This function also synchronizes termination with the parent process
                    by supporting the parent's Wait system call.
  Parameters -      systemArgs *args
                        args->arg1: Termination code for the process.
  Returns -         None.
  Side Effects -    Uses the termination code from args->arg1 to call terminate_real,
                    affecting the process and its children.
  ----------------------------------------------------------------------- */
static void sysTerminate(sysargs *args) {
    int status;  // Variable to store the termination status passed by the invoking process

    // Ensure the function is executed in kernel mode
    check_kernel_mode(__func__);

    // Retrieve the termination status from the passed system arguments
    status = (int) args->arg1;

    // Call the kernel-level terminate function with the retrieved status
    terminate_real(status);

    // Transition to user mode before returning control to the system
    enableUserMode();

    return;
} /* sysTerminate */



/* ------------------------------------------------------------------------
  Name -            terminate_real
  Purpose -         Terminates the invoking process and all its children, synchronizing
                    the termination with the parent's Wait system call.
  Parameters -      exit_code: Termination status to pass to the system.
  Returns -         None.
  Side Effects -    Zaps remaining children, updates parent's child list, reinitializes
                    the corresponding UserProcTable slot, and ultimately calls quit to
                    terminate the process.
  ----------------------------------------------------------------------- */
void terminate_real(int exit_code) {
    int pid;               // Process ID for operations
    int parentID;          // Parent process ID
    usr_proc_ptr pChild, pCurrent, pParent;  // Pointers to user process entries

    // Check that this function is running in kernel mode
    check_kernel_mode(__func__);

    // Retrieve the current process's entry in the UserProcTable
    pCurrent = &UsrProcTable[getpid() % MAXPROC];

    // Loop through and terminate all child processes
    while (pCurrent->children.total > 0) {
        // Remove the first child from the list
        pid = RemoveProcessLL(pCurrent->children.pHeadProc->pProc->pid, &pCurrent->children);
        pChild = &UsrProcTable[pid % MAXPROC];  // Get pointer to child's process entry
        pChild->parentPID = -1;                // Clear child's parent PID

        // Zap the child process, signaling it should terminate
        zap(pid);
    }

    // Handle removal from parent's child list if there's a valid parent
    parentID = pCurrent->parentPID;
    if (parentID > -1) {
        pParent = &UsrProcTable[parentID % MAXPROC];  // Get pointer to parent's process entry
        RemoveProcessLL(pCurrent->pid, &pParent->children);  // Remove current process from parent's child list
    }

    // Clear and reinitialize the process's slot in the UserProcTable
    ProcessInit(pCurrent->pid % MAXPROC, pCurrent->pid);

    // Terminate the current process by calling quit with the given exit code
    quit(exit_code);

    return;
} /* terminate_real */



/* ------------------------------------------------------------------------
  Name -            sysSemCreate [semCreate]
  Purpose -         Creates a user-level semaphore and initializes it with the provided value.
  Parameters -      systemArgs *args
                        args->arg1: Initial semaphore value (int).
  Returns -         None. Sets arg values:
                    args->arg1:    Semaphore ID (sid) if creation was successful.
                    args->arg4:    -1 if no more semaphores are available or initial value is invalid,
                                    0 otherwise.
  Side Effects -    Calls sem_creat_real to manage semaphore creation and updates system args.
  ----------------------------------------------------------------------- */
static void sysSemCreate(sysargs *args) {
    int value;      // Initial value for the semaphore
    int semaphore;  // ID for the newly created semaphore

    // Ensure the function is executed in kernel mode
    check_kernel_mode(__func__);

    // Retrieve the initial semaphore value from the system arguments
    value = (int) args->arg1;

    // Attempt to create a semaphore with the specified initial value
    semaphore = sem_creat_real(value);

    // Set the return value in the system arguments: Semaphore ID or -1 if an error occurred
    args->arg1 = (void *)semaphore;

    // Check if the semaphore creation failed due to no more semaphores being available or invalid initial value
    args->arg4 = (void *)(semaphore == -1 ? -1 : 0);

    // Switch the mode back to user mode before exiting the function
    enableUserMode();

    return;
} /* sysSemCreate */



/* ------------------------------------------------------------------------
  Name -            sem_creat_real
  Purpose -         Creates a new semaphore with a specified initial value.
                    This function manages the allocation of semaphore resources
                    within the system.
  Parameters -      init_value: The initial value for the semaphore, which
                    must not be negative.
  Returns -         sid: Semaphore ID on success, -1 if initialization fails
                    due to invalid value or no available semaphores.
  Side Effects -    Updates SemaphoreTable to include the new semaphore and
                    modifies the totalSem count.
  ----------------------------------------------------------------------- */
int sem_creat_real(int init_value) {
    int sid = -1;  // Default to an invalid semaphore ID

    // Ensure the function is executed in kernel mode
    check_kernel_mode(__func__);

    // Check if the initial value is negative
    if (init_value < 0) {
        DebugConsole3("%s: Initial value cannot be negative.\n", __func__);
        return -1;
    }

    // Check if there are semaphores available in the semaphore table
    if (totalSem >= MAXSEMS) {
        DebugConsole3("%s: Maximum number of semaphores reached. No more available.\n", __func__);
        return -1;
    }

    // Search for an available slot in the semaphore table
    for (int i = 0; i < MAXSEMS; i++) {
        if (SemaphoreTable[i].sid == -1) {
            sid = i;  // Set the sid to the current index
            break;    // Exit the loop as we found an available slot
        }
    }

    // If sid remains -1, no available slots were found
    if (sid == -1) {
        DebugConsole3("%s: Failed to find an available semaphore slot.\n", __func__);
        return -1;
    }

    // Increment the global semaphore count
    totalSem++;

    // Initialize the semaphore in the table
    AddToSemTable(sid, SEM_READY, init_value);

    // Return the semaphore ID
    return sid;
} /* sem_creat_real */



/* ------------------------------------------------------------------------
  Name -            sysSemV [SemV]
  Purpose -         Performs a "V" operation (signal) on a semaphore, effectively
                    incrementing its value and potentially releasing a waiting process.
  Parameters -      systemArgs *args
                        args->arg1: Semaphore handle (sid).
  Returns -         Void. Modifies system argument values to reflect operation success:
                    args->arg4:    -1 if the semaphore handle is invalid,
                                    0 otherwise.
  Side Effects -    Calls semV_real to perform the semaphore operation.
  ----------------------------------------------------------------------- */
static void sysSemV(sysargs *args) {
    int handler;  // The semaphore ID from system arguments

    // Ensure the function is executed in kernel mode
    check_kernel_mode(__func__);

    // Retrieve the semaphore handle from the system arguments
    handler = (int) args->arg1;

    // Validate the semaphore handle by checking it exists in the semaphore table
    if (SemaphoreTable[handler % MAXSEMS].sid != handler) {
        // If the semaphore handle is invalid, set the error flag and switch to user mode
        args->arg4 = (void *) -1;
        enableUserMode();
        return;
    }

    // Perform the "V" operation using the kernel function semV_real
    int result = semV_real(handler);
    // Set the output argument to indicate success (semV_real should handle its own errors if any)
    args->arg4 = (void *) (result == -1 ? -1 : 0);

    // Switch back to user mode before returning to the caller
    enableUserMode();

    return;
} /* sysSemV */



/* ------------------------------------------------------------------------
  Name -            semV_real [semV_real]
  Purpose -         Performs a "V" (signal) operation on a semaphore, which increments
                    its value. This can potentially unblock a process waiting on this semaphore.
  Parameters -      semaphore: Semaphore ID (sid).
  Returns -         0: Successful operation.
                    -1: Failure due to illegal arguments in MboxSend(),
                        the process being zapped, or the mailbox being released while
                        the process was blocked.
  Side Effects -    Unblocks processes that are blocked on this semaphore and
                    increments the semaphore value by one if no processes are blocked.
  ----------------------------------------------------------------------- */
int semV_real(int semaphore) {
    sem_struct_ptr sem;   // Pointer to semaphore structure
    usr_proc_ptr proc;    // Pointer to user process structure
    int pid;              // Process ID of the process to unblock
    int result;           // Result from MboxSend operation
    int headPID;          // Process ID of the head process in the blocked list

    // Ensure the function is executed in kernel mode
    check_kernel_mode(__func__);

    // Retrieve the semaphore from the SemaphoreTable using the provided semaphore ID
    sem = &SemaphoreTable[semaphore % MAXSEMS];

    // Check if there are any processes blocked on this semaphore
    if (sem->blockedProcs.total > 0) {
        // Retrieve the PID of the process at the head of the blocked list
        pid = sem->blockedProcs.pHeadProc->pProc->pid;
        headPID = RemoveProcessLL(pid, &sem->blockedProcs);
        proc = &UsrProcTable[headPID % MAXPROC];

        // Attempt to unblock the process using MboxSend
        result = MboxSend(proc->mboxID, NULL, 0);

        // Check the result of the MboxSend operation
        if (result == -1) {
            DebugConsole3("%s : Illegal arguments used within MboxSend().\n", __func__);
            return -1;
        } else if (result == -3) {
            DebugConsole3("%s : Process was zapped or mailbox was released while the process was blocked.\n", __func__);
            return -1;
        }
    } else {
        // If no processes are blocked, simply increment the semaphore value
        sem->value++;
    }

    return 0;
} /* semV_real */


/* ------------------------------------------------------------------------
  Name -            sysSemP [SemP]
  Purpose -         Performs a "P" operation on a semaphore, which decrements
                    its value. This operation may block the calling process if the
                    semaphore value is zero or less.
  Parameters -      systemArgs *args
                        args->arg1: Semaphore handle (sid).
  Returns -         Void. Modifies system argument values to reflect operation success:
                    args->arg4: -1 if the semaphore handle is invalid,
                                 0 otherwise.
  Side Effects -    Calls semP_real to perform the semaphore operation.
  ----------------------------------------------------------------------- */
static void sysSemP(sysargs *args) {
    int handler;  // The semaphore ID from system arguments

    // Ensure the function is executed in kernel mode
    check_kernel_mode(__func__);

    // Retrieve the semaphore handle from the system arguments
    handler = (int) args->arg1;

    // Validate the semaphore handle by checking it exists in the semaphore table
    if (SemaphoreTable[handler % MAXSEMS].sid != handler) {
        // If the semaphore handle is invalid, set the error flag and switch to user mode
        args->arg4 = (void *) -1;
        enableUserMode();
        return;
    }

    // Perform the "P" operation using the kernel function semP_real
    int result = semP_real(handler);
    // Set the output argument based on the result of the kernel semaphore operation
    args->arg4 = (void *)(result == -1 ? -1 : 0);

    // Switch back to user mode before returning to the caller
    enableUserMode();

    return;
} /* sysSemP */




/* ------------------------------------------------------------------------
  Name -            semP_real [semP_real]
  Purpose -         Performs a "P" operation on a semaphore, decrementing its value.
                    This may block the process if the semaphore's value is zero or less.
  Parameters -      semaphore: Semaphore ID (sid) to operate on.
  Returns -         0: Success.
                    -1: Failure due to illegal arguments in MboxReceive(),
                        the sent message exceeds the maximum size,
                        the process was zapped, or
                        the mailbox was released while the process was blocked.
  Side Effects -    Potentially blocks the calling process and decrements the semaphore's
                    value by one. May terminate the process if the semaphore is freed
                    during the operation.
  ----------------------------------------------------------------------- */
int semP_real(int semaphore) {
    sem_struct_ptr sem;    // Pointer to the semaphore structure
    usr_proc_ptr proc;     // Pointer to the current process structure
    int result;            // Result from the MboxReceive operation

    // Ensure the function is executed in kernel mode
    check_kernel_mode(__func__);

    // Retrieve the semaphore from the SemaphoreTable using the provided semaphore ID
    sem = &SemaphoreTable[semaphore % MAXSEMS];

    // If the semaphore value is greater than zero, decrement it
    if (sem->value > 0) {
        sem->value--;
    }
    // If the semaphore value is zero or less, block the process
    else {
        // Add the current process to the semaphore's blocked list
        proc = &UsrProcTable[getpid() % MAXPROC];
        AddProcessLL(proc, &sem->blockedProcs);

        // Block the process by receiving a message (simulating a wait state)
        result = MboxReceive(proc->mboxID, NULL, 0);

        // Check the result of the MboxReceive operation
        if (result == -1) {
            DebugConsole3("%s : Illegal arguments within MboxReceive() or message exceeds max size.\n",
                          __func__);
            return -1;
        } else if (result == -3) {
            DebugConsole3("%s : Process was zapped or mailbox was released while blocked.\n",
                          __func__);
            return -1;
        }

        // If the semaphore was freed while the process was blocked, terminate the process
        if (sem->status == FREEING) {
            enableUserMode();
            Terminate(1);
        }
    }

    return 0;
} /* semP_real */



/* ------------------------------------------------------------------------
  Name -            sysSemFree [SemFree]
  Purpose -         Frees a specified semaphore and handles any processes that
                    might be blocked on it.
  Parameters -      systemArgs *args
                        args->arg1: Semaphore handle (sid).
  Returns -         Void. Sets arg values based on the outcome:
                    args->arg4:    -1 if the semaphore handle is invalid,
                                    1 if there were processes blocked on the semaphore,
                                    0 otherwise.
  Side Effects -    Calls semFree_real to manage the actual freeing of the semaphore,
                    potentially unblocking any processes and updating internal structures.
  ----------------------------------------------------------------------- */
static void sysSemFree(sysargs *args) {
    int handler;  // The semaphore ID from system arguments

    // Retrieve the semaphore handle from the system arguments
    handler = (int) args->arg1;

    // Validate the semaphore handle by checking it exists in the semaphore table
    if (SemaphoreTable[handler % MAXSEMS].sid != handler) {
        // If the semaphore handle is invalid, set the error flag
        args->arg4 = (void *) -1;
        enableUserMode();  // Switch back to user mode before returning
        return;
    }

    // Call the kernel function to free the semaphore and capture the result
    int result = semFree_real(handler);
    // Set the output argument based on the result of the kernel semaphore free operation
    args->arg4 = (void *)result;

    // Switch back to user mode before returning to the caller
    enableUserMode();

    return;
} /* sysSemFree */



/* ------------------------------------------------------------------------
  Name -            semFree_real
  Purpose -         Frees a semaphore and handles any processes that might be
                    blocked on it. If processes are blocked, it attempts to unblock them.
  Parameters -      semaphore: Semaphore ID (sid).
  Returns -         0: Success and no processes were blocked.
                    -1: Failure due to illegal arguments in MboxSend() or
                        if a process was zapped or mailbox was released while blocked.
                     1: Success but there were processes blocked on the semaphore.
  Side Effects -    Reinitializes the semaphore slot or unblocks blocked processes,
                    potentially terminating them if the semaphore is being freed.
  ----------------------------------------------------------------------- */
int semFree_real(int semaphore) {
    sem_struct_ptr sem;   // Pointer to semaphore structure
    usr_proc_ptr proc;    // Pointer to user process structure
    int pid;              // Process ID for operations
    int result;           // Result from MboxSend operation

    // Retrieve the semaphore from the SemaphoreTable using the provided semaphore ID
    sem = &SemaphoreTable[semaphore % MAXSEMS];

    // Check if there are no processes blocked on the semaphore
    if (sem->blockedProcs.total == 0) {
        // Reinitialize the semaphore slot and decrement the total semaphore count
        SemaphoreInit(semaphore % MAXSEMS, sem->sid);
        totalSem--;
    } else {
        // If processes are blocked, mark the semaphore status as freeing
        sem->status = FREEING;

        // Unblock all processes from the blocked list
        while (sem->blockedProcs.total > 0) {
            pid = sem->blockedProcs.pHeadProc->pProc->pid;
            RemoveProcessLL(pid, &sem->blockedProcs);
            proc = &UsrProcTable[pid % MAXPROC];

            // Attempt to unblock the process using MboxSend
            result = MboxSend(proc->mboxID, NULL, 0);

            // Check the result of the MboxSend operation
            if (result == -1) {
                DebugConsole3("%s: Illegal arguments within MboxSend().\n", __func__);
                return -1;
            } else if (result == -3) {
                DebugConsole3("%s: Process was zapped or mailbox was released while blocked.\n", __func__);
                return -1;
            }
        }

        // Return 1 to indicate successful freeing with blocked processes
        return 1;
    }

    // Return 0 to indicate successful freeing without any blocked processes
    return 0;
} /* semFree_real */



/* ------------------------------------------------------------------------
  Name -            sysGetTimeOfDay
  Purpose -         Retrieves the current value of the time-of-day clock.
  Parameters -      systemArgs *args
  Returns -         Void. Sets arg values:
                    args->arg1: Contains the time of day in milliseconds since 
                                system start or another significant event.
  Side Effects -    Assigns the current time of day to args->arg1.
  ----------------------------------------------------------------------- */
static void sysGetTimeOfDay(sysargs *args) {
    int time;  // Variable to hold the time of day from the system clock

    // Ensure the function is executed in kernel mode
    check_kernel_mode(__func__);

    // Call sys_clock to get the current time of day
    time = sys_clock();

    // Store the obtained time in the system arguments to pass back to the caller
    args->arg1 = (void *)time;

    // Switch back to user mode before returning to the system
    enableUserMode();
} /* sysGetTimeOfDay */



/* ------------------------------------------------------------------------
  Name -            sysCPUTime
  Purpose -         Retrieves the amount of CPU time consumed by the calling process.
  Parameters -      systemArgs *args
  Returns -         Void. Sets system argument values:
                    args->arg1: CPU time consumed by the process in ticks or milliseconds.
  Side Effects -    Populates args->arg1 with the CPU time of the process.
  ----------------------------------------------------------------------- */
static void sysCPUTime(sysargs *args) {
    int cpuTime;  // Variable to hold the CPU time used by the process

    // Ensure the function is executed in kernel mode
    check_kernel_mode(__func__);

    // Get the CPU time for the current process using readtime()
    cpuTime = readtime();

    // Store the obtained CPU time in the system arguments to pass back to the caller
    args->arg1 = (void *) cpuTime;

    // Switch back to user mode before returning to the system
    enableUserMode();
} /* sysCPUTime */



/* ------------------------------------------------------------------------
  Name -            sysGetPID
  Purpose -         Retrieves the process identifier (PID) of the currently executing process.
  Parameters -      systemArgs *args
  Returns -         Void. Sets system argument values:
                    args->arg1: PID of the currently running process.
  Side Effects -    Populates args->arg1 with the PID of the process.
  ----------------------------------------------------------------------- */
static void sysGetPID(sysargs *args) {
    int pid;  // Variable to hold the process ID

    // Ensure the function is executed in kernel mode
    check_kernel_mode(__func__);

    // Retrieve the PID of the current process
    pid = getpid();

    // Store the obtained PID in the system arguments to pass back to the caller
    args->arg1 = (void *) pid;

    // Switch back to user mode before returning to the system
    enableUserMode();
} /* sysGetPID */




/* ------------------------------------------------------------------------
   Name -           check_kernel_mode
   Purpose -        Validates that the current execution mode is kernel mode.
                    It is essential for certain operations that must not be run
                    in user mode due to security and stability reasons.
   Parameters -     functionName: The name of the function being verified.
   Returns -        None.
   Side Effects -   The system halts if it is not running in kernel mode when this
                    function is called, indicating a critical security violation.
   ----------------------------------------------------------------------- */
void check_kernel_mode(const char *functionName) {
    union psr_values psrValue; // Union to hold processor state register values

    // Fetch the current processor state register value
    psrValue.integer_part = psr_get();

    // Check if the current mode bit indicates user mode (0)
    if (psrValue.bits.cur_mode == 0) {
        // If in user mode, print error message and halt the system
        console("Kernel mode expected, but %s was called in user mode.\n", functionName);
        halt(1); // Halt system call, typically stops the processor/system
    }

    // Optional debug message to confirm kernel mode is set (commented out)
    // DebugConsole3("check_kernel_mode(): %s is verified in kernel mode.\n", functionName);
} /* check_kernel_mode */



/* ------------------------------------------------------------------------
   Name -           DebugConsole3
   Purpose -        Outputs debug messages to the console when debug mode is active.
   Parameters -     *format: Format string as per printf specifications.
                    ...: Variable arguments corresponding to the format string.
   Returns -        None.
   Side Effects -   If debugging is enabled, messages are printed to the standard output.
   ----------------------------------------------------------------------- */
void DebugConsole3(char *format, ...) {
    // Check if both DEBUG3 and debugFlag are enabled
    if (DEBUG3 && debugFlag) {
        va_list argptr;
        va_start(argptr, format);               // Initialize the argument list
        vfprintf(stdout, format, argptr);       // Print formatted string to stdout
        fflush(stdout);                         // Flush the output buffer
        va_end(argptr);                         // Clean up the argument list
    }
} /* DebugConsole3 */

/* ------------------------------------------------------------------------
  Name -            nullsys3
  Purpose -         Handles undefined or invalid system calls by terminating the process.
  Parameters -      systemArgs *args: System arguments that contain the syscall number.
  Returns -         None.
  Side Effects -    Terminates the process due to an invalid syscall invocation.
  ----------------------------------------------------------------------- */
void nullsys3(sysargs *args) {
    console("nullsys(): Invalid syscall %d. Halting...\n", args->number);  // Log the invalid syscall number
    terminate_real(1);  // Terminate the process with a general error status
} /* nullsys3 */


/* ------------------------------------------------------------------------
  Name -            enableUserMode
  Purpose -         Transitions the processor's execution mode from kernel to user.
  Parameters -      None.
  Returns -         None.
  Side Effects -    Changes the PSR to set the current execution mode to user.
  ----------------------------------------------------------------------- */
void enableUserMode() {
    psr_set(psr_get() & ~PSR_CURRENT_MODE);  // Clear the current mode bit of PSR to switch to user mode
} /* enableUserMode */

