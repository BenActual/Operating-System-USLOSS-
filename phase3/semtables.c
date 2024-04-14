#include "semtables.h"
#include "main.h"

/** ------------------------------------- Globals ------------------------------------- **/

extern int debugFlag;   //flag for debugging
extern int start2Pid;   //pid for start2
extern usr_proc_struct UsrProcTable[MAXPROC];       //Process Table
extern semaphore_struct SemaphoreTable[MAXSEMS];    //Semaphore Table

/** ------------------------------------ Functions ------------------------------------ **/
/* -------------------------------- External Prototypes -------------------------------- */
extern void DebugConsole3(char *format, ...);

/* ------------------------------ Process Table Functions ------------------------------ */

/* ------------------------------------------------------------------------
   Name -           ProcessInit
   Purpose -        Initializes a process table entry at the specified index. This
                    resets all the process attributes to their default, uninitialized states.
   Parameters -     index: Index of the process in the process table.
                    pid: Process ID intended for the process table entry (used for reinitialization).
   Returns -        None.
   Side Effects -   Resets the specified process table entry to its default state.
   ----------------------------------------------------------------------- */
void ProcessInit(int index, short pid) {
    usr_proc_struct *pProc = &UsrProcTable[index];

    memset(pProc->name, 0, sizeof(pProc->name));          // Clear process name
    memset(pProc->startArg, 0, sizeof(pProc->startArg));  // Clear start function arguments

    pProc->index = -1;                                    // Reset index
    pProc->startFunc = NULL;                              // Reset start function pointer
    pProc->pid = -1;                                      // Reset process ID
    pProc->stackSize = -1;                                // Reset stack size
    pProc->priority = -1;                                 // Reset priority
    pProc->mboxID = -1;                                   // Reset mailbox ID
    pProc->status = STATUS_EMPTY;                         // Set status to empty
    pProc->parentPID = -1;                                // Reset parent PID
    InitializeList(&pProc->children);                     // Initialize child process list

    return;
} /*ProcessInit*/

/* ------------------------------------------------------------------------
   Name -           AddToProcTable
   Purpose -        Adds a process to the process table with specified attributes.
   Parameters -     newStatus, name, pid, startFunc, startArg, stackSize, priority.
   Returns -        None.
   Side Effects -   Updates a process table entry with new values, potentially overwriting.
   ----------------------------------------------------------------------- */
void AddToProcTable(int newStatus, char name[], int pid, int (*startFunc)(char *),
                    char *startArg, int stackSize, int priority) {
    int parentPID = getpid();
    int index = GetProcIndex(pid);
    usr_proc_ptr pProc = &UsrProcTable[index];

    memcpy(pProc->name, name, sizeof(pProc->name));   // Set process name
    pProc->index = index;                             // Set process index
    pProc->startFunc = startFunc;                     // Set starting function
    pProc->pid = pid;                                 // Set process ID
    pProc->stackSize = stackSize;                     // Set stack size
    pProc->priority = priority;                       // Set priority
    pProc->status = newStatus;                        // Set process status
    InitializeList(&pProc->children);                 // Initialize child list

    if (parentPID > start2Pid) {
        pProc->parentPID = parentPID;                 // Set parent PID
    }

    if (startArg) {
        memcpy(pProc->startArg, startArg, sizeof(pProc->startArg)); // Set start arguments
    }

    return;
} /*AddToProcTable*/

/* ------------------------------------------------------------------------
   Name -           GetProcIndex
   Purpose -        Calculates the index in the process table for a given PID.
   Parameters -     pid: Process ID.
   Returns -        Index in the process table.
   Side Effects -   None.
   ----------------------------------------------------------------------- */
int GetProcIndex(int pid) {
    return pid % MAXPROC;
} /*GetProcIndex*/

/* ------------------------------------------------------------------------
   Name -           SemaphoreInit
   Purpose -        Initializes a semaphore table entry at the specified index.
   Parameters -     index: Index of the semaphore in the semaphore table.
                    sid: Semaphore ID intended for initialization.
   Returns -        None.
   Side Effects -   Resets the specified semaphore table entry to its default state.
   ----------------------------------------------------------------------- */
void SemaphoreInit(int index, short sid) {
    semaphore_struct *pSem = &SemaphoreTable[index];

    pSem->status = STATUS_EMPTY;                      // Set semaphore status to empty
    pSem->sid = -1;                                   // Reset semaphore ID
    pSem->value = -1;                                 // Reset semaphore value
    InitializeList(&pSem->blockedProcs);              // Initialize the list of blocked processes

    return;
} /* SemaphoreInit */

/* ------------------------------------------------------------------------
   Name -           AddToSemTable
   Purpose -        Adds a semaphore to the semaphore table with specified attributes.
   Parameters -     sid, newStatus, newValue.
   Returns -        None.
   Side Effects -   Updates a semaphore table entry with new values.
   ----------------------------------------------------------------------- */
void AddToSemTable(int sid, int newStatus, int newValue) {
    int index = GetSemIndex(sid);
    sem_struct_ptr pSem = &SemaphoreTable[index];

    pSem->sid = sid;                                  // Set semaphore ID
    pSem->status = newStatus;                         // Set new status
    pSem->value = newValue;                           // Set new value
    InitializeList(&pSem->blockedProcs);              // Initialize the list of blocked processes

    return;
} /* AddToSemTable */

/* ------------------------------------------------------------------------
   Name -           GetSemIndex
   Purpose -        Calculates the index in the semaphore table for a given semaphore ID.
   Parameters -     sid: Semaphore ID.
   Returns -        Index in the semaphore table.
   Side Effects -   None.
   ----------------------------------------------------------------------- */
int GetSemIndex(int sid) {
    return sid % MAXSEMS;
} /* GetSemIndex */
