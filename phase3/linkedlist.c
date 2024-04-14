#include "linkedlist.h"

/** ------------------------------------- Globals ------------------------------------- **/

/* Flags */
extern int debugFlag;

/* General Globals */
extern void DebugConsole3(char *format, ...);

/* Process Globals */
extern usr_proc_struct UsrProcTable[MAXPROC];   //Process Table
extern int totalProc;                           //total Processes
extern unsigned int nextPID;                    //next process id

/** ------------------------------------ Functions ------------------------------------ **/

/* ------------------------------------------------------------------------
    Name -          InitializeList
    Purpose -       Initializes a linked list for managing processes,
                    setting the head, tail to NULL, and total to 0.
    Parameters -    *pProc: Pointer to the process list to initialize.
    Returns -       None.
    Side Effects -  Resets the linked list to an empty state.
   ----------------------------------------------------------------------- */
void InitializeList(procQueue *pProc) {
    pProc->pHeadProc = NULL;    // Set the head of the queue to NULL
    pProc->pTailProc = NULL;    // Set the tail of the queue to NULL
    pProc->total = 0;           // Reset the total number of processes in the queue to 0
}/* InitializeList */


/* ------------------------------------------------------------------------
    Name -          ListIsFull
    Purpose -       Checks if the process list has reached its maximum capacity.
    Parameters -    *pProc: Pointer to the process list to check.
    Returns -       1 if the list is full, 0 otherwise.
    Side Effects -  None.
   ----------------------------------------------------------------------- */
bool ListIsFull(const procQueue *pProc) {
    return pProc->total == MAXPROC;  // Return true if total processes equal the maximum allowed
}/* ListIsFull */


/* ------------------------------------------------------------------------
    Name -          ListIsEmpty
    Purpose -       Determines if the process list is empty.
    Parameters -    *pProc: Pointer to the process list to check.
    Returns -       1 if the list is empty, 0 otherwise.
    Side Effects -  None.
   ----------------------------------------------------------------------- */
bool ListIsEmpty(const procQueue *pProc) {
    return pProc->pHeadProc == NULL;  // Return true if the head of the list is NULL
}/* ListIsEmpty */


/* ------------------------------------------------------------------------
    Name -          AddProcessLL
    Purpose -       Adds a process to a specified process queue.
    Parameters -    pProc: Pointer to the process structure.
                    pq: Pointer to the process queue where the process will be added.
    Returns -       0 on success, -1 if the queue is full or the system's process table is full.
    Side Effects -  Modifies the process queue by adding a new process.
   ----------------------------------------------------------------------- */
int AddProcessLL(usr_proc_ptr pProc, procQueue *pq) {
    if (ListIsFull(pq) || totalProc >= MAXPROC) {
        DebugConsole3("%s: Process list is full.\n", __func__);
        return -1;  // Early return if the queue is full or MAXPROC is exceeded
    }

    ProcList *pList = (ProcList *) malloc(sizeof(ProcList));
    if (pList == NULL) {
        DebugConsole3("%s: Memory allocation failed for process list node.\n", __func__);
        halt(1);  // Halt if memory allocation fails
    }

    pList->pProc = pProc;            // Link the process to the new node
    pList->pNextProc = NULL;         // Set the next pointer of the new node to NULL

    if (ListIsEmpty(pq)) {
        pq->pHeadProc = pList;       // If the list is empty, set the new node as the head
        pList->pPrevProc = NULL;     // Since it's the head, no previous node
    } else {
        pq->pTailProc->pNextProc = pList;  // Link the new node at the end of the list
        pList->pPrevProc = pq->pTailProc;  // Set the previous node
    }

    pq->pTailProc = pList;           // Update the tail to the new node
    pq->total++;                     // Increment the count of processes in the queue

    return 0;  // Return success
}/* AddProcessLL */


/* ------------------------------------------------------------------------
    Name -          RemoveProcessLL
    Purpose -       Removes a process from a specified process queue based on its PID.
    Parameters -    pid:    Process ID of the process to remove.
                    pq:     Pointer to the process queue from which to remove the process.
    Returns -       PID of the removed process; halts the system on error.
    Side Effects -  Modifies the process queue by removing the specified process and updating link pointers.
   ----------------------------------------------------------------------- */
int RemoveProcessLL(int pid, procQueue *pq) {
    if (ListIsEmpty(pq)) {
        DebugConsole3("%s: Queue is empty.\n", __func__);
        halt(1);  // Halt system if the list is empty to indicate a critical error.
    }

    ProcList *current = pq->pHeadProc; // Start from the head of the list.
    int found = 0;  // Flag to indicate if the process was found.

    // Traverse the list to find the process with the given PID.
    while (current != NULL) {
        if (current->pProc->pid == pid) {
            found = 1;  // Set the found flag.

            // Adjust pointers to remove the current node from the list.
            if (current == pq->pHeadProc) {
                pq->pHeadProc = current->pNextProc;  // Update head pointer.
                if (pq->pHeadProc) {  // If there's a new head, clear its previous pointer.
                    pq->pHeadProc->pPrevProc = NULL;
                }
            } else {
                current->pPrevProc->pNextProc = current->pNextProc;  // Update previous node's next pointer.
            }

            if (current == pq->pTailProc) {
                pq->pTailProc = current->pPrevProc;  // Update tail pointer.
                if (pq->pTailProc) {  // If there's a new tail, clear its next pointer.
                    pq->pTailProc->pNextProc = NULL;
                }
            } else {
                current->pNextProc->pPrevProc = current->pPrevProc;  // Update next node's previous pointer.
            }

            free(current);  // Free the memory allocated for the removed process node.
            pq->total--;  // Decrement the count of processes in the queue.
            return pid;  // Return the PID of the removed process.
        }

        current = current->pNextProc;  // Move to the next node in the list.
    }

    if (!found) {
        DebugConsole3("%s: PID %d not found in the queue. Halting...\n", __func__, pid);
        halt(1);  // Halt system if the PID is not found to indicate a critical error.
    }

    return -1;  // Return an error code if not found (though halt would prevent reaching here).
}


