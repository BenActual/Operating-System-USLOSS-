
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <strings.h>
#include <stdbool.h>
#include <usloss.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>
#include <phase4.h>
#include <usyscall.h>
#include <provided_prototypes.h>
#include "process.h"


/** ------------------------------ Prototypes ------------------------------ **/
int start3(char *);
extern int start4(char *arg);
static int ClockDriver(char *);
static int DiskDriver(char *);
static int sleep(int seconds);
static int diskIO(int operation,
                  void *buffer,
                  int sectors,
                  int trackStart,
                  int sectorStart,
                  int unit);
static int diskSize(int unit,
                    int *sectorSize,
                    int *numSectors,
                    int *numTracks);
int GetIndex(int pid);
void AddToProcTable(int pid);
proc_ptr CreatePointer(int pid);
void InitializeList(procQueue *pProc);
bool ListIsFull(const procQueue *pProc);
bool ListIsEmpty(const procQueue *pProc);
int AddToList(proc_ptr pProc, procQueue * pq);
int RemoveFromList(int pid, procQueue * pq);
static void check_kernel_mode(const char *functionName);
void DebugConsole4(char *format, ...);
static void setUserMode();
static void setKernelMode();
static void sysCall(sysargs *args);
static int SecToMSec(int seconds);

/* ------------------------------ Globals ------------------------------ */
int debugFlag = 0;
int exitDriver = 0;
int totalProcs = 0;                 // total processes
int totalSleepingProcs = 0;         // total sleeping processes
int totalRequestProcs = 0;          // total request processes
int startMailbox = 0;               // start 3 mailbox
int currentTrack = 0;               // current track
int criticalMboxID;                 // mbox for critical sections
static int runningSID;              // semaphore to synchronize drivers and start3
static int diskPIDs[DISK_UNITS];    // disk processes for zapping
procQueue requestQueue[DISK_UNITS]; // waiting disk requests
int trackAmount[DISK_UNITS];        // total tracks per disk
int diskSems[DISK_UNITS];           // disk semaphores
p4proc_struct ProcTable[MAXPROC];   // process table
procQueue SleepingProcs;            // sleeping processes list

/* ----------------------------- Functions ----------------------------- */

/* ------------------------------------------------------------------------
  Name -            start3
  Purpose -         Phase 4 entry point.
  Parameters -      *arg:   default arg passed by fork1
  Returns -         0:      so C doesn't get mad
  Side Effects -    lots since it initializes the phase4 data structures.
  ----------------------------------------------------------------------- */
int start3(char *arg) {
    /* Function Initialization */
    char name[128];
    char buf[10];
    int	clockPID;
    int	status;
    int pid;
    int msg = 0;

    /* Check for Kernel Mode */
    check_kernel_mode(__func__);

    /* Assign System Call Handlers */
    sys_vec[SYS_SLEEP]     = sysCall;
    sys_vec[SYS_DISKREAD]  = sysCall;
    sys_vec[SYS_DISKWRITE] = sysCall;
    sys_vec[SYS_DISKSIZE]  = sysCall;

    /* Initialize Global Tables */
    memset(ProcTable, 0, sizeof(ProcTable));

    /* Initialize Global Lists */
    InitializeList(&SleepingProcs);
    for (int i = 0; i++; i < DISK_UNITS) {
        InitializeList(&requestQueue[i]);
    }

    /* Create Process Mailboxes */
    for (int i=0; i< MAXPROC ; i++) {
        ProcTable[i].mboxID = MboxCreate(0,sizeof(int));
        ProcTable[i].blockSem = semcreate_real(0);
    }
    criticalMboxID = MboxCreate(1,sizeof(int));

    
    /* Fork Clock Driver */
    runningSID = semcreate_real(0);
    clockPID = fork1("Clock Driver",
                     ClockDriver,
                     NULL,
                     USLOSS_MIN_STACK,
                     2);

    /* Error Check: Valid Clock Driver Creation */
    if (clockPID < 0) {
        console("%s : Can't create clock driver. Halting ...\n",
                __func__);
        halt(1);
    }

    /*
     * Wait for the clock driver to start. The idea is that ClockDriver
     * will V the semaphore "runningSID" once it is running.
     */

    semp_real(runningSID);

    /*
     * Create the disk device drivers here.  You may need to increase
     * the stack size depending on the complexity of your
     * driver, and perhaps do something with the pid returned.
     */

    proc_ptr pCur = CreatePointer(getpid());

    for (int i = 0; i < DISK_UNITS; i++) {
        sprintf(buf, "%d", i);
        sprintf(name, "DiskDriver%d", i);

        diskSems[i] = semcreate_real(0);
        diskPIDs[i] = fork1(name, DiskDriver, buf, USLOSS_MIN_STACK, 2);

        startMailbox = pCur->mboxID;
        MboxReceive(startMailbox, &msg, sizeof(int));

        if (diskPIDs[i] < 0) {
            console("start3(): Can't create disk driver %d\n", i);
            halt(1);
        }
    }

    /*
     * Create first user-level process and wait for it to finish.
     * These are lower-case because they are not system calls;
     * system calls cannot be invoked from kernel mode.
     * I'm assuming kernel-mode versions of the system calls
     * with lower-case names.
     */

    pid = spawn_real("start4", start4, NULL,  8 * USLOSS_MIN_STACK, 3);
    pid = wait_real(&status);

    /*
     * Zap the device drivers
     */

    exitDriver = 1;

    /* Zap Clock Driver */
    zap(clockPID);

    /* Disk Driver */
    for (int i = 0; i < DISK_UNITS; i++) {
        /* Wake Up Disk Processes */
        semv_real(diskSems[i]);

        /* Zap Disk Processes */
        zap(diskPIDs[i]);
    }

    join(&status);

    /* Quit Start3() */
    quit(0);

    return 0;

} /* start3 */


/* ------------------------------------------------------------------------
  Name -            ClockDriver
  Purpose -         Sleeps a process for a specific amount of time
  Parameters -      *arg: default arg passed by fork1
  Returns -         0:    So C doesn't get mad
  Side Effects -    none
  ----------------------------------------------------------------------- */
static int ClockDriver(char *arg) {
    
    int result;
    int status;
    int curTime;
    int headPID;
    int awakerPID;
    int msg = 0;

    /*
     * Let the parent know we are running and enable interrupts.
     */

    semv_real(runningSID);

    /*** Enable Interrupts ***/
    setKernelMode();

    /*** Loop Until Zapped ***/
    while (!is_zapped()) {
        result = waitdevice(CLOCK_DEV, 0, &status);

        if (result != 0) {
            return 0;
        }

        /*
         * Compute the current time and wake up any processes
         * whose time has come.
         */

        curTime = sys_clock();

        /*** Awaken any Processes that need to be Awakened ***/
        while ((SleepingProcs.total > 0) && (SleepingProcs.pHeadProc->pProc->wakeTime < curTime)) {
            headPID = SleepingProcs.pHeadProc->pProc->pid;

            /*** Remove Head Sleep Process from the Sleeping List ***/
            awakerPID = RemoveFromList(headPID, &SleepingProcs);

            /*** Wake up Process ***/
            MboxSend(ProcTable[awakerPID % MAXPROC].mboxID, &msg, sizeof(int));
        }

    }

    /*** The Clock Driver was zapped -> quit ***/
    quit(0);

    return 0;

} /* ClockDriver */


/* ------------------------------------------------------------------------
  Name -            DiskDriver
  Purpose -         Sending read/write/disk size requests
  Parameters -      *arg: default arg passed by fork1
  Returns -         0:    So C doesn't get mad
  Side Effects -    none
  ----------------------------------------------------------------------- */
static int DiskDriver(char *arg) {
    
    int unit = atoi(arg);
    int result;
    int status;
    int sectorCount;
    int msg = CRIT_EMPTY;    //used for Mbox functions
    device_request my_request;
    proc_ptr current_req;

    DebugConsole4("DiskDriver(%d): started\n", unit);

    /* Get the number of tracks for this disk */
    my_request.opr  = DISK_TRACKS;
    my_request.reg1 = &trackAmount[unit];

    /* Block Handling */
    result = device_output(DISK_DEV, unit, &my_request);
    result = waitdevice(DISK_DEV, unit, &status);

    /* Error Check: Invalid Output Result */
    if (result == DEV_INVALID) {
        DebugConsole4("%s :Invalid device output result.\n", __func__);
    }

    /*
    * Let the parent know we are running and enable interrupts.
    */
    MboxSend(startMailbox, &msg, sizeof(int));    //unblock Start3

    /* Initialize Arm Position to 0 */
    result = device_output(DISK_DEV, unit, &my_request);
    result = waitdevice(DISK_DEV, unit, &status);

    /* Error Check: Invalid Output Result */
    if (result == DEV_INVALID) {
        DebugConsole4("%s :Invalid device output result.\n", __func__);
    }

    while (!is_zapped()) {

        /* Await Request */
        semp_real(diskSems[unit]);

        /* Error Check: Check for Zapping Upon Return */
        if (is_zapped() || exitDriver == 1) {
            return 0;
        }

        /* Enter Mutex for Critical Section */
        MboxCondReceive(criticalMboxID, &msg, sizeof(int));

        if (msg == CRIT_EMPTY) {
            msg = CRIT_FULL;
            MboxSend(criticalMboxID, &msg, sizeof(int));

        }
        else {
            MboxReceive(criticalMboxID, &msg, sizeof(int));
            msg = CRIT_FULL;
            MboxSend(criticalMboxID, &msg, sizeof(int));
        }

        /* Check Queue */
        if (requestQueue[unit].total == 0) {
            DebugConsole4("%s : Disk queue is empty.\n", __func__);
        }
        else {
            
            /* Take Next Request from Queue */
            current_req = requestQueue[unit].pHeadProc->pProc;

            /* Remove Request from Queue */
            RemoveFromList(current_req->pid, &requestQueue[unit]);

            /* Exit Mutex for Critical Section */
            msg = CRIT_EMPTY;
            MboxRelease(criticalMboxID);
            criticalMboxID = MboxCreate(1,sizeof(int));
            MboxSend(criticalMboxID, &msg, sizeof(int));

            /** Initialize Starting Values **/
            current_req->currentTrack = current_req->trackStart;
            current_req->currentSector = current_req->sectorStart;
            current_req->diskOffset = current_req->diskBuf;
            sectorCount = 0;

            do {
                
                if (currentTrack != current_req->trackStart) {

                    /* Seek to Current Track */
                    my_request.opr =  DISK_SEEK;
                    my_request.reg1 = current_req->currentTrack;

                    result = device_output(DISK_DEV, unit, &my_request);
                    result = waitdevice(DISK_DEV, unit, &status);

                    /* Error Check: Invalid Output Result */
                    if (result == DEV_INVALID) {
                        DebugConsole4("%s :Invalid device output result.\n", __func__);
                    }

                    /* Update Global */
                    currentTrack = current_req->trackStart;
                }

                my_request.opr = current_req->operation;
                my_request.reg1 = (void *) current_req->currentSector;
                my_request.reg2 = current_req->diskOffset;

                result = device_output(DISK_DEV, unit, &my_request);
                result = waitdevice(DISK_DEV, unit, &status);

                if (result != DEV_OK) {
                    console("DiskDriver %d: did not get DEV_OK on DISK_TRACKS call\n", unit);
                    console("DiskDriver %d: is the file disk%d present???\n", unit, unit);
                    halt(1);
                }

                if (++(current_req->currentSector) == DISK_TRACK_SIZE) {
                    current_req->currentSector = 0;
                    current_req->currentTrack = (current_req->currentTrack + 1) % DISK_TRACK_SIZE;
                    currentTrack = current_req->currentTrack;

                }

                current_req->diskOffset += 512;

                sectorCount++;

            } while (sectorCount < current_req->numSectors);

            /* Wake - Inform Process that Request is Complete */
            MboxSend(current_req->mboxID, &msg, sizeof(int));
        }
    }

   
    quit(0);

    return 0;

} /* DiskDriver */


/* ------------------------------------------------------------------------
  Name -            sleep
  Purpose -         Delays the calling process for int seconds
  Parameters -      seconds:    number of seconds to delay the process
  Returns -         -1:         illegal values passed
                     0:         Success
  Side Effects -    none
  ----------------------------------------------------------------------- */
static int sleep(int seconds) {
    
    int result = -1;
    int mSec;
    proc_ptr pCur;
    int curTime;
    int msg = 0;

   
    AddToProcTable(getpid());

   
    if (seconds > 0) {

        /* Change to Microseconds */
        mSec = SecToMSec(seconds);

        /* Get Current Time */
        curTime = sys_clock();

        /* Set Wake Time for Process */
        ProcTable[getpid() % MAXPROC].wakeTime = mSec + curTime;

        /* Add to Sleeping List */
        pCur = CreatePointer(getpid());
        AddToList(pCur, &SleepingProcs); //TODO: test functionality

        /* Block Process */
        MboxReceive(pCur->mboxID, &msg, sizeof(int));

        result = 0;
    }

    
    if (is_zapped()) {
        memset(&ProcTable[getpid() % MAXPROC], 0, sizeof(p4proc_struct));
        quit(1);
    }

    return result;

} /* sleep */


/* ------------------------------------------------------------------------
  Name -            diskIO
  Purpose -         Handles disk read/write
  Parameters -      buffer:         memory address to transfer to
                    operation:      indicates disk operation
                    sectors:        number of sectors to read/write
                    trackStart:     starting disk track number
                    sectorStart:    starting disk sector number
                    unit:           unit number from which to write
  Returns -         0:              success
                    -1:             illegal arguments
  Side Effects -    none
  ----------------------------------------------------------------------- */
static int diskIO(int operation, void *buffer, int sectors, int trackStart, int sectorStart, int unit){
    /*** Function Initialization ***/
    int msg = CRIT_EMPTY;

    /*** Error Check: Valid Parameters ***/
    /* Verify Valid Track Start */
    if (trackStart < 0 || trackStart > trackAmount[unit]) {
        DebugConsole4("%s : Illegal trackStart parameter.\n", __func__);
        return -1;
    }
    /* Verify Valid Sector Start */
    if (sectorStart < 0 || sectorStart  > DISK_TRACK_SIZE) {
        DebugConsole4("%s : Illegal sectorStart parameter.\n", __func__);
        return -1;
    }
    /* Verify Unit */
    if (unit < 0 || unit > (DISK_UNITS-1)) {
        DebugConsole4("%s : Illegal unit parameter.\n", __func__);
        return -1;
    }

    
    AddToProcTable(getpid());
    proc_ptr pProc = CreatePointer(getpid());

    /* Build the Request */
    pProc->been_zapped = 0;
    pProc->operation = operation;
    pProc->mboxID = pProc->mboxID;
    pProc->diskBuf = buffer;
    pProc->numSectors = sectors;
    pProc->trackStart = trackStart;
    pProc->sectorStart = sectorStart;
    pProc->unit = unit;

    /* Enter Mutex for Critical Section */
    MboxCondReceive(criticalMboxID, &msg, sizeof(int));

    if (msg == CRIT_EMPTY) {
        msg = CRIT_FULL;
        MboxSend(criticalMboxID, &msg, sizeof(int));

    }
    else {
        MboxReceive(criticalMboxID, &msg, sizeof(int));
        msg = CRIT_FULL;
        MboxSend(criticalMboxID, &msg, sizeof(int));
    }

    /* Add Request to Queue */
    AddToList(pProc, &requestQueue[unit]);

    /* Exit Mutex for Critical Section */
    msg = CRIT_EMPTY;
    MboxRelease(criticalMboxID);
    criticalMboxID = MboxCreate(1,sizeof(int));
    MboxSend(criticalMboxID, &msg, sizeof(int));

    /*** Handle Blocking ***/
    semv_real(diskSems[unit]);      //wake up disk

    MboxReceive(pProc->mboxID, &msg, sizeof(int));

    return 0;

} /* diskIO */


/* ------------------------------------------------------------------------
  Name -            diskSize
  Purpose -         Retrieving the number for sectors,
                    size of sectors,
                    and number of tracks of a disk unit
  Parameters -      unit:        the disk unit
                    *sectorSize: for setting sector amounts
                    *numSectors: for setting number of sectors
                    *numTracks:  for setting number of tracks
  Returns -         0:           Success
                    -1:          Invalid Unit
  Side Effects -    none
  ----------------------------------------------------------------------- */
static int diskSize(int unit, int *sectorSize, int *numSectors, int *numTracks) {
    /* Error Check: Unit is Valid */
    if (unit < 0 || unit > DISK_UNITS ){
        return -1;
    }

    /*** Get Disk Information ***/
    *sectorSize = DISK_SECTOR_SIZE;
    *numSectors = DISK_TRACK_SIZE;
    *numTracks = trackAmount[unit];

    /* Return Results */
    return 0;

} /* diskSize */

/* ------------------------------------------------------------------------
   Name -           GetIndex
   Purpose -        Gets Process index from id
   Parameters -     pid:    Unique Process ID
   Returns -        Process Index
   Side Effects -   none
   ----------------------------------------------------------------------- */
int GetIndex(int pid){
    return pid % MAXPROC;

} /* GetIndex */


/* ------------------------------------------------------------------------
  Name -            AddToProcTable
  Purpose -         Adds current process to ProcTable()
  Parameters -      pid:    Unique Process ID
  Returns -         none
  Side Effects -    Process added to ProcTable
  ----------------------------------------------------------------------- */
void AddToProcTable(int pid){
    /*** Function Initialization ***/
    int index = GetIndex(pid);
    proc_ptr pProc = &ProcTable[index];

    /*** Verify Entry ***/
    if (pid != pProc->pid) {
        /*** Update ProcTable Entry ***/
        pProc->index = index;       //Process Index
        pProc->pid = pid;           //Process ID
        pProc->status = READY;      //Process Status

        totalProcs++;
    }

} /* AddToProcTable */


/* ------------------------------------------------------------------------
    Name -          CreatePointer
    Purpose -       Creates a pointer to specified process
    Parameters -    pid:    Process ID
    Returns -       Pointer to found Process
    Side Effects -  None
   ----------------------------------------------------------------------- */
proc_ptr CreatePointer(int pid){
    /*** Create Current Pointer ***/
    int index = pid % MAXPROC;

    return &ProcTable[index];

} /* CreatePointer */

/* ------------------------------------------------------------------------
    Name -          InitializeList
    Purpose -       Initialize List pointed to by parameter
    Parameters -    *pProc: Pointer to Process List
    Returns -       None
    Side Effects -  None
   ----------------------------------------------------------------------- */
void InitializeList(procQueue *pProc) {
    /*** Initialize Proc Queue ***/
    pProc->pHeadProc = NULL;    //Head of Queue
    pProc->pTailProc = NULL;    //Tail of Queue
    pProc->total = 0;           //Total Count

}/* InitializeList */


/* ------------------------------------------------------------------------
    Name -          ListIsFull
    Purpose -       Checks if process list is Full
    Parameters -    *pProc: Pointer to Process List
    Returns -        0:     not full
                     1:     full
    Side Effects -  none
   ----------------------------------------------------------------------- */
bool ListIsFull(const procQueue *pProc) {
    return pProc->total == MAXPROC;

}/* ListIsFull */


/* ------------------------------------------------------------------------
    Name -          ListIsEmpty
    Purpose -       Checks if process list is empty
    Parameters -    *pProc: Pointer to Process List
    Returns -        0:     not Empty
                     1:     Empty
    Side Effects -  none
   ----------------------------------------------------------------------- */
bool ListIsEmpty(const procQueue *pProc) {
    return pProc->pHeadProc == NULL;

}/* ListIsEmpty */


/* ------------------------------------------------------------------------
    Name -          AddToList
    Purpose -       Add Process to Specified Process Queue
    Parameters -    pProc:      Pointer to Process
                    pq:         Pointer to Process Queue
    Returns -        0:         Success
                    -1:         Proc Queue is Full or System ProcTable is Full
    Side Effects -  None
   ----------------------------------------------------------------------- */
int AddToList(proc_ptr pProc, procQueue * pq) {
    /*** Function Initialization ***/
    bool procAdded = false; //Process Added flag
    ProcList *pList;       //New Node
    ProcList *pSave;       //Save Pointer

    
    if (ListIsFull(pq)) {
        DebugConsole4("%s: Queue is full.\n", __func__);
        return -1;
    }

    
    /* Allocate Space for New Node */
    pList = (ProcList *) malloc(sizeof(ProcList));

    /* Verify Allocation Success */
    if (pList == NULL) {
        DebugConsole4("%s: Failed to allocate memory for node in linked list. Halting...\n",
                      __func__);
        halt(1);    //memory allocation failed
    }

   
    /* Point pList to pProc */
    pList->pProc = pProc;

    /* Add New Node to List */
    pList->pNextProc = NULL;                //assign pNext to NULL

    if (ListIsEmpty(pq)) {                  //if list is empty...
        pq->pHeadProc = pList;              //add pNew to front of list
        pq->pTailProc = pList;              //reassign pTail to new node
        procAdded = true;
    }
    else {                                  //if list not empty...
        
        pSave = pq->pHeadProc;          //Set pSave to head of list
        while (pSave != NULL) {   //verify not end of list

            
            /* if pProc wakes later than pSave, iterate */
            if (pProc->wakeTime >= pSave->pProc->wakeTime) {
                pSave = pSave->pNextProc;       //increment to next in list
            }
                /* if pSave wakes later than pProc, insert pProc */
            else {
                /* Adding Proc as New Head */
                if (pSave == pq->pHeadProc) {
                    pq->pHeadProc = pList;
                    pSave->pPrevProc = pList;
                    pList->pNextProc = pSave;
                }
                    /* Add Proc Between Two Procs */
                else {
                    pSave->pPrevProc->pNextProc = pList;
                    pList->pPrevProc = pSave->pPrevProc;
                    pList->pNextProc = pSave;
                    pSave->pPrevProc = pList;
                }

                procAdded = true;   //update flag
                break;
            }

            /* Adding Proc as New Tail if pProc has biggest time */
            if (pSave == pq->pTailProc) {
                pq->pTailProc = pList;
                pSave->pNextProc = pList;
                pList->pPrevProc = pSave;

                procAdded = true;
                break;
            }
        }

        if (procAdded == false) {
            pq->pTailProc->pNextProc = pList;   //add pNew to end of list
            pList->pPrevProc = pq->pTailProc;   //assign pNew prev to current tail
            pq->pTailProc = pList;              //reassign pTail to new node
        }
    }

   
    /* List Total */
    pq->total++;            //update pq count

    /* Global Total */
    if (pq == &SleepingProcs) {
        totalSleepingProcs++;
    }
    else if (pq == &requestQueue[0] || pq == &requestQueue[1]) {
        totalRequestProcs++;
    }
    else {
        DebugConsole4("%s: Invalid List", __func__);
    }

    /*** Function Termination ***/
    if (procAdded) {
        return 0;   //Process Addition Successful
    }
    return 1;       //Process Addition Unsuccessful

}/* AddToList */


/* ------------------------------------------------------------------------
    Name -          RemoveFromList
    Purpose -       Removes Process from Specified Process Queue
    Parameters -    pid:    Process ID
                    pq:     Pointer to Process Queue
    Returns -       Pid of Removed Process, halt (1) on error
    Side Effects -  None
   ----------------------------------------------------------------------- */
int RemoveFromList(int pid, procQueue * pq) {

   
    bool pidFlag = false;   //verify pid found in list
    bool remFlag = false;   //verify process removed successfully

    ProcList *pSave;       //Pointer for Linked List

    
    if (ListIsEmpty(pq)) {
        DebugConsole4("%s: Queue is empty.\n", __func__);
        halt(1);
    }

    
    pSave = pq->pHeadProc;              //Set pSave to head of list

    /** PID Found **/
    pidFlag = true;             //Trigger Flag - PID found

    /* Traverse List */
    if (pSave == pq->pHeadProc) {
        pq->pHeadProc = pSave->pNextProc;       //Set next pid as head
        pSave->pNextProc = NULL;                //Set old head next pointer to NULL

        /* if proc is NOT only node on list */
        if (pq->pHeadProc != NULL) {
            pq->pHeadProc->pPrevProc = NULL;    //Set new head prev pointer to NULL
        }

            /* if proc IS only node on list */
        else {
            pSave->pPrevProc = NULL;            //Set old prev pointer to NULL
            pq->pTailProc = NULL;               //Set new tail to NULL
        }

        remFlag = true;                         //Trigger Flag - Process Removed
    }

   
    /* List Total */
    pq->total--;            //update pq count

    /* Global Total */
    if (pq == &SleepingProcs) {
        totalSleepingProcs--;
    }
    else if (pq == &requestQueue[0] || pq == &requestQueue[1]) {
        totalRequestProcs--;
    }
    else {
        DebugConsole4("%s: Invalid List", __func__);
    }

    /*** Error Check: Pid Found and Removed ***/
    if (pidFlag && remFlag) {
        pSave = NULL;       //free() causing issues in USLOSS
    }
    else {
        if (pidFlag == false) {
            DebugConsole4("%s: Unable to locate pid [%d]. Halting...\n",
                          __func__, pid);
            halt(1);
        }
        else if (remFlag == false) {
            DebugConsole4("%s: Removal of pid [%d] unsuccessful. Halting...\n",
                          __func__, remFlag);
            halt(1);
        }
    }

    /*** Function Termination ***/
    return pid;     //process removal success

}/* RemoveFromList */



/* ------------------------------------------------------------------------
   Name -           check_kernel_mode
   Purpose -        Checks the PSR for kernel mode and halts if in user mode
   Parameters -     functionName:   Function to Verify
   Returns -        none
   Side Effects -   Halts if not kernel mode
   ----------------------------------------------------------------------- */
static void check_kernel_mode(const char *functionName) {
    union psr_values psrValue; /* holds caller's psr values */


    /* test if in kernel mode; halt if in user mode */
    psrValue.integer_part = psr_get();

    if (psrValue.bits.cur_mode == 0) {
        console("Kernel mode expected, but function called in user mode.\n");
        halt(1);
    }



} /* check_kernel_mode */


/* ------------------------------------------------------------------------
   Name -           DebugConsole4
   Purpose -        Prints the message to the console if in debug mode
   Parameters -     *format:    Format String to Display
                    ...:        Optional Corresponding Arguments
   Returns -        none
   Side Effects -   none
   ----------------------------------------------------------------------- */
void DebugConsole4(char *format, ...) {
    if (DEBUG4 && debugFlag) {
        va_list argptr;
        va_start(argptr, format);
        vfprintf(stdout, format, argptr);
        fflush(stdout);
        va_end(argptr);
    }

} /* DebugConsole4 */


/* ------------------------------------------------------------------------
  Name -            setUserMode
  Purpose -         Sets mode from kernel to user
  Parameters -      none
  Returns -         none
  Side Effects -    user mode is set
  ----------------------------------------------------------------------- */
static void setUserMode() {
    psr_set(psr_get() & ~PSR_CURRENT_MODE);

} /* setUserMode */


/* ------------------------------------------------------------------------
  Name -            setKernelMode
  Purpose -         Sets mode from user to kernel
  Parameters -      none
  Returns -         none
  Side Effects -    kernel mode is set
  ----------------------------------------------------------------------- */
static void setKernelMode() {
    psr_set(psr_get() | PSR_CURRENT_INT);

} /* setKernelMode */


/* ------------------------------------------------------------------------
  Name -            sysCall
  Purpose -         manages the syscall for disk read, disk write, and disk size
  Parameters -      *args: the syscall args
  Returns -         none
  Side Effects -    none
  ----------------------------------------------------------------------- */
static void sysCall(sysargs *args) {
    
    char *pFunctionName;

    if (args == NULL) {
        console("%s: Invalid syscall %d, no arguments.\n", __func__, args->number);
        console("%s: Process %d, terminating...\n", __func__, getpid());
        terminate_real(1);
    }

    switch (args->number) {
        case SYS_SLEEP:
            args->arg4 = (void *) sleep((__intptr_t) args->arg1);
            break;
        case SYS_DISKREAD:
            args->arg4 = (void *) diskIO(DISK_READ,
                                         args->arg1,
                                         (__intptr_t) args->arg2,
                                         (__intptr_t) args->arg3,
                                         (__intptr_t) args->arg4,
                                         (__intptr_t) args->arg5);

           
            if (args->arg4  == -1) {
                args->arg1 = DEV_INVALID;
            }
           
            else {
                args->arg1 = (void *) DEV_OK;
            }
            break;
        case SYS_DISKWRITE:
            args->arg4 = (void *) diskIO(DISK_WRITE,
                                         args->arg1,
                                         (__intptr_t) args->arg2,
                                         (__intptr_t) args->arg3,
                                         (__intptr_t) args->arg4,
                                         (__intptr_t) args->arg5);

            /*** Invalid Parameters ***/
            if(args->arg4 == -1){
                args->arg1 = DEV_INVALID;
            }
            /*** Success ***/
            else {
                args->arg1 = (void *) DEV_OK;
            }
            break;
        case SYS_DISKSIZE:
            args->arg4 = (void *) diskSize((__intptr_t) args->arg1,
                                           (__intptr_t) &args->arg1,
                                           (__intptr_t) &args->arg2,
                                           (__intptr_t) &args->arg3);
            break;
        default:
            console("Unknown syscall number");
            halt(1);
    }

    
    if (is_zapped()) {
        DebugConsole4("%s: process %d was zapped while in system call.\n", pFunctionName, getpid());
        terminate_real(0);
    }

    
    setUserMode();

} /* sysCall */


/* ------------------------------------------------------------------------
  Name -            SecToMsec
  Purpose -         Converts seconds to microseconds
  Parameters -      seconds
  Returns -         microseconds
  Side Effects -    none
  ----------------------------------------------------------------------- */
static int SecToMSec(int seconds) {
    return (seconds * 1000000);

} /* SecToMSec */