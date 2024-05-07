/* Header File for Phase 4 */

#ifndef PROCESS_H    //Header Guards
#define PROCESS_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <usloss.h>


/** ------------------------- Constants ----------------------------------- **/
#define DEBUG4      0

#define EMPTY       0
#define READY       1
#define SLEEPING    2
#define ZAPPED      3

#define CRIT_FULL   4
#define CRIT_EMPTY  5

/** ------------------------ Typedefs and Structs ------------------------ **/
typedef struct p4proc_struct p4proc_struct;
typedef struct p4proc_struct * proc_ptr;
typedef struct procQueue procQueue;
typedef struct procList * proc_list_ptr;

typedef struct sleep_struct sleep_struct;
typedef struct sleep_struct * sleep_proc_ptr;
typedef struct sleepQueue sleepQueue;
typedef struct sleepList * sleep_proc_list_ptr;

/* Structures for Processes */
typedef struct procList{
    proc_ptr    pProc;          //points to process
    struct procList *pNextProc; //points to next process
    struct procList *pPrevProc; //points to previous process
} ProcList;

typedef struct procQueue {
    ProcList *pHeadProc;    //points to proc list head
    ProcList *pTailProc;    //points to proc list tail
    int total;              //counts total procs in queue
} ProcQueue;

struct p4proc_struct {
    int     pid;            //process ID
    int     index;          //index Location
    int     been_zapped;    //zapping flag
    int     mboxID;         //mailbox ID
    int     blockSem;       //semaphore ID
    int     status;         //status
    int     wakeTime;       //time to wake

    /* Used for disk requests */
    int     operation;      //indicates disk operation
    int     unit;
    int     trackStart;     //track starting location
    int     currentTrack;   //current track location
    int     sectorStart;    //sector starting location
    int     currentSector;  //current sector location
    int     numSectors;     //number of sectors
    void    *diskBuf;       //starting buffer location
    void    *diskOffset;    //current buffer location (512i)
    device_request diskRequest;     //found within usloss.h
};
//end of Process structures

struct psr_bits {
    unsigned int cur_mode:1;
    unsigned int cur_int_enable:1;
    unsigned int prev_mode:1;
    unsigned int prev_int_enable:1;
    unsigned int unused:28;
};

union psr_values {
    struct psr_bits bits;
    unsigned int integer_part;
};

#endif  //PROCESS_H