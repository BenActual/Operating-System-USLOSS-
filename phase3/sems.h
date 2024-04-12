// Macro definitions for general purposes
#define DEBUG2 1
#define USED 1
#define UNUSED 0

#define NULL 0
#define INACTIVE 0
#define ACTIVE 1
#define WAITING_PROCESS_BLOCKED 3

// Type definitions for easier usage
typedef struct UserProcessTable UserProcessTable;
typedef struct UserProcessTable *UserProcessTable_ptr;

typedef struct SemaphoreStructure SemaphoreStructure;
typedef struct SemaphoreStructure *SemaphoreStructure_ptr;

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

// PSR structure definitions
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
