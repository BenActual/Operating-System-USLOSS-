#define DEBUG 1

typedef struct proc_struct proc_struct;

typedef struct proc_struct * proc_ptr;

struct proc_struct {
    proc_ptr next_proc_ptr;
    proc_ptr child_proc_ptr;
    proc_ptr next_sibling_ptr;
    char name[MAXNAME];                 /* process's name */
    char start_arg[MAXARG];             /* args passed to process */
    context currentContext;             /* current context for process */
    short pid;                          /* process id */
    int priority;
    int (*start_func)(char *);          /* function where process begins -- launch */
    char *stack;
    unsigned int stacksize;
    int status;                         /* READY, BLOCKED, QUIT, etc. */

    /* other fields as needed... */
    proc_ptr quit_children;         // Pointer to the list of children that quit
    int quit_children_num;          // Number of children that quit
    int total_time;                 // Total execution time of the process
    int startTime;                  // Start time of the process
    int lastRunTime;                // Time when the process was last executed
    int parent_pid;                 // Parent process ID
    int zapped;                     // Flag indicating whether the process was zapped
    int kids;                       // Number of child processes
    int kid_num;                    // Number of the child process
    int kids_status_list[MAXPROC];  // Status list of child processes
    int quit_code;                  // Quit code of the process
    int proc_table_location;        // Location of the process in the process table
    int parent_location;            // Location of the parent process in the process table
    int blocked_by;                 // Process ID of the process that blocked this process
} ;



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

/* Some useful constants.  Add more as needed... */
#define NO_CURRENT_PROCESS NULL
#define MINPRIORITY 5
#define MAXPRIORITY 1
#define SENTINELPID 1
#define SENTINELPRIORITY LOWEST_PRIORITY
#define READY 2
#define QUIT 1
#define RUNNING 4
#define ZAP_BLOCK 5
#define BLOCKED 6
#define JOIN_BLOCK 3
#define TIME_SLICE_DURATION 80000

