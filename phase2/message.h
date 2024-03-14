// Macro definitions for general purposes
#define DEBUG2 1
#define USED 1
#define UNUSED 0

// Statuses
#define ACTIVE 2
#define FAILED 3

// Block types
#define SEND_BLOCK 101
#define RECV_BLOCK 102

// Table types
#define MAILBOX_TABLE 1
#define SLOT_TABLE    2
#define PROC_TABLE    3

// Type definitions for easier usage
typedef struct mailbox mail_box;
typedef struct mailbox *mboxPtr;

typedef struct mail_slot mail_slot;
typedef struct mail_slot *slot_ptr;

typedef struct mbox_proc mbox_proc;
typedef struct mbox_proc *mbox_proc_ptr;

// Structure definitions
struct mailbox {
   int           mbox_id;
   int           status;
   int           num_slots;
   int           max_slot_size;
   int           mbox_slots_used;
   slot_ptr      slots;
   mbox_proc_ptr blocked_procs;
   mbox_proc_ptr block_sendlist;
   mbox_proc_ptr block_recvlist;
};

struct mail_slot {
   int       mbox_id;
   int       slot_id;
   int       status;
   char      message[MAX_MESSAGE];
   int       msg_size;
   slot_ptr  next_slot;
};

struct mbox_proc {
   short           pid;
   int           status;
   void         *message;
   int           msg_size;
   int           mbox_release;
   mbox_proc_ptr next_block_send;
   mbox_proc_ptr next_block_recv;
   mbox_proc_ptr next_ptr;
};

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

