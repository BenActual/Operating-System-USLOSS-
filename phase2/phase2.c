/* ------------------------------------------------------------------------
   phase2.c
   Applied Technology
   College of Applied Science and Technology
   The University of Arizona
   CSCV 452

   ------------------------------------------------------------------------ */
#include <stdlib.h>
#include <phase1.h>
#include <phase2.h>
#include <usloss.h>
#include <stdio.h>
#include <string.h>

#include "message.h"

/* ------------------------- Prototypes ----------------------------------- */
int start1 (char *);
extern int start2 (char *); 

int MboxCreate(int slots, int slot_size);
int MboxSend(int mbox_id, void *msg_ptr, int msg_size);
int MboxReceive(int mbox_id, void *msg_ptr, int msg_size);

int MboxRelease(int mbox_id);
int MboxCondSend(int mbox_id, void *msg_ptr, int msg_size);
int MboxCondReceive(int mbox_id, void *msg_ptr, int max_msg_size);

void Check_kernel_mode(char *func_name);
void EnableInterrupts();
void DisableInterrupts();
int Check_mode(void);
void ClockInterruptHandler(int dev, void *punit);
void DiskInterruptHandler(int dev, void *punit);
void TerminalInterruptHandler(int dev, void *punit);
void SyscallInterruptHandler(int dev, void *unit);
void HandleInvalidSyscall(sysargs *args); 
void ResetMailbox(int mbox_id);
void ResetMailSlot(int slot_id);
void ResetProcessMailSlot(int pid);
int NextFreeSlot();
slot_ptr init_slot(int slot_index, int mbox_id, void *msg_ptr, int msg_size);
int add_slot_list(slot_ptr added_slot, mboxPtr mbox_ptr);
int check_io();
int WaitForDevice(int type, int unit, int *status);

/* -------------------------- Globals ------------------------------------- */

// Debug flag used to control verbose output for debugging purposes.
int debugflag2 = 0;

/* Array of MailBox structures to represent each mailbox in the system. */
mail_box MailBoxTable[MAXMBOX];

/* Array of MailSlot structures for storing messages passed through mailboxes. */
mail_slot MailBoxSlots[MAXSLOTS];

/* Process table for Phase 2, tracking processes involved in mailbox operations. */
mbox_proc ProcTable[MAXPROC];

// Counter to keep track of the total number of slots currently in use across all mailboxes.
int mbox_slots_used = 0;

// System call vector array; each entry points to a function handling a specific system call.
void(*sys_vec[MAXSYSCALLS])(sysargs *args);

/* -------------------------- Functions ----------------------------------- */

/* ------------------------------------------------------------------------
   Name - start1
   Purpose - Initializes mailboxes and interrupt vector.
             Start the phase2 test process.
   Parameters - one, default arg passed by fork1, not used here.
   Returns - one to indicate normal quit.
   Side Effects - lots since it initializes the phase2 data structures.
   ----------------------------------------------------------------------- */
int start1(char *arg) {
    // Ensure this function is called in kernel mode for safety.
    Check_kernel_mode("start1");
   
    // Disable interrupts 
    DisableInterrupts();
   
    int kid_pid, status; // Variables for process ID of the child and its termination status.
    int i; // Loop index.

    // Debugging output at the start of the function.
    if (DEBUG2 && debugflag2) {
        console("start1(): at beginning\n");
    }

   /* Initialize the mail box table, slots, & other data structures.
    * Initialize int_vec and sys_vec, allocate mailboxes for interrupt
    * handlers.  Etc... */

    // Initialize the process table entries to a safe state.
    for (i = 0; i < MAXPROC; i++) {
        ResetProcessMailSlot(i); // Function call abstracting initialization of a process table entry.
    }

    // Initialize all mailboxes in the mailbox table.
    for (i = 0; i < MAXMBOX; i++) {
        MailBoxTable[i].mbox_id = i; // Assign unique ID.
        ResetMailbox(i); // Initialize mailbox state.
    }

    // Initialize all slots in the mailbox slots array.
    for (i = 0; i < MAXSLOTS; i++) {
        MailBoxSlots[i].slot_id = i; // Assign unique ID.
        ResetMailSlot(i); // Initialize slot state.
    }

    // Initialize mailboxes specifically for the clock device handlers.
    for (i = 0; i < 7; i++) { // Assuming 7 is the number of required mailboxes.
        MboxCreate(0, MAX_MESSAGE); // Create mailbox with max message size.
    }

    // Set up interrupt vector table with appropriate handlers for devices and syscall.
    int_vec[CLOCK_DEV] = ClockInterruptHandler;
    int_vec[DISK_DEV] = DiskInterruptHandler;
    int_vec[TERM_DEV] = TerminalInterruptHandler;
    int_vec[SYSCALL_INT] = SyscallInterruptHandler;

    // Initialize system call vector table with a default handler to catch undefined syscalls.
    for (i = 0; i < MAXSYSCALLS; i++) {
        sys_vec[i] = HandleInvalidSyscall; // Default system call handler.
    }

    // Re-enable interrupts after initialization is complete.
    EnableInterrupts();

    // Process creation and management:
    // Create the start2 process and wait for it to complete before proceeding.
    if (DEBUG2 && debugflag2) {
        console("start1(): fork'ing start2 process\n");
    }

    // Fork a new process for 'start2'.
    kid_pid = fork1("start2", start2, NULL, 4 * USLOSS_MIN_STACK, 1);

    // Wait for the start2 process to terminate and ensure it is the correct process.
    if (join(&status) != kid_pid) {
        console("start2(): join returned something other than start2's pid\n");
    }

    // Successfully completed initialization and process management.
    return 0;
} // End of start1



/* ------------------------------------------------------------------------
   Name - MboxCreate
   Purpose - gets a free mailbox from the table of mailboxes and initializes it 
   Parameters - maximum number of slots in the mailbox and the max size of a msg
                sent to the mailbox.
   Returns - -1 to indicate that no mailbox was created, or a value >= 0 as the
             mailbox id.
   Side Effects - initializes one element of the mail box array. 
   ----------------------------------------------------------------------- */
int MboxCreate(int slots, int slot_size) {
   
    // Ensure we are in kernel mode
    Check_kernel_mode("MboxCreate");

   // disable interrupts for safety.
   DisableInterrupts();
   
    // Validate the slot size and slots count right at the start.
    if (slot_size < 0 || slot_size > MAX_MESSAGE) {
        if (DEBUG2 && debugflag2) {
            console("MboxCreate(): Slot size is not valid.\n");
        }
        return -1;
    }

    if (slots < 0 || slots > MAXSLOTS) {
        if (DEBUG2 && debugflag2) {
            console("MboxCreate(): Slots count is not valid.\n");
        }
        return -1;
    }

    // Ensure there is at least one mailbox slot available.
    if (mbox_slots_used >= MAXMBOX) {
        if (DEBUG2 && debugflag2) {
            console("MboxCreate(): No mailboxes are available.\n");
        }
        return -1;
    }

    // Search for an unused mailbox within the MailBoxTable.
    int mboxID = -1; // Default to an invalid ID to indicate not found yet.
    for (int i = 0; i < MAXMBOX; i++) {
        if (MailBoxTable[i].status == UNUSED) {
            mboxID = i; // Set the unused mailbox ID.
            mbox_slots_used++; // Increment the count of used mailbox slots.
            break; // Exit the loop once an unused mailbox is found.
        }
    }

    // If no unused mailbox was found, return an error.
    if (mboxID == -1) {
        if (DEBUG2 && debugflag2) {
            console("MboxCreate(): Failed to find an unused mailbox.\n");
        }
        return -1;
    }

    // Initialize the selected mailbox with the provided parameters.
    MailBoxTable[mboxID].mbox_id = mboxID;
    MailBoxTable[mboxID].status = USED;
    MailBoxTable[mboxID].num_slots = slots;
    MailBoxTable[mboxID].max_slot_size = slot_size;
    MailBoxTable[mboxID].slots = 0; // Initialize with no slots currently used.
    MailBoxTable[mboxID].blocked_procs = 0; // Initialize with no processes currently blocked.

   // Re-enable interrupts
    EnableInterrupts();
   
    // Successfully return the unique mailbox ID.
    return mboxID;
}
/* MboxCreate */


/* ------------------------------------------------------------------------
   Name - MboxSend
   Purpose - Put a message into a slot for the indicated mailbox.
             Block the sending process if no slot available.
   Parameters - mailbox id, pointer to data of msg, # of bytes in msg.
   Returns - zero if successful, -1 if invalid args.
   Side Effects - none.
   ----------------------------------------------------------------------- */
int MboxSend(int mbox_id, void *msg_ptr, int msg_size) {
    // Check kernel mode and disable interrupts for operation safety.
    Check_kernel_mode("MboxSend");
    DisableInterrupts();

    // Validate message size.
    if (msg_size < 0 || msg_size > MAX_MESSAGE) {
        console("Message is to large.\n");
        return -1;     
    }

    // Validate mailbox ID range.
    if (mbox_id < 1 || mbox_id > MAXMBOX) {
        console("The message box ID is not valid.\n");
        return -1;     
    }

    // Get a pointer to the mailbox.
    mboxPtr *mbox_ptr = &MailBoxTable[mbox_id];

    // If the mailbox cannot accommodate the message, enable interrupts and return.
    if (mbox_ptr->num_slots != 0 && msg_size > mbox_ptr->max_slot_size) {
        EnableInterrupts();
        return -1;
    }

    // Update process table with message details.
    int pid = getpid();
    ProcTable[pid % MAXPROC].pid = pid;
    ProcTable[pid % MAXPROC].status = ACTIVE;
    ProcTable[pid % MAXPROC].message = msg_ptr;
    ProcTable[pid % MAXPROC].msg_size = msg_size;

    // If no slots available or receiving process is not waiting, block the sending process.
    if (mbox_ptr->num_slots <= mbox_ptr->mbox_slots_used && mbox_ptr->block_recvlist == NULL) {
        mbox_proc_ptr* lastPtr = &(mbox_ptr->block_sendlist);
        while (*lastPtr != NULL) {
            lastPtr = &((*lastPtr)->next_block_send);
        }
        *lastPtr = &ProcTable[pid % MAXPROC];

        block_me(SEND_BLOCK);
        if (ProcTable[pid % MAXPROC].mbox_release) {
            EnableInterrupts();
            return -3;
        }

      if (is_zapped())
      {
         EnableInterrupts();
         return -3;
      }
    }

    // Check for a process waiting to receive; if so, transfer the message directly.
    if (mbox_ptr->block_recvlist != NULL) {
        if (msg_size > mbox_ptr->block_recvlist->msg_size) {
            mbox_ptr->block_recvlist->status = FAILED;
            int pidToUnblock = mbox_ptr->block_recvlist->pid;
            mbox_ptr->block_recvlist = mbox_ptr->block_recvlist->next_ptr;
            unblock_proc(pidToUnblock);
            EnableInterrupts();
            return -1;
        }

        memcpy(mbox_ptr->block_recvlist->message, msg_ptr, msg_size);
        mbox_ptr->block_recvlist->msg_size = msg_size;

        int recvPid = mbox_ptr->block_recvlist->next_ptr;
        unblock_proc(recvPid);
        EnableInterrupts();

         if (is_zapped())
         {
            EnableInterrupts();
            return -3;
         }
    }

    // Check for mail slot table overflows.
    int slot = NextFreeSlot();
    if (slot == -2) {
        console("MboxSend(): No slots in system. Halting...\n");
        halt(1);
    }

    // Initialize and add the slot to the mailbox's slot list.
    slot_ptr added_slot = init_slot(slot, mbox_id, msg_ptr, msg_size);
    add_slot_list(added_slot, mbox_ptr);

   
    if (is_zapped()) {
      {
         EnableInterrupts();
         return -3;
      }
    
    EnableInterrupts();      
    return 0;
}
 /* MboxSend */


/* ------------------------------------------------------------------------
   Name - MboxReceive
   Purpose - Get a msg from a slot of the indicated mailbox.
             Block the receiving process if no msg available.
   Parameters - mailbox id, pointer to put data of msg, max # of bytes that
                can be received.
   Returns - actual size of msg if successful, -1 if invalid args.
   Side Effects - none.
   ----------------------------------------------------------------------- */
int MboxReceive(int mbox_id, void *msg_ptr, int msg_size) {
    Check_kernel_mode("MboxReceive");
    DisableInterrupts();

    // Validate mailbox ID.
    if (mbox_id < 0 || mbox_id >= MAXMBOX) {
        console("The message box ID is not valid.\n");
        EnableInterrupts(); // Remember to re-enable interrupts on error.
        return -1;
    }

    mboxPtr *mbox_ptr = &MailBoxTable[mbox_id];

    // Update the process table for the current process.
    int pid = getpid();
    mbox_proc_ptr *procPtr = &ProcTable[pid % MAXPROC];
    procPtr->pid = pid;
    procPtr->status = ACTIVE;
    procPtr->message = msg_ptr;
    procPtr->msg_size = msg_size;

    // If no messages are available in the mailbox.
    if (mbox_ptr->slots == NULL) {
        mbox_proc_ptr* lastPtr = &(mbox_ptr->block_recvlist);
        while (*lastPtr != NULL) {
            lastPtr = &((*lastPtr)->next_block_recv);
        }
        *lastPtr = procPtr;

        block_me(RECV_BLOCK);

        // Check after being unblocked.
        if (procPtr->mbox_release || is_zapped()) {
            EnableInterrupts();
            return -3;
        }
        if (procPtr->status == FAILED) {
            EnableInterrupts();
            return -1;
        }

        EnableInterrupts();
        return procPtr->msg_size;
    } else {
        // Messages are available, so proceed to receive one.
        slot_ptr slotPtr = mbox_ptr->slots;
        if (slotPtr->msg_size > msg_size) {
            EnableInterrupts();
            return -1; // Message size exceeds the receiver's buffer.
        }

        memcpy(msg_ptr, slotPtr->message, slotPtr->msg_size);
        int receivedMsgSize = slotPtr->msg_size;

        mbox_ptr->slots = slotPtr->next_slot;
        ResetMailSlot(slotPtr->slot_id); // Assuming this frees the slot.
        mbox_ptr->mbox_slots_used--;

        // Process any processes waiting to send if slots are now available.
        if (mbox_ptr->block_sendlist != NULL) {
            // Assuming you have mechanisms to initiate sending processes here.
            // Since process_send_queue() is not to be used, implement the sending logic here.

            slot_ptr new_slot = init_slot(NextFreeSlot(), mbox_ptr->mbox_id, 
                                          mbox_ptr->block_sendlist->message,
                                          mbox_ptr->block_sendlist->msg_size);
            if (new_slot != NULL) { // Check if the slot was successfully initialized.
                add_slot_list(new_slot, mbox_ptr);
                
                int pidToSend = mbox_ptr->block_sendlist->pid;
                mbox_proc_ptr nextInLine = mbox_ptr->block_sendlist->next_block_send;

                mbox_ptr->block_sendlist = nextInLine; // Move to the next process in the queue.
                unblock_proc(pidToSend); // Unblock the process that was waiting to send.
            }
        }

        EnableInterrupts();
        return receivedMsgSize; // Return the size of the received message.
    }
}
/* MboxReceive */


//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< FUNCTIONS ADDED >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


/* ------------------------------------------------------------------------
   Name - MboxRelease
   Purpose - Frees a mailbox and notifies any blocked processes.
   Parameters - mbox_id (mailbox ID).
   Returns - 0 (success), -1 (invalid ID), -3 (caller zapped).
   Side Effects - Resets mailbox and unblocks waiting processes.
   ----------------------------------------------------------------------- */
int MboxRelease(int mbox_id) {
    Check_kernel_mode("MboxRelease");
    DisableInterrupts();

    // Validate the mailbox ID.
    if (mbox_id < 0 || mbox_id >= MAXMBOX) {
        EnableInterrupts();
        return -1;
    }

    // Check if the mailbox was previously created and is in use.
    if (MailBoxTable[mbox_id].status == UNUSED) {
        EnableInterrupts();
        return -1;
    }

    mboxPtr *mbox_ptr = &MailBoxTable[mbox_id];

    // Set mailbox status to UNUSED to prevent new operations on it.
    mbox_ptr->status = UNUSED;

    // Process all blocked processes in the send list.
    while (mbox_ptr->block_sendlist != NULL) {
        mbox_proc_ptr procToSend = mbox_ptr->block_sendlist;
        procToSend->mbox_release = 1; // Mark process as released.
        mbox_ptr->block_sendlist = procToSend->next_block_send; // Move to next in list.
        unblock_proc(procToSend->pid); // Unblock the process.
        DisableInterrupts();
    }

    // Process all blocked processes in the receive list.
    while (mbox_ptr->block_recvlist != NULL) {
        mbox_proc_ptr procToRecv = mbox_ptr->block_recvlist;
        procToRecv->mbox_release = 1; // Mark process as released.
        mbox_ptr->block_recvlist = procToRecv->next_block_recv; // Move to next in list.
        unblock_proc(procToRecv->pid); // Unblock the process.
        DisableInterrupts();
    }

    // Clear out the mailbox to reset its state fully.
    ResetMailbox(mbox_id);
   

    // Return the zapped status to indicate if the current process was interrupted.
    if (is_zapped())
      {
         EnableInterrupts();
         return -3;
      } 

    EnableInterrupts();
    return 0;
}
 /* MboxRelease */


 
/* ------------------------------------------------------------------------
   Name - MboxCondReceive
   Purpose - Non-blockingly receives a message from a specified MBOX slot.
   Parameters - mbox_id (mailbox ID), msg_ptr (buffer for message), max_msg_size (buffer size).
   Returns - Message size (success), -1 (error), -2 (no message), -3 (caller zapped).
   Side Effects - May remove a message from a mailbox slot.
   ----------------------------------------------------------------------- */
int MboxCondSend(int mbox_id, void *msg_ptr, int msg_size) {
    Check_kernel_mode("MboxCondSend");
    DisableInterrupts();

    // Validate the mailbox ID.
    if (mbox_id < 0 || mbox_id >= MAXMBOX) {
        EnableInterrupts();
        return -1;
    }

    mboxPtr *mbox_ptr = &MailBoxTable[mbox_id];

    // Validate the message size against the maximum slot size for this mailbox.
    if (msg_size > mbox_ptr->max_slot_size) {
        EnableInterrupts();
        return -1;
    }

    // Add the current process to the Phase2 process table.
    int pid = getpid();
    ProcTable[pid % MAXPROC].pid = pid;
    ProcTable[pid % MAXPROC].status = ACTIVE;
    ProcTable[pid % MAXPROC].message = msg_ptr;
    ProcTable[pid % MAXPROC].msg_size = msg_size; // Should this be `msg_size` instead of MAX_MESSAGE?

    // If there are no available slots in the mailbox, return immediately.
    if (mbox_ptr->num_slots == mbox_ptr->mbox_slots_used) {
        EnableInterrupts();
        return -2;
    }

    // Check if there's a process waiting to receive a message and if so, send the message directly.
    if (mbox_ptr->block_recvlist != NULL) {
        if (msg_size > mbox_ptr->block_recvlist->msg_size) {
            EnableInterrupts();
            return -1;
        }

        // Copy the message directly to the waiting receiver.
        memcpy(mbox_ptr->block_recvlist->message, msg_ptr, msg_size);
        mbox_ptr->block_recvlist->msg_size = msg_size;
        int recvPid = mbox_ptr->block_recvlist->pid;
        mbox_ptr->block_recvlist = mbox_ptr->block_recvlist->next_block_recv;
        unblock_proc(recvPid);
        EnableInterrupts();
        return 0; // Success, message sent directly to a waiting receiver.
    }

    // If no direct receiver, try to find an empty slot for the message.
    int slot = NextFreeSlot();
    if (slot == -2) {
        // No slots available.
        EnableInterrupts();
        return -2;
    }

    // Initialize the slot with the message and add it to the mailbox's slot list.
    slot_ptr added_slot = init_slot(slot, mbox_id, msg_ptr, msg_size);
    if (!added_slot) {
        EnableInterrupts();
        return -2; // Fail to initialize or add the slot implies a resource issue.
    }
    add_slot_list(added_slot, mbox_ptr);

   if (is_zapped())
      {
         EnableInterrupts();
         return -3;
      }
      
    EnableInterrupts();
    return 0; // Message successfully queued in a slot.
}
 /* MboxCondSend */

/* ------------------------------------------------------------------------
   Name - MboxCondSend
   Purpose - Sends a message to a mailbox non-blockingly.
   Parameters - mbox_id (mailbox ID), msg_ptr (message data), msg_size (message size).
   Returns - 0 (success), -1 (error), -2 (mailbox full), -3 (caller zapped).
   Side Effects - May directly transfer message to waiting receiver.
   ----------------------------------------------------------------------- */
int MboxCondReceive(int mbox_id, void *msg_ptr, int max_msg_size) {
    Check_kernel_mode("MboxCondReceive");
    DisableInterrupts();

    // Validate mailbox availability and ID range.
    if (mbox_id < 0 || mbox_id >= MAXMBOX || MailBoxTable[mbox_id].status == UNUSED) {
        EnableInterrupts();
        return -1;
    }

    mboxPtr *mbox_ptr = &MailBoxTable[mbox_id];

    // Validate message size.
    if (max_msg_size < 0) {
        EnableInterrupts();
        return -1;
    }

    // Update process status in the Phase2 process table.
    int pid = getpid();
    ProcTable[pid % MAXPROC].pid = pid;
    ProcTable[pid % MAXPROC].status = ACTIVE;
    ProcTable[pid % MAXPROC].message = msg_ptr;
    ProcTable[pid % MAXPROC].msg_size = max_msg_size;

    // If no messages are in the mailbox, return immediately.
    if (mbox_ptr->slots == NULL) {
        EnableInterrupts();
        return -2;
    }

    slot_ptr slotPtr = mbox_ptr->slots;
    // Check if the message buffer is large enough for the message.
    if (slotPtr->msg_size > max_msg_size) {
        EnableInterrupts();
        return -1;
    }

    // Copy the message into the receiver's buffer.
    memcpy(msg_ptr, slotPtr->message, slotPtr->msg_size);
    int receivedMsgSize = slotPtr->msg_size;

    // Clean up the used slot.
    ResetMailSlot(slotPtr->slot_id);
    mbox_ptr->slots = slotPtr->next_slot; // Move to the next slot.
    mbox_ptr->mbox_slots_used--; // Decrement the count of used slots.

    // Process any blocked send processes.
    if (mbox_ptr->block_sendlist != NULL) {
        int slot = NextFreeSlot();
        if (slot != -2) { // Ensure there's an available slot.
            slot_ptr added_slot = init_slot(slot, mbox_id, mbox_ptr->block_sendlist->message, mbox_ptr->block_sendlist->msg_size);
            if (added_slot) { // Ensure slot was initialized.
                add_slot_list(added_slot, mbox_ptr);

                // Unblock the first process in the send queue.
                int pidToSend = mbox_ptr->block_sendlist->pid;
                mbox_ptr->block_sendlist = mbox_ptr->block_sendlist->next_block_send;
                unblock_proc(pidToSend);
            }
        }
    }

   if (is_zapped())
      {
         EnableInterrupts();
         return -3;
      }
      
    EnableInterrupts();
    return receivedMsgSize; // Return the size of the received message instead of is_zapped().
}
/* MboxCondReceive */


int check_io(){

   return 0;

} /* check_io */



/* --------------------------------------------------------------------------------
   Name - Check_kernel_mode
   Purpose - Ensures that the system is in kernel mode when executing certain operations.
             This function is crucial for maintaining system integrity and preventing
             unauthorized access to kernel-level operations by user mode processes.
   Parameters - *func_name: A string indicating the name of the function where the
                 kernel mode check is being performed. This aids in debugging by
                 identifying where the check was invoked.
   Returns - None. This function does not return a value but will halt the system
             if it finds that the operation was attempted in user mode.
   Side Effects - If the system is in user mode, this function prints an error message
                  using the console function and then halts the system, preventing any
                  further execution of unauthorized operations.
   -------------------------------------------------------------------------------- */
void Check_kernel_mode(char *func_name) {
    union psr_values caller_psr;  // Holds the caller's PSR values for checking the current mode.
    char buffer[200];  // Buffer for formatting debug messages.

    // Debugging output, if enabled.
    if (DEBUG2 && debugflag2) {
        sprintf(buffer, "Check_kernel_mode(): called for function %s\n", func_name);
        console("%s", buffer);
    }

    // Check if currently in kernel mode; halt if not.
    caller_psr.integer_part = psr_get();  // Retrieve the current processor status.
    if (caller_psr.bits.cur_mode == 0) {  // Check if the current mode bit indicates user mode.
        console("%s", buffer);  // Reuse the buffer to report the error.
        halt(1);  // Halt the system to prevent execution in an unauthorized mode.
    }
}
/* Check_kernel_mode */

/* ------------------------------------------------------------------------
   Name - DisableInterrupts
   Purpose - Disables interrupts in the system, ensuring that this operation
             is performed only when in kernel mode to maintain system security
             and integrity.
   Parameters - None.
   Returns - None.
   Side Effects - If called outside of kernel mode, the system will halt with
                  an error message. If in kernel mode, interrupts will be
                  turned off, preventing the system from handling interrupts
                  until they are explicitly re-enabled. This could affect system
                  responsiveness and the handling of concurrent operations.
   ----------------------------------------------------------------------- */
void DisableInterrupts()
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
}  /* DisableInterrupts */

/* ------------------------------------------------------------------------
   Name - EnableInterrupts
   Purpose - Enables interrupts if the processor is in kernel mode, otherwise halts the system
   Parameters - none
   Returns - void
   Side Effects - May halt the system if not in kernel mode
   ----------------------------------------------------------------------- */
void EnableInterrupts()
{
   if (Check_mode() == 0)
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
}/* enableInterupts */

int Check_mode(void)
{
   return PSR_CURRENT_MODE & psr_get();
}


/* --------------------------------------------------------------------------------
   Name - ClockInterruptHandler
   Purpose - Handles clock interrupts by sending periodic messages and ensuring
             time-slicing for processes.
   Parameters - dev: Device number (expected to be CLOCK_DEV).
                punit: Pointer to the unit number of the clock device.
   Returns - None. Incorrect device or unit range errors are handled internally.
   Side Effects - Sends a message through MboxCondSend for every 5th call (100 ms)
                  and calls time_slice to potentially switch processes.
   -------------------------------------------------------------------------------- */
void ClockInterruptHandler(int dev, void *punit) {
    // Cast void pointer to integer to represent the unit number.
    int unit = (int)punit;

    // Verify the device is the expected clock device.
    if (dev != CLOCK_DEV) {
        if (DEBUG2 && debugflag2) {
            console("ClockInterruptHandler(): Invoked for a non-clock device.\n");
        }
        return;  // Early return on incorrect device.
    }

    // Ensure the unit number is within valid bounds.
    if (unit < 0 || unit >= CLOCK_UNITS) {
        if (DEBUG2 && debugflag2) {
            console("ClockInterruptHandler(): Unit number %d is out of range.\n", unit);
        }
        return;  // Early return on invalid unit number.
    }

    // Static counter to keep track of clock ticks handled.
    static int tickCount = 0;
 
    // Increment the tick count by the defined milliseconds per tick.
    tickCount += CLOCK_MS;

    // Perform an action every 100 ms, assuming 20 ms per tick.
    if (tickCount % 100 == 0) {
        // Conditionally send a message if it's time.
        MboxCondSend(unit, &dummyMsg, sizeof(dummyMsg));
    }

    // Call time_slice to potentially switch processes according to scheduling.
    time_slice();
}

/* ClockInterruptHandler */

/* --------------------------------------------------------------------------------
   Name - DiskInterruptHandler
   Purpose - Manages disk interrupt events by verifying the device type and unit number,
             reading the device's status, and conditionally forwarding this status
             to a mailbox based on the unit number. Ensures that disk operations
             trigger appropriate system responses.
   Parameters - dev: The identifier for the device generating the interrupt.
               punit: A pointer to the unit number associated with the interrupt.
   Returns - Returns -1 if the device type or unit number is incorrect; otherwise, does not
             explicitly return a value but may influence system state through mailbox communication.
   Side Effects - If the device and unit checks are successful, the disk's status is sent
                  to a designated mailbox. This operation can affect processes waiting on
                  disk I/O completion, potentially unblocking them or altering their execution
                  state based on the disk operation's outcome.
   -------------------------------------------------------------------------------- */
void DiskInterruptHandler(int dev, void *punit) {
    // Ensure the handler is responding to disk device interrupts.
    if (dev != DISK_DEV) {
        console("DiskInterruptHandler(): Incorrect device. Expected DISK_DEV.\n");
        return -1;
    }

    int unit = (int)punit;
    // Validate the disk unit number.
    if (unit < 0 || unit >= DISK_UNITS) {
        console("DiskInterruptHandler(): Unit %d out of range.\n", unit);
        return -1;
    }

    // Retrieve the status from the disk device.
    int status;
    device_input(DISK_DEV, unit, &status);

    // Attempt to send the disk status to the mailbox associated with this unit.
    // This is a non-blocking attempt to communicate device status.
    int sendResult = MboxCondSend(unit, &status, sizeof(status));
    // Optionally handle or log sendResult to monitor mailbox communication status.
}
 /* DiskInterruptHandler */

/* --------------------------------------------------------------------------------
    Name - TerminalInterruptHandler
    Purpose - Handles interrupts from terminal devices by validating the device and unit,
              reading the terminal status, and conditionally sending this status to a mailbox.
    Parameters - dev (device number), punit (pointer to unit number).
    Returns - None explicitly, but -1 is returned in error cases.
    Side Effects - May send a message to a mailbox corresponding to the terminal unit.
   -------------------------------------------------------------------------------- */

void TerminalInterruptHandler(int dev, void *punit) {
    int status;
    int unit = (int)punit;

    // Validate the device is a terminal device.
    if (dev != TERM_DEV) {
        if (DEBUG2 && debugflag2) {
            console("TerminalInterruptHandler(): Called on non-terminal device.\n");
        }
        return -1;
    }

    // Validate the unit number is within the acceptable range.
    if (unit < 0 || unit >= TERM_UNITS) {
        if (DEBUG2 && debugflag2) {
            console("TerminalInterruptHandler(): Unit number %d is out of range.\n", unit);
        }
        return -1;
    }

    // Read the status register of the terminal device.
    device_input(TERM_DEV, unit, &status);

    // Attempt to send the status to the mailbox associated with this terminal unit.
    int result = MboxCondSend(unit, &status, sizeof(status));

    // Note: The function currently does not utilize 'result'. 
}
/* TerminalInterruptHandler */

/* --------------------------------------------------------------------------------
   Name - SyscallInterruptHandler
   Purpose - Handles system call interrupts by invoking the appropriate system call function
             based on the syscall number provided in the sysargs structure.
   Parameters - dev: Device number to verify the interrupt source.
                unit: Pointer to sysargs structure containing syscall number and arguments.
   Returns - Does not return a value directly but may halt the system on error.
   Side Effects - Depending on the system call invoked, various side effects can occur,
                  ranging from process creation, termination, to message passing and I/O operations.
   -------------------------------------------------------------------------------- */
void SyscallInterruptHandler(int dev, void *unit) {
    sysargs *sys_ptr = (sysargs *) unit; // Cast to sysargs pointer for system call arguments.

    // Ensure this handler is invoked for the correct device type (SYSCALL_INT).
    if (dev != SYSCALL_INT) {
        console("SyscallInterruptHandler(): Incorrect device. Halting.\n");
        halt(1); // Halt system on device mismatch.
    }

    // Validate the system call number is within the defined range.
    if (sys_ptr->number < 0 || sys_ptr->number >= MAXSYSCALLS) {
        console("SyscallInterruptHandler(): System call number out of range. Halting.\n");
        halt(1); // Halt system if the syscall number is out of range.
    }

    // Dispatch to the appropriate system call handler based on syscall number.
    sys_vec[sys_ptr->number](sys_ptr);
}
 /* SyscallInterruptHandler */

/* --------------------------------------------------------------------------------
   Name - HandleInvalidSyscall
   Purpose - Acts as a placeholder for unimplemented system calls and reports an error.
   Parameters - args: Pointer to sysargs structure containing the syscall number and arguments.
   Returns - Does not return; halts the system on invocation.
   Side Effects - Halts the system, indicating an attempt to use an unimplemented or invalid system call.
   -------------------------------------------------------------------------------- */
void HandleInvalidSyscall(sysargs *args) {
    printf("HandleInvalidSyscall: invalid syscall %d. Halting...\n", args->number);
    halt(1);
}
 /* HandleInvalidSyscall */

/* --------------------------------------------------------------------------------
   Name - WaitForDevice
   Purpose - Waits for a specified device to complete an operation, typically used for synchronization.
   Parameters - type: The type of device (DISK_DEV, CLOCK_DEV, TERM_DEV).
                unit: The specific unit of the device type to wait on.
                status: Pointer to an integer where the device's status will be stored.
   Returns - 0 on successful wait, -1 if the process calling WaitForDevice was zapped.
   Side Effects - Blocks the calling process until the specified device operation completes.
                  The process may also be terminated if it is zapped while waiting.
   -------------------------------------------------------------------------------- */
int WaitForDevice(int type, int unit, int *status) {
    int result = 0;

    // Validate the device type.
    if ((type != DISK_DEV) && (type != CLOCK_DEV) && (type != TERM_DEV)) {
        if (DEBUG2 && debugflag2) {
            console("WaitForDevice(): incorrect device type. Halting..\n");
        }
        halt(1);
    }
    
    // Use a mailbox to wait for the device operation to complete.
    switch (type) {
        case DISK_DEV:
        case CLOCK_DEV:
        case TERM_DEV:
            result = MboxReceive(unit, status, sizeof(int));
            break;
        default:
            printf("WaitForDevice(): unexpected device type (%d). Halting...\n", type);
            halt(1); // Halt on invalid device type.
    } 

    //check if zapped
    if(result == -3) 
    {
        return -1;
    }
   
    // Check if the process was zapped while waiting.
    //return (result == -3) ? -1 : 0;
   return 0;
}
 /* WaitForDevice */

/* --------------------------------------------------------------------------------
   Name - ResetMailbox
   Purpose - Resets a mailbox to its initial, unused state by clearing its properties.
   Parameters - mbox_id: The ID of the mailbox to be reset.
   Returns - None.
   Side Effects - Modifies the specified mailbox in the MailBoxTable, marking it as UNUSED,
                  clearing its process waitlists, and resetting its slot usage and capacity attributes.
   -------------------------------------------------------------------------------- */
void ResetMailbox(int mbox_id) {
    // Reset the mailbox identified by mbox_id to its default state.
    MailBoxTable[mbox_id].status = UNUSED;            // Mark the mailbox as unused.
    MailBoxTable[mbox_id].block_recvlist = NULL;      // Clear the list of blocked receiving processes.
    MailBoxTable[mbox_id].block_sendlist = NULL;      // Clear the list of blocked sending processes.
    MailBoxTable[mbox_id].slots = NULL;               // Clear the pointer to the slots.
    MailBoxTable[mbox_id].num_slots = -1;             // Reset the total number of slots to an invalid value.
    MailBoxTable[mbox_id].mbox_slots_used = -1;       // Reset the number of used slots to an invalid value.
    MailBoxTable[mbox_id].max_slot_size = -1;         // Reset the maximum slot size to an invalid value.
}
/*ResetMailbox*/
/* --------------------------------------------------------------------------------
   Name - ResetMailSlot
   Purpose - Resets a mail slot to its initial, unused state by clearing its properties.
   Parameters - slot_id: The ID of the mail slot to be reset.
   Returns - None.
   Side Effects - Modifies the specified slot in the MailBoxSlots array, marking it as UNUSED,
                  and clearing its linkage and mailbox association.
   -------------------------------------------------------------------------------- */
void ResetMailSlot(int slot_id) {
    MailBoxSlots[slot_id].status = UNUSED;        // Mark the slot as unused.
    MailBoxSlots[slot_id].next_slot = NULL;       // Remove any linkage to next slots.
    MailBoxSlots[slot_id].mbox_id = -1;           // Disassociate the slot from any mailbox.
}
/*ResetMailSlot*/
/* --------------------------------------------------------------------------------
   Name - ResetProcessMailSlot
   Purpose - Resets the properties of a process table entry associated with mailbox operations.
   Parameters - pid: The process ID whose entry in the Phase2 process table is to be reset.
   Returns - None.
   Side Effects - Modifies the specified process's entry in the Phase2 process table, marking it
                  as UNUSED, clearing any message pointers, resetting process communication
                  attributes, and marking the process as not released from a mailbox.
   -------------------------------------------------------------------------------- */
void ResetProcessMailSlot(int pid) {
    int index = pid % MAXPROC; // Calculate the index in the process table.
    ProcTable[index].status = UNUSED;             // Mark the process status as unused.
    ProcTable[index].message = NULL;              // Clear the message pointer.
    ProcTable[index].next_block_recv = NULL;      // Clear the next blocked receive pointer.
    ProcTable[index].next_block_send = NULL;      // Clear the next blocked send pointer.
    ProcTable[index].pid = -1;                    // Reset the process ID to an invalid value.
    ProcTable[index].msg_size = -1;               // Reset the message size to an invalid value.
    ProcTable[index].mbox_release = 0;            // Mark the process as not released from a mailbox.
}
/*ResetProcessMailSlot*/
/* --------------------------------------------------------------------------------
   Name - NextFreeSlot
   Purpose - Finds and returns the index of the next available (unused) slot in the 
             MailBoxSlots array to be utilized for message passing.
   Parameters - None.
   Returns - The index of the first available slot if one exists, or -2 to indicate 
             that no slots are currently available.
   Side Effects - None directly from this function, but the returned slot index is 
                  typically used immediately after for message storage, affecting the 
                  status of that slot in the MailBoxSlots array.
   -------------------------------------------------------------------------------- */
int NextFreeSlot() {
    // Iterate through the MailBoxSlots array to find an unused slot.
    for (int i = 0; i < MAXSLOTS; i++) {
        if (MailBoxSlots[i].status == UNUSED) {
            // Return the index of the first unused slot found.
            return i;
        }
    }
    // Return -2 if no unused slot is found.
    return -2;
}
/*NextFreeSlot*/

/* --------------------------------------------------------------------------------
   Name - init_slot
   Purpose - Initializes a slot with provided message details, marking it as used.
   Parameters - slot_index: Index of the slot to initialize.
                mbox_id: Mailbox ID the slot is associated with.
                msg_ptr: Pointer to the message data to copy into the slot.
                msg_size: Size of the message data to copy.
   Returns - Pointer to the initialized slot (slot_ptr).
   Side Effects - Updates a slot in the MailBoxSlots array with message details and 
                  changes its status to USED, which can affect mailbox operations.
   -------------------------------------------------------------------------------- */
slot_ptr init_slot(int slot_index, int mbox_id, void *msg_ptr, int msg_size) {
    // Associate the slot with a mailbox and mark it as used.
    MailBoxSlots[slot_index].mbox_id = mbox_id;
    MailBoxSlots[slot_index].status = USED;

    // Copy the message into the slot. Ensure the message doesn't exceed slot capacity.
    // Assuming MailBoxSlots[slot_index].message is a buffer of adequate size.
    memcpy(MailBoxSlots[slot_index].message, msg_ptr, msg_size);

    // Set the message size for the slot.
    MailBoxSlots[slot_index].msg_size = msg_size;

    // Return a pointer to the initialized slot.
    return &MailBoxSlots[slot_index];
}
/*init_slot*/

/* --------------------------------------------------------------------------------
   Name - add_slot_list
   Purpose - Links a new slot to the end of a mailbox's slot list and updates the count of used slots.
   Parameters - added_slot: Pointer to the slot to be added.
                mbox_ptr: Pointer to the mailbox to which the slot will be added.
   Returns - The updated number of slots used in the mailbox after addition.
   Side Effects - Modifies the mailbox's slot list by appending a new slot to the end,
                  potentially changing the mailbox's state from empty to containing messages.
   -------------------------------------------------------------------------------- */
int add_slot_list(slot_ptr added_slot, mboxPtr mbox_ptr) {
    slot_ptr current = mbox_ptr->slots; // Start at the head of the list.

    if (current == NULL) {
        // If the list is empty, directly assign the added slot as the head.
        mbox_ptr->slots = added_slot;
    } else {
        // Traverse to the end of the list.
        while (current->next_slot != NULL) {
            current = current->next_slot;
        }
        // Link the new slot as the last element.
        current->next_slot = added_slot;
    }

    // Increment and return the count of slots used in this mailbox.
    return ++mbox_ptr->mbox_slots_used;
}
/*add_slot_list*/

