#ifndef PHASE3_SEMS_H
#define PHASE3_SEMS_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "semtables.h"
#include "linkedlist.h"
#include "main.h"

#define SEM_READY 0
#define SEM_USED  1
#define LOCKED    1
#define UNLOCKED  0
#define FREEING   2

/** ------------------------ Typedefs and Structs ------------------------ **/
typedef struct semaphore_struct semaphore_struct;
typedef struct semaphore_struct * sem_struct_ptr;
void SemaphoreInit(int index, short sid);
void AddToSemTable(int sid, int newStatus, int newValue);
int GetSemIndex(int sid);

#endif