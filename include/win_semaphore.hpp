/*
    Copyright (c) 2011, Dongsheng Song <songdongsheng@live.cn>
	
    Licensed to the Apache Software Foundation (ASF) under one or more
    contributor license agreements.  See the NOTICE file distributed with
    this work for additional information regarding copyright ownership.
    The ASF licenses this file to You under the Apache License, Version 2.0
    (the "License"); you may not use this file except in compliance with
    the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

/*
	Simple Windows replacement for POSIX semaphores 
	Modified by Daniel Tillett from libpthread <http://github.com/songdongsheng/libpthread>
	Copyright (c) 2015, Daniel Tillett <daniel.tillett @ gmail.com>
*/

#ifndef _SEMAPHORE_H_
#define _SEMAPHORE_H_   1

/**
    @file semaphore.h
    @brief POSIX Semaphore Definitions and Routines
*/

/**
    @defgroup sem POSIX Semaphore Definitions and Routines
    @{
*/

#include <errno.h> /* Adding definition of EINVAL, ETIMEDOUT, ..., etc. */
#include <fcntl.h> /* Adding O_CREAT definition. */
#include <stdio.h>
#include <winsock.h>
#include <time.h>

#ifndef PTHREAD_PROCESS_SHARED
#define PTHREAD_PROCESS_PRIVATE	0
#define PTHREAD_PROCESS_SHARED	1
#endif

/* Support POSIX.1b semaphores.  */
#ifndef _POSIX_SEMAPHORES
#define _POSIX_SEMAPHORES       200809L
#endif

#ifndef SEM_VALUE_MAX
#define SEM_VALUE_MAX           INT_MAX
#endif

#ifndef SEM_FAILED
#define SEM_FAILED              NULL
#endif

#define UNUSED(x)				(void)(x)

#ifndef ETIMEDOUT
#define ETIMEDOUT				138 /* This is the value in VC 2010. */
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void  *sem_t;

#ifndef _MODE_T_
typedef unsigned short _mode_t;
#define _MODE_T_  1

#ifndef NO_OLDNAMES
typedef _mode_t mode_t;
#endif
#endif  /* _MODE_T_ */

typedef struct {
	HANDLE handle;
	} arch_sem_t;

/*
#ifndef _TIMESPEC_DEFINED
struct timespec {
	time_t  tv_sec;       // Seconds
	long    tv_nsec;      // Nanoseconds
	};

struct itimerspec {
	struct timespec  it_interval; // Timer period
	struct timespec  it_value;    // Timer expiration
	};
#define _TIMESPEC_DEFINED       1
#endif  // _TIMESPEC_DEFINED */

int sem_init(sem_t *sem, int pshared, unsigned int value);
int sem_wait(sem_t *sem);
int sem_trywait(sem_t *sem);
int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout);
int sem_post(sem_t *sem);
int sem_getvalue(sem_t *sem, int *value);
int sem_destroy(sem_t *sem);
sem_t *sem_open(const char *name, int oflag, mode_t mode, unsigned int value);
int sem_close(sem_t *sem);
int sem_unlink(const char *name);

#ifdef __cplusplus
	}
#endif

/** @} */

#endif /* _SEMAPHORE_H_ */
