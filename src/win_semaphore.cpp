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


/**
    @file semaphore.c
    @brief Implementation Code of Semaphore Routines
*/

#include "win_semaphore.hpp"

extern "C" {

	static int lc_set_errno(int result) {
		if (result != 0) {
			errno = result;
			return -1;
		}

		return 0;
	}

	/**
		Create an unnamed semaphore.
		@param sem The pointer of the semaphore object.
		@param pshared The pshared argument indicates whether this semaphore
			  is to be shared between the threads (0 or PTHREAD_PROCESS_PRIVATE)
			  of a process, or between processes (PTHREAD_PROCESS_SHARED).
		@param value The value argument specifies the initial value for
			  the semaphore.
		@return If the function succeeds, the return value is 0.
			   If the function fails, the return value is -1,
			   with errno set to indicate the error.
	*/
	int sem_init(sem_t* sem, int pshared, unsigned int value) {
		char buf[24] = { '\0' };
		arch_sem_t* pv;

		if (sem == NULL || value > (unsigned int)SEM_VALUE_MAX) {
			return lc_set_errno(EINVAL);
		}

		if (NULL == (pv = (arch_sem_t*)calloc(1, sizeof(arch_sem_t)))) {
			return lc_set_errno(ENOMEM);
		}

		if (pshared != PTHREAD_PROCESS_PRIVATE) {
			sprintf(buf, "Global\\%p", pv);
		}

		if ((pv->handle = CreateSemaphoreA(NULL, value, SEM_VALUE_MAX, buf)) == NULL) {
			free(pv);
			return lc_set_errno(ENOSPC);
		}

		*sem = pv;
		return 0;
	}

	/**
		Acquire a semaphore.
		@param sem The pointer of the semaphore object.
		@return If the function succeeds, the return value is 0.
			   If the function fails, the return value is -1,
			   with errno set to indicate the error.
	*/
	int sem_wait(sem_t* sem) {
		arch_sem_t* pv = (arch_sem_t*)sem;

		if (sem == NULL || pv == NULL) {
			return lc_set_errno(EINVAL);
		}

		if (WaitForSingleObject(pv->handle, INFINITE) != WAIT_OBJECT_0) {
			return lc_set_errno(EINVAL);
		}

		return 0;
	}

	/**
		Try acquire a semaphore.
		@param sem The pointer of the semaphore object.
		@return If the function succeeds, the return value is 0.
			   If the function fails, the return value is -1,
			   with errno set to indicate the error.
	*/
	int sem_trywait(sem_t* sem) {
		unsigned rc;
		arch_sem_t* pv = (arch_sem_t*)sem;

		if (sem == NULL || pv == NULL) {
			return lc_set_errno(EINVAL);
		}

		if ((rc = WaitForSingleObject(pv->handle, 0)) == WAIT_OBJECT_0) {
			return 0;
		}

		if (rc == WAIT_TIMEOUT) {
			return lc_set_errno(EAGAIN);
		}

		return lc_set_errno(EINVAL);
	}

	/* Time conversion functions */
#define INT64_MAX				0x7fffffffffffffff
#define INT64_C(x)				((x) + (INT64_MAX - INT64_MAX))

/*  Number of 100ns-seconds between the beginning of the Windows epoch
	(Jan. 1, 1601) and the Unix epoch (Jan. 1, 1970)
*/
#define DELTA_EPOCH_IN_100NS    INT64_C(116444736000000000)
#define POW10_3					INT64_C(1000)
#define POW10_4					INT64_C(10000)
#define POW10_6					INT64_C(1000000)

	static __int64 FileTimeToUnixTimeIn100NS(FILETIME* input) {
		return (((__int64)input->dwHighDateTime) << 32 | input->dwLowDateTime) - DELTA_EPOCH_IN_100NS;
	}

	/* Return milli-seconds since the Unix epoch (jan. 1, 1970) UTC */
	static __int64 arch_time_in_ms(void) {
		FILETIME time;
		GetSystemTimeAsFileTime(&time);
		return FileTimeToUnixTimeIn100NS(&time) / POW10_4;
	}

	static  __int64 arch_time_in_ms_from_timespec(const struct timespec* ts) {
		return ts->tv_sec * POW10_3 + ts->tv_nsec / POW10_6;
	}

	static unsigned arch_rel_time_in_ms(const struct timespec* ts) {
		__int64 t1 = arch_time_in_ms_from_timespec(ts);
		__int64 t2 = arch_time_in_ms();
		__int64 t = t1 - t2;

		if (t < 0 || t >= INT64_C(4294967295)) {
			return 0;
		}

		return (unsigned)t;
	}

	/**
		Try acquire a semaphore.
		@param sem The pointer of the semaphore object.
		@param abs_timeout The pointer of the structure that specifies an
			  absolute timeout in seconds and nanoseconds since the Epoch,
			  1970-01-01 00:00:00 +0000 (UTC).
		@return If the function succeeds, the return value is 0.
			   If the function fails, the return value is -1,
			   with errno set to indicate the error.
	*/
	int sem_timedwait(sem_t* sem, const struct timespec* abs_timeout) {
		unsigned rc;
		arch_sem_t* pv = (arch_sem_t*)sem;

		if (sem == NULL || pv == NULL) {
			return lc_set_errno(EINVAL);
		}

		if ((rc = WaitForSingleObject(pv->handle, arch_rel_time_in_ms(abs_timeout))) == WAIT_OBJECT_0) {
			return 0;
		}

		if (rc == WAIT_TIMEOUT) {
			return lc_set_errno(ETIMEDOUT);
		}

		return lc_set_errno(EINVAL);
	}

	/**
		Release a semaphore.
		@param sem The pointer of the semaphore object.
		@return If the function succeeds, the return value is 0.
			   If the function fails, the return value is -1,
			   with errno set to indicate the error.
	*/
	int sem_post(sem_t* sem) {
		arch_sem_t* pv = (arch_sem_t*)sem;

		if (sem == NULL || pv == NULL) {
			return lc_set_errno(EINVAL);
		}

		if (ReleaseSemaphore(pv->handle, 1, NULL) == 0) {
			return lc_set_errno(EINVAL);
		}

		return 0;
	}

	/**
		Get the value of a semaphore.
		@param sem The pointer of the semaphore object.
		@param value The pointer of the current value of the semaphore.
		@return If the function succeeds, the return value is 0.
			   If the function fails, the return value is -1,
			   with errno set to indicate the error.
	*/
	int sem_getvalue(sem_t* sem, int* value) {
		long previous;
		arch_sem_t* pv = (arch_sem_t*)sem;

		switch (WaitForSingleObject(pv->handle, 0)) {
		case WAIT_OBJECT_0:
			if (!ReleaseSemaphore(pv->handle, 1, &previous)) {
				return lc_set_errno(EINVAL);
			}

			*value = previous + 1;
			return 0;

		case WAIT_TIMEOUT:
			*value = 0;
			return 0;

		default:
			return lc_set_errno(EINVAL);
		}
	}

	/**
		Destroy a semaphore.
		@param sem The pointer of the semaphore object.
		@return If the function succeeds, the return value is 0.
			   If the function fails, the return value is -1,
			   with errno set to indicate the error.
	*/
	int sem_destroy(sem_t* sem) {
		arch_sem_t* pv = (arch_sem_t*)sem;

		if (pv == NULL) {
			return lc_set_errno(EINVAL);
		}

		if (CloseHandle(pv->handle) == 0) {
			return lc_set_errno(EINVAL);
		}

		free(pv);
		*sem = NULL;
		return 0;
	}

	/**
		Open a named semaphore.
		@param name The name of the semaphore object.
		@param oflag If O_CREAT is specified in oflag, then the semaphore is
			  created if it does not already exist. If both O_CREAT and O_EXCL
			  are specified in oflag, then an error is returned if a semaphore
			  with the given name already exists.
		@param mode Ignored (The mode argument specifies the permissions to be
			  placed on the new semaphore).
		@param value The value argument specifies the initial value for
			  the semaphore.
		@return On success, returns the address of the new semaphore; On error,
			   returns SEM_FAILED (NULL), with errno set to indicate the error.
	*/
	sem_t* sem_open(const char* name, int oflag, mode_t mode, unsigned int value) {
		int len;
		char buffer[512];
		arch_sem_t* pv;
		UNUSED(mode);

		if (value > (unsigned int)SEM_VALUE_MAX || (len = strlen(name)) > (int)sizeof(buffer) - 8 || len < 1) {
			lc_set_errno(EINVAL);
			return NULL;
		}

		if (NULL == (pv = (arch_sem_t*)calloc(1, sizeof(arch_sem_t)))) {
			lc_set_errno(ENOMEM);
			return NULL;
		}

		memmove(buffer, "Global\\", 7);
		memmove(buffer + 7, name, len);
		buffer[len + 7] = '\0';

		if ((pv->handle = CreateSemaphoreA(NULL, value, SEM_VALUE_MAX, buffer)) == NULL) {
			switch (GetLastError()) {
			case ERROR_ACCESS_DENIED:
				lc_set_errno(EACCES);
				break;

			case ERROR_INVALID_HANDLE:
				lc_set_errno(ENOENT);
				break;

			default:
				lc_set_errno(ENOSPC);
				break;
			}

			free(pv);
			return NULL;
		}

		else {
			if (GetLastError() == ERROR_ALREADY_EXISTS) {
				if ((oflag & O_CREAT) && (oflag & O_EXCL)) {
					CloseHandle(pv->handle);
					free(pv);
					lc_set_errno(EEXIST);
					return NULL;
				}

				return (sem_t*)pv;
			}

			else {
				if (!(oflag & O_CREAT)) {
					free(pv);
					lc_set_errno(ENOENT);
					return NULL;
				}
			}
		}

		return (sem_t*)pv;
	}

	/**
		Close a named semaphore.
		@param sem The pointer of the semaphore object.
		@return If the function succeeds, the return value is 0.
			   If the function fails, the return value is -1,
			   with errno set to indicate the error.
		@remark Same as sem_destroy.
	*/
	int sem_close(sem_t* sem) {
		return sem_destroy(sem);
	}

	/**
		Remove a named semaphore.
		@param name The name of the semaphore object.
		@return If the function succeeds, the return value is 0.
			   If the function fails, the return value is -1,
			   with errno set to indicate the error.
		@remark The semaphore object is destroyed when its last handle has been
			   closed, so this function does nothing.
	*/
	int sem_unlink(const char* name) {
		UNUSED(name);
		return 0;
	}
}
