/*
	 Copyright (C) 2017 xiewenzhou(Joe)


	 This program is distributed in the hope that it will be useful,
	 but WITHOUT ANY WARRANTY; without even the implied warranty of
	 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	 GNU General Public License for more details.

*/

#include <unistd.h>  
#include <errno.h>  
#include <stdint.h>  
#include <fcntl.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <string.h>  
#include <semaphore.h>  
#include <pthread.h>  
#include <sys/shm.h>  
#include <sys/mman.h>  
#include <sys/stat.h>  
#include <sys/ipc.h>  
#include <sys/sem.h>  
#include <sys/types.h>  
#include <sys/syscall.h>

#include "util.h"

static const key_t ctrl_shm_key_base = 0xffee;
static const char *ctrl_shm_name = "joe";

static void ctrl_init(ctrl_t *c) {
	pthread_mutexattr_t ma;
	pthread_mutexattr_init(&ma);
	pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED);
	pthread_mutexattr_setrobust(&ma, PTHREAD_MUTEX_ROBUST);
	
	pthread_mutex_init(&c->lock, &ma);
}

/* create a share memory and a struct ctrl return a struct
 * ctrl point who point theshare memory.
 * */
ctrl_t *ctrl_get() {
	int size = sizeof(ctrl_t);

	int fd = shm_open(ctrl_shm_name, O_RDWR, 0777);
	if (fd < 0) {
		info("creating ctrl.shm");

		char path[256];
		sprintf(path, "%s.%d", ctrl_shm_name, getpid());
		fd = shm_open(path, O_CREAT|O_RDWR, 0777);
		info("creating ctrl.shm: shm_open %s: %d", path, fd);
		if (fd < 0) {
			return NULL;
		}

		int r = ftruncate(fd, size);
		info("create shm.ctrl: ftruncate: %d", r);
		if (r < 0) {
			return NULL;
		}

		void *addr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
		if (addr == NULL) {
			warn("create shm.ctrl: mmap failed");
			return NULL;
		}

		memset(addr, 0, size);
		ctrl_init((ctrl_t *)addr);
		munmap(addr, size);

		char path_old[256];
		char path_new[256];
		sprintf(path_old, "/dev/shm/%s", path);
		sprintf(path_new, "/dev/shm/%s", ctrl_shm_name);

		r = link(path_old, path_new);
		info("create shm.ctrl: link(%s, %s): %d", path_old, path_new, r);

		unlink(path_old);

		fd = shm_open(ctrl_shm_name, O_RDWR, 0777);
		if (fd < 0) {
			warn("reopen shm.ctrl failed");
			return NULL;
		}
	}

	ctrl_t *c = (ctrl_t *)mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
	if (c == NULL) {
		warn("mmap shm.ctrl failed");
		return NULL;
	}

	int r = pthread_mutex_lock(&c->lock);
	if (r == EOWNERDEAD) {
		pthread_mutex_consistent(&c->lock);
		log("mutex_lock: mark consistent");
	}

	return c;
}

/* release the mutex lock and release the map memory.
 */
void ctrl_put(ctrl_t *c) {
	pthread_mutex_unlock(&c->lock);
	munmap(c, sizeof(ctrl_t));
}

/*
static void dump_procs(chan_t *ch) {
	int i;
	for (i = 0; i < PROCS_NR; i++) {
	}
}
*/

/*
static void ctrl_dump(ctrl_t *c) {
	int i;

	for (i = 0; i < CHANS_NR; i++) {
		chan_t *ch = &c->chans[i];
		fprintf(stderr, "chan #%d\n", i);
		fprintf(stderr, "  proc_nr %d\n", ch->proc_nr);
		if (ch->proc_nr)
			dump_procs(ch);
		fprintf(stderr, "  post_nr %d\n", ch->post_nr);
	}
}
*/

/* get a share memory of len length.
 */
int ishm_new(int len) {
	for (;;) {
		int shm = shmget(ctrl_shm_key_base + (rand()%SHMKEY_MAX), len, 0777|IPC_CREAT|IPC_EXCL);
		if (shm > 0)
			return shm;
	}
}

/* new a share memory and fill in it content of buf and meta data.
 */
int ishm_new_from_buf(void *buf, int buf_len, void *meta, int meta_len) {
	int k = ishm_new(buf_len + meta_len);
	void *p = shmat(k, NULL, 0);

	if (meta_len) {
		memcpy(p, meta, meta_len);
		memcpy(p + meta_len, buf, buf_len);
	} else {
		memcpy(p, buf, buf_len);
	}

	shmdt(p);
	return k;
}

/* remove a share memory.
 */
void ishm_del(int i) {
	semctl(i, 0, IPC_RMID, 0);
}

/* get the length of share memory
 */
int ishm_len(int i) {
	struct shmid_ds ds;
	shmctl(i, IPC_STAT, &ds);
	return ds.shm_segsz;
}

static const char *isem_fmt = "joe.%d";

/* delete the semophare.
 */
void isem_del(int k) {
	char name[128];
	sprintf(name, isem_fmt, k);

	log("%s", name);
	sem_unlink(name);
}

/* new a semophare.
 */
int isem_new(int n) {
	for (;;) {
		int k = ctrl_shm_key_base + (rand()%SHMKEY_MAX);

		char name[128];
		sprintf(name, isem_fmt, k);
		sem_t *s = sem_open(name, O_CREAT|O_EXCL, 0777, n);
		if (s != SEM_FAILED) {
			sem_close(s);
			return k;
		} else {
			log("sem_open('%s', %d) failed: %s", name, n, strerror(errno));
		}
	}
}

/* semophore count add 1, notify the arbitrary thread who is wait.
 */
void isem_up(int k) {
	char name[128];
	sprintf(name, isem_fmt, k);

	sem_t *s = sem_open(name, 0);
	if (s == SEM_FAILED)
		return;
	sem_post(s);
}

/* get the semophare's value
 */
int isem_val(int k, int *v) {
	char name[128];
	sprintf(name, isem_fmt, k);

	sem_t *s = sem_open(name, 0);
	if (s == SEM_FAILED) {
		warn("open %s failed", name);
		return -ENOENT;
	}

	return sem_getvalue(s, v);
}

/* pass a fixed time, semophare - 1.
 */
void isem_down_timeout(int k, int timeout) {
	char name[128];
	sprintf(name, isem_fmt, k);

	sem_t *s = sem_open(name, 0);
	if (s == SEM_FAILED) {
		warn("open %s failed", name);
		return;
	}

	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += timeout/1000;
	ts.tv_nsec += (timeout%1000)*1000000;
	if (ts.tv_nsec > 1000000000) {
		ts.tv_nsec -= 1000000000;
		ts.tv_sec++;
	}

	log("wait start: timeout=%d", timeout);

	int r;
	if (timeout == 0) {
		r = sem_wait(s);//success:return 0, fail:return -1.
	} else {
                //wait a fixed time
		r = sem_timedwait(s, &ts);
	}
	if (r)
		log("wait end: %s", strerror(errno));
	else
		log("wait end: ok");
}

/* get the thread's process id, gettid is a system call, but need you realize.
 */
int gettid() {
	return syscall(SYS_gettid);
}

/* if the file:/proc/$pid/task/$tid is exists and can access.
 */
static int pid_tid_exists(int pid, int tid) {
	char buf[128];
	sprintf(buf, "/proc/%d/task/%d", pid, tid);
	return !access(buf, F_OK);
}

/* find a no exists file:/proc/$pid/task/$tid,
 * reset it's memory space and return the address
 */
static proc_t *chan_free_procs(chan_t *ch) {
	int i;

	for (i = 0; i < PROCS_NR; i++) {
		proc_t *p = &ch->procs[i];

		if (pid_tid_exists(p->pid, p->tid))
			continue;

		if (p->sem)
			isem_del(p->sem);

		memset(p, 0, sizeof(proc_t));
		ch->proc_nr--;

		return p;
	}

	return NULL;
}

/* find the proc_t in chan_t struct,if find,return the address;
 * or new a proc_t in chan_t's free space;
 * if the chan_t space has no free space, return null.
 */
static proc_t *chan_get_or_new_proc(chan_t *ch, int pid, int tid) {
	int i;
	proc_t *p;

	for (i = 0; i < PROCS_NR; i++) {
		p = &ch->procs[i];
		if (p->pid == pid && p->tid == tid)
			return p;
	}

	p = chan_free_procs(ch);
	if (p == NULL)
		return NULL;

	p->post_i = ch->post_e;
	p->pid = pid;
	p->tid = tid;
	ch->proc_nr++;

	return p;
}

/* define two function pointer
 */
typedef int (*check_post_cb_t)(post_t *, void *);
typedef int (*check_proc_cb_t)(chan_t *, proc_t *, void *);

/* from the struct chan_t get the struct post_t
 */
static post_t *proc_get_post(chan_t *ch, proc_t *p, check_post_cb_t cb, void *cb_p) {
	log("post_i=%d", p->post_i);

	if (p->post_i < ch->post_s)
		p->post_i = ch->post_s;
	while (p->post_i < ch->post_e) {
		post_t *po = &ch->posts[p->post_i % POSTS_NR];
		p->post_i++;

		if (cb(po, cb_p) == 0)
			return po;
	}
	return NULL;
}

/* push the semaphore out of the queue 
 */
static int wait_post(
	int chan_id, int timeout, void **out, int *out_len,
	check_proc_cb_t check_proc, check_post_cb_t check_post, void *cb_p
) {
	log("chan=%d pid=%d tid=%d timeout=%d", chan_id, getpid(), gettid(), timeout);

	for (;;) {
		ctrl_t *c = ctrl_get();
		if (c == NULL)
			return -EINVAL;

		chan_t *ch = &c->chans[chan_id];

		proc_t *p = chan_get_or_new_proc(ch, getpid(), gettid());
		if (p == NULL) {
			ctrl_put(c);
			return -ENOMEM;
		}

		if (check_proc) {
			int r = check_proc(ch, p, cb_p);
			if (r) {
				ctrl_put(c);
				return r;
			}
		}

		post_t *po = proc_get_post(ch, p, check_post, cb_p);
		if (po == NULL) {
			int sem = isem_new(0);

			p->stat = WAITING;

			if (p->sem)
				isem_del(p->sem);
			p->sem = sem;
			ctrl_put(c);

			// waiting 
			log("waiting sem=%d timeout=%d", sem, timeout);
			isem_down_timeout(sem, timeout);
			continue;
		}

		p->stat = NONE;
		if (p->buf) 
			shmdt(p->buf);
		p->buf = shmat(po->shm, NULL, 0);
		*out = p->buf + sizeof(post_t);
		*out_len = ishm_len(po->shm) - sizeof(post_t);

		ctrl_put(c);
		return 0;
	}
}

/* the semaphore in the queue post
 */
static int enque_post(int chan_id, int type, uint64_t ack_id, void *in, int in_len, post_t *cb) {
	ctrl_t *c = ctrl_get();
	if (c == NULL)
		return -ENOENT;

	chan_t *ch = &c->chans[chan_id];
	post_t *po;

	if (ch->post_nr == POSTS_NR) {
		po = &ch->posts[ch->post_s % POSTS_NR];
		ishm_del(po->shm);
		po->shm = 0;
		ch->post_s++;
		ch->post_nr--;
	}

	po = &ch->posts[ch->post_e % POSTS_NR];
	po->type = type;
	po->id = ch->post_e;
	po->ack_id = ack_id;
	po->chan_id = chan_id;
	po->shm = ishm_new_from_buf(in, in_len, po, sizeof(post_t));
	if (cb)
		*cb = *po;
	ch->post_nr++;
	ch->post_e++;
	log("nr=%d que=%d,%d len=%d", ch->post_nr, ch->post_s, ch->post_e, in_len);

	int i;
	for (i = 0; i < PROCS_NR; i++) {
		proc_t *p = &ch->procs[i];
		if (p->stat == WAITING) {
			isem_up(p->sem);
		}
	}

	ctrl_put(c);
	return 0;
}

/* check the post's type is POST or PUSH
 */
static int post_is_normal(post_t *p, void *_) {
	return !(p->type == POST || p->type == PUSH);
}

/*
 * chan_id: channal id
 *     out: the buffer 
 * out_len: buffer's length
 * timeout: time out
 *
 * the function is a get a semaphore buffer.the data get in the buffer out.
 **/
int sem_event_get(int chan_id, void **out, int *out_len, int timeout) {
	return wait_post(chan_id, timeout, out, out_len, NULL, post_is_normal, NULL);
}

/* post event to the channel of chan_id.
 */
int sem_event_post(int chan_id, void *in, int in_len) {
	return enque_post(chan_id, POST, 0, in, in_len, NULL);
}

static int push_check_proc(chan_t *ch, proc_t *p, void *_) {
	post_t *po = (post_t *)_;
	if (po->id < ch->post_s)
		return -ENOENT;
	return 0;
}

static int push_check_post(post_t *po, void *_) {
	post_t *po_push = (post_t *)_;
	return !(po->type == ACK && po->ack_id == po_push->id);
}

/* push a event to the channel and wait for it's answer.
 */
int sem_event_push(int chan_id, void *in, int in_len, void **out, int *out_len, int timeout) {
	log("chan=%d in_len=%d", chan_id, in_len);
	post_t po;
	enque_post(chan_id, PUSH, 0, in, in_len, &po);
	return wait_post(chan_id, timeout, out, out_len, push_check_proc, push_check_post, &po);
}

/* answer the event.
 */
int sem_event_ack(void *in, void *out, int out_len) {
	post_t *po = (post_t *)(in - sizeof(post_t));
	if (po->type != PUSH)
		return -EINVAL;
	return enque_post(po->chan_id, ACK, po->id, out, out_len, NULL);
}

