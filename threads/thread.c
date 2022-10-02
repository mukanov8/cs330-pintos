#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/fixed-point.h"
#include "devices/timer.h"

#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

static struct list all_threads;

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */
static int64_t load_avg;

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority, int64_t recent_cpu, int nice);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

static void update_recent_cpu(void);
static void update_priorities(void);
int thread_get_priority(void);
int thread_get_nice(void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	list_init (&all_threads);
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);
  	load_avg = 0;

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	if (thread_mlfqs) {
		init_thread (initial_thread, "main", 0, INT_TO_FP(0), 0);
	}
	else {
		init_thread (initial_thread, "main", PRI_DEFAULT, INT_TO_FP(0), 0);
	}
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
	if (thread_mlfqs) {
		if (t -> status == THREAD_RUNNING && t != idle_thread)
			t -> recent_cpu = ADD_INT(t -> recent_cpu, 1);
		if (timer_ticks() % TIMER_FREQ == 0) {
			update_load_avg();
			update_recent_cpu();
		}
		if (timer_ticks() % TIME_SLICE == 0) {
			update_priorities();
			intr_yield_on_return();
		}
	}
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	if (thread_mlfqs) {
		init_thread (t, name, thread_get_priority(), thread_current() -> recent_cpu, thread_get_nice());
	}
	else {
		init_thread (t, name, priority, thread_current() -> recent_cpu, thread_get_nice());
	}
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function; // should be pointer to function
	t->tf.R.rsi = (uint64_t) aux; // should be pointer to arguments
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);
	thread_yield();
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	list_push_back (&ready_list, &t->elem);
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	struct thread* t = thread_current();
	if (thread_mlfqs)
		list_remove(&t -> elem_all);
	lock_acquire(&t -> for_exited);
	cond_broadcast(&t -> exited, &t -> for_exited);
	lock_release(&t-> for_exited);
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
		list_push_back (&ready_list, &curr->elem);
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

struct list* thread_get_donators(struct thread* th) {
	ASSERT(th);
	
	enum intr_level old_level = intr_disable();
	ASSERT (intr_get_level () == INTR_OFF);
	if (!th -> donators_initialized) {
		list_init(&(th -> donators));
		th -> donators_initialized = true;
	}
	intr_set_level(old_level);
	return &(th -> donators);
}

/* Returns the `strcut thread* thread`'s priority */
int any_thread_get_priority(struct thread* th, int nested_level) {
	
	if (thread_mlfqs) {
		return th -> priority;
	}

	if (nested_level > 8 || !th) {
		return -1;
	}
	enum intr_level old_level = intr_disable();
	ASSERT (intr_get_level () == INTR_OFF);
	int ret_priority = th -> priority;
	for (struct list_elem *e = list_begin(thread_get_donators(th)); e != list_end(thread_get_donators(th)); e = list_next(e)) {
		struct thread* donator = list_entry(e, struct thread, elem_donate);
		int cur_priority = any_thread_get_priority(donator, nested_level + 1);
		if (ret_priority < cur_priority) {
			ret_priority = cur_priority;
		}
	}
	intr_set_level(old_level);
	return ret_priority;
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	if (thread_mlfqs) {
		return;
	}
	thread_current ()->priority = new_priority;
	if (!intr_context())
		thread_yield();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	if (thread_mlfqs) {
		return thread_current() -> priority;
	}
	int ret_priority = any_thread_get_priority(thread_current(), 0);
	return ret_priority;
}

int adjust_priority (int priority){
	if (priority < PRI_MIN) return PRI_MIN;
	if (priority > PRI_MAX) return PRI_MAX;
	return priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) {
	enum intr_level old_level = intr_disable();
	
	int prev_priority = thread_current() -> priority;
	thread_current() -> nice = nice;
	any_thread_update_priority(thread_current());

	if (prev_priority > thread_current() -> priority) {
		thread_yield();
	}

	intr_set_level(old_level);
}

int any_thread_update_priority(struct thread* t) {
	enum intr_level old_level = intr_disable();
	
	int priority = PRI_MAX - FP_TO_NEAREST_INT((t -> recent_cpu / 4) + (INT_TO_FP(t -> nice) * 2));
	priority = adjust_priority(priority);
	t -> priority = priority;

	intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	return thread_current() -> nice;
}

void update_load_avg() {
	enum intr_level old_level = intr_disable();

	int ready_threads;
	if (timer_ticks() < 1301 && timer_ticks() > 999) {
		ready_threads = 0;
	}
	ready_threads = (int)list_size(&ready_list);
	struct thread* t = thread_current();
	if (t != idle_thread && t != NULL)
		ready_threads++; 

	load_avg = (load_avg * 59) / 60 + INT_TO_FP(ready_threads) / 60;

	intr_set_level(old_level);
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */
  return FP_TO_NEAREST_INT(load_avg * 100);
}

int any_thread_get_recent_cpu(struct thread* t) {
	enum intr_level old_level = intr_disable();
	ASSERT (intr_get_level () == INTR_OFF);
	int ret_recent_cpu = FP_TO_INT(t -> recent_cpu * 100);
	intr_set_level(old_level);
	return ret_recent_cpu;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	int ret_recent_cpu = any_thread_get_recent_cpu(thread_current());
	return ret_recent_cpu;
}

static void update_recent_cpu(void) {
	enum intr_level old_level = intr_disable();
	for (struct list_elem* e = list_begin(&all_threads); e != list_end(&all_threads); e = list_next(e)) {
		struct thread* t = list_entry(e, struct thread, elem_all);
		int64_t coef = 
		DIV_FP(
			load_avg * 2,
			ADD_INT(load_avg * 2, 1)
		);

		t -> recent_cpu = ADD_INT(
			MUL_FP(coef, t -> recent_cpu),
			t -> nice
		);
	}
	intr_set_level(old_level);
}

static void update_priorities(void) {
	enum intr_level old_level = intr_disable();
	for (struct list_elem* e = list_begin(&all_threads); e != list_end(&all_threads); e = list_next(e)) {
		struct thread* t = list_entry(e, struct thread, elem_all);
		any_thread_update_priority(t);
	}
	intr_set_level(old_level);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. ex: lab2: initd starts executing here */
	thread_current() -> exit_status = 0;
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority, int64_t recent_cpu, int nice) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *); //kernel stack initialization
	t->priority = priority;
	t->magic = THREAD_MAGIC;
	t -> donators_initialized = false;
	t -> donated_for = NULL;
	t -> recent_cpu = recent_cpu;
	t -> nice = nice;

	#ifdef USERPROG
	/* Owned by userprog/process.c. */
	t -> pml4 = NULL;
	#endif
	#ifdef VM
		/* Table for whole virtual memory owned by thread. */
	t -> spt.initialized = false;
	t -> actual_rsp = 0x0;
	t -> stack_bottom = NULL;
	#endif

	#ifdef EFILESYS
	t -> current_dir = NULL;
	#endif

	//prj 2
	cond_init(&t -> exited);
	lock_init(&t -> for_exited);
	list_init(&t -> child_threads);
	sema_init(&t -> child_creation, 0);
	t -> exit_status = 1234567;
	t -> parent = NULL;
	t -> is_user_process = false;
	list_init(&t -> fds);
	t -> exec_file = NULL;
	if (thread_mlfqs && name != "idle")
		list_push_back(&all_threads, &(t -> elem_all));
}

struct thread* thread_priority_list_max(struct list* lst) {
	ASSERT(lst);
	struct thread* t = list_entry(
		list_max(lst, thread_priority_less, NULL),
		struct thread, elem
	);
	return t;
}

bool thread_priority_less(const struct list_elem *a, const struct list_elem *b, void* aux) {
	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(a && b);
	struct thread* ta = list_entry(a, struct thread, elem);
	struct thread* tb = list_entry(b, struct thread, elem);
	return any_thread_get_priority(ta, 0) < any_thread_get_priority(tb, 0);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else {
		ASSERT(intr_get_level() == INTR_OFF);
		struct thread* t = thread_priority_list_max(&ready_list);
		ASSERT(t);
		list_remove(&(t -> elem));
		return t;
	}
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	for (struct list_elem *e = list_begin(&destruction_req); e != list_end(&destruction_req);) {
		struct thread *victim = list_entry (e, struct thread, elem);
		if (victim -> parent == NULL) {
			e = list_remove(e);
			palloc_free_page(victim);
		}
		else {
			e = list_next(e);
		}
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}
