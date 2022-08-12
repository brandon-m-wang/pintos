#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"

struct lock_pair {
  struct lock* second;
  struct lock* first;
};

static void a_thread_func(void* locks_) {
  struct lock_pair* locks = locks_;
  struct lock* lock_a = locks->first;
  struct lock* lock_b = locks->second;

  lock_acquire(lock_b);
  msg("Thread a acquired lock b.");

  lock_acquire(lock_a);
  msg("Thread a acquired lock a.");
  lock_release(lock_a);
  msg("Thread a finished.");
  lock_release(lock_b);
}

static void b_thread_func(void* locks_) {
  struct lock_pair* locks = locks_;
  struct lock* lock_a = locks->first;
  struct lock* lock_c = locks->second;

  lock_acquire(lock_c);
  msg("Thread b acquired lock c.");

  lock_acquire(lock_a);
  msg("Thread b acquired lock a.");
  lock_release(lock_a);
  msg("Thread b finished.");
  lock_release(lock_c);
}

static void c_thread_func(void* lock_) {
  struct lock* lock = lock_;

  lock_acquire(lock);
  msg("Thread c acquired lock b.");
  lock_release(lock);
  msg("Thread c finished.");
}

static void d_thread_func(void* lock_) {
  struct lock* lock = lock_;

  lock_acquire(lock);
  msg("Thread d acquired lock c.");
  lock_release(lock);
  msg("Thread d finished.");
}

void test_priority_donate_tree(void) {
  struct lock_pair first_lock_pairs;
  struct lock_pair second_lock_pairs;
  struct lock a, b, c;

  /* This test does not work with the MLFQS. */
  ASSERT(active_sched_policy == SCHED_PRIO);

  /* Make sure our priority is the default. */
  ASSERT(thread_get_priority() == PRI_DEFAULT);

  lock_init(&a);
  lock_init(&b);
  lock_init(&c);

  lock_acquire(&a);

  second_lock_pairs.first = &a;
  second_lock_pairs.second= &c;
  thread_create("b", PRI_DEFAULT + 3, b_thread_func, &second_lock_pairs);
  msg("Main thread should have priority %d.  Actual priority: %d.", PRI_DEFAULT + 3,
      thread_get_priority());

  first_lock_pairs.first = &a;
  first_lock_pairs.second= &b;
  thread_create("a", PRI_DEFAULT + 3, a_thread_func, &first_lock_pairs);
  msg("Main thread should have priority %d.  Actual priority: %d.", PRI_DEFAULT + 3,
      thread_get_priority());

  thread_create("c", PRI_DEFAULT + 6, c_thread_func, &b);
  msg("Main thread should have priority %d.  Actual priority: %d.", PRI_DEFAULT + 6,
      thread_get_priority());

  thread_create("d", PRI_DEFAULT + 9, d_thread_func, &c);
  msg("Main thread should have priority %d.  Actual priority: %d.", PRI_DEFAULT + 9,
      thread_get_priority());

  lock_release(&a);
  msg("Main thread should have priority %d.  Actual priority: %d.", PRI_DEFAULT,
      thread_get_priority());

  msg("Threads b, d, a, c should have just finished, in that order.");
}