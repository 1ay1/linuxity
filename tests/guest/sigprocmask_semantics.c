#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static double now(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e9+t.tv_nsec;}
int main(){
  sigset_t a,b,old; int bad=0;
  sigemptyset(&a); sigaddset(&a,SIGUSR1); sigaddset(&a,SIGUSR2);
  // BLOCK then query
  sigprocmask(SIG_BLOCK,&a,&old);
  sigprocmask(SIG_BLOCK,NULL,&b);
  if(!sigismember(&b,SIGUSR1)||!sigismember(&b,SIGUSR2)){puts("BLOCK failed");bad=1;}
  // UNBLOCK one
  sigset_t u; sigemptyset(&u); sigaddset(&u,SIGUSR1);
  sigprocmask(SIG_UNBLOCK,&u,NULL);
  sigprocmask(SIG_BLOCK,NULL,&b);
  if(sigismember(&b,SIGUSR1)||!sigismember(&b,SIGUSR2)){puts("UNBLOCK failed");bad=1;}
  // SETMASK empty
  sigset_t e; sigemptyset(&e);
  sigprocmask(SIG_SETMASK,&e,&b);
  if(!sigismember(&b,SIGUSR2)){puts("SETMASK oldset wrong");bad=1;}
  sigprocmask(SIG_BLOCK,NULL,&b);
  for(int s=1;s<32;s++) if(sigismember(&b,s)){printf("SETMASK left %d\n",s);bad=1;}
  // KILL/STOP must never be blockable
  sigset_t k; sigfillset(&k); sigprocmask(SIG_SETMASK,&k,NULL);
  sigprocmask(SIG_BLOCK,NULL,&b);
  if(sigismember(&b,SIGKILL)||sigismember(&b,SIGSTOP)){puts("blocked KILL/STOP!");bad=1;}
  sigprocmask(SIG_SETMASK,&e,NULL);
  // and does the HOST agree? a blocked signal must stay pending, then fire
  volatile int got=0; void h(int s){(void)s;}
  signal(SIGUSR1, (void(*)(int))h);
  sigprocmask(SIG_BLOCK,&u,NULL);
  kill(getpid(), SIGUSR1);
  sigset_t p; sigpending(&p);
  if(!sigismember(&p,SIGUSR1)){puts("pending not visible -- HOST DISAGREES");bad=1;}
  sigprocmask(SIG_SETMASK,&e,NULL);      // unblock: handler must run now
  puts(bad? "SIGMASK FAIL":"SIGMASK OK");
  const long N=200000; double t0=now();
  for(long i=0;i<N;i++) sigprocmask(SIG_BLOCK,NULL,&b);
  printf("sigprocmask query: %.1f ns/call\n",(now()-t0)/N);
  t0=now(); for(long i=0;i<N;i++){ sigprocmask(SIG_BLOCK,&u,&old); sigprocmask(SIG_SETMASK,&old,NULL); }
  printf("block+restore pair: %.1f ns/call\n",(now()-t0)/(2*N));
  return bad; }
