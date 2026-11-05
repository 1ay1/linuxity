#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
static double now(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e9+t.tv_nsec;}
#define B(name, expr) do{ double a=now(); for(long i=0;i<N;i++){expr;} double b=now(); \
  printf("%-22s %7.1f ns/call\n", name, (b-a)/N);}while(0)
int main(){ const long N=300000; volatile long s=0;
  B("getpid",      s+=syscall(SYS_getpid));
  B("gettid",      s+=syscall(SYS_gettid));
  B("getuid",      s+=syscall(SYS_getuid));
  B("sched_yield", s+=syscall(SYS_sched_yield));
  B("clock_gettime(vDSO)", {struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); s+=t.tv_nsec;});
  B("geteuid(libc cached)", s+=geteuid());
  B("close(-1) [traps]", s+=syscall(SYS_close,-1));
  return (int)s&0; }
