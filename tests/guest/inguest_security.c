#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
static sigjmp_buf jb;
static void h(int s){ (void)s; siglongjmp(jb,1); }
static int probe(uint64_t addr, const char* what){
  struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_handler=h; sigaction(SIGSEGV,&sa,0); sigaction(SIGBUS,&sa,0);
  if(sigsetjmp(jb,1)==0){ volatile uint64_t v = *(volatile uint64_t*)addr;
    printf("  READ %-28s at %#llx -> %#llx  *** LEAK ***\n", what, (unsigned long long)addr, (unsigned long long)v); return 1; }
  printf("  read %-28s at %#llx -> SIGSEGV (good)\n", what, (unsigned long long)addr); return 0;
}
static int wprobe(uint64_t addr, const char* what){
  struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_handler=h; sigaction(SIGSEGV,&sa,0); sigaction(SIGBUS,&sa,0);
  if(sigsetjmp(jb,1)==0){ *(volatile uint64_t*)addr = 0xdeadbeef;
    printf("  WRITE %-27s at %#llx -> OK  *** FORGEABLE ***\n", what, (unsigned long long)addr); return 1; }
  printf("  write %-27s at %#llx -> SIGSEGV (good)\n", what, (unsigned long long)addr); return 0;
}
int main(){
  int bad=0;
  puts("probing the hypervisor-private area from EL0:");
  bad+=probe(0x0,     "vectors / EL1 handler");
  bad+=probe(0x1000,  "L1 page table");
  bad+=probe(0x2000,  "L2 page table");
  bad+=probe(0x3000,  "in-guest answer table");
  bad+=wprobe(0x3000, "in-guest answer table");
  bad+=wprobe(0x400,  "EL1 handler code");
  // Can a guest fake an entry for a syscall we do NOT publish?
  long r = syscall(SYS_close, -1);
  printf("  close(-1) still traps and fails: %ld (%s)\n", r, r<0?"good":"BAD");
  printf("%s\n", bad? "SECURITY FAIL":"SECURITY OK");
  return bad; }
