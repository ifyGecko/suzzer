#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>

#define REG_RIP 16
#define PAGE_SIZE 4096
#define MAP_SIZE 65535

uint8_t coverage_map[MAP_SIZE] = { 0 };
size_t prev_loc = 0x0;

void coverage_handler(int signum, siginfo_t* info, void* context) {
  ucontext_t* uc = (ucontext_t*)context;

  void* instr_ptr = (void*)uc->uc_mcontext.gregs[REG_RIP];

  mprotect((void*)((size_t)instr_ptr & ~(PAGE_SIZE -1)), PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);

  *(uint16_t*)instr_ptr = 0x9090;

  coverage_map[((size_t)(prev_loc >> 1) ^ (size_t)instr_ptr) % MAP_SIZE - 1]++;

  prev_loc = (size_t)instr_ptr;
}

int main(int argc, char** argv) {
  struct sigaction sa;
  sa.sa_handler = (void (*)(int))coverage_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGILL, &sa, NULL);

  __asm__ volatile(".word 0x0f0f0\n");
  printf("here\n");
  __asm__ volatile(".word 0x0f0f0\n");
  printf("here\n");
  __asm__ volatile(".word 0x0f0f0\n");
  printf("here\n");

  for(int i = 0; i < MAP_SIZE; ++i) {
    if(coverage_map[i] != 0) {
	  printf("index: %d\n", i);
    }
  }

  return 0;
}
