//
// Created by songyucheng on 18-11-6.
//

#ifndef PTRACEINJECT_PTRACE_UTIL_H
#define PTRACEINJECT_PTRACE_UTIL_H

#include <stdio.h>
#include <stdlib.h>
//#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <android/log.h>
#include <sys/uio.h>

#define CPSR_T_MASK     ( 1u << 5 )
#define FUNCTION_NAME_ADDR_OFFSET       0x100
#define FUNCTION_PARAM_ADDR_OFFSET      0x200

#if defined(__aarch64__)
#define pt_regs         user_pt_regs
#define uregs	regs
#define ARM_pc	pc
#define ARM_sp	sp
#define ARM_cpsr	pstate
#define ARM_lr		regs[30]
#define ARM_r0		regs[0]
#define PTRACE_GETREGS PTRACE_GETREGSET
#define PTRACE_SETREGS PTRACE_SETREGSET
#endif


int ptrace_write_data(pid_t pid, const uint8_t *dest, const uint8_t *data, size_t size);
int ptrace_setregs(pid_t pid, struct pt_regs *regs);
int ptrace_getregs(pid_t pid, struct pt_regs *regs);
int ptrace_continue(pid_t pid);
int ptrace_call(pid_t pid, void *targetFuncAddr, long *params, long paramsLength, struct pt_regs *regs);
int ptrace_attach(pid_t pid);
int ptrace_detach(pid_t pid);
int ptrace_call_wrapper(pid_t target_pid, const char *func_name, void *func_addr, long *parameters, int param_num,
                      struct pt_regs *regs);
long ptrace_retval(struct pt_regs *regs);

#endif //PTRACEINJECT_PTRACE_UTIL_H
