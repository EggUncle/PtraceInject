//
// Created by songyucheng on 18-11-6.
//

#ifndef PTRACEINJECT_MAIN_UTIL_H
#define PTRACEINJECT_MAIN_UTIL_H

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


int get_target_process_pid(char *pkg_name);
void *get_libs_addr(pid_t pid, char *lib_name);
char *get_libs_path(pid_t pid, char *lib_name);
void *get_remote_func_addr(void *local_lib_addr, void *local_func_addr, void *remote_func_addr);
char *strim(char *str);

#endif //PTRACEINJECT_MAIN_UTIL_H
