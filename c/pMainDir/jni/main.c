//
// Created by songyucheng on 18-6-1.
//
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
#include "include/main_util.h"
#include "include/ptrace_util.h"

#if defined(__arm__)
const char *LIBC_NAME = "/system/lib/libc.so";
const char *LINKER_PATH = "/system/bin/linker";
#elif defined(__aarch64__)
const char *LIBC_NAME = "/system/lib64/libc.so";
const char *LINKER_PATH = "/system/bin/linker64";
#endif

int main(int argc, char **argv) {
    //需要三个参数 进程包名 目标方法名称 libhook路径
    char *pkgname = "com.example.egguncle.hidekeyinjni";
    char *target_func_name = "hookEntry";
    char *hook_so_path = "/data/local/tmp/libhooker.so";

    if (argc != 4) {
        printf("args error\n");
        printf("process_name targetmethod_name libhook_path\n");
    } else {
        pkgname = argv[1];
        target_func_name = argv[2];
        hook_so_path = argv[3];
        printf("pkgname is %s\n", pkgname);
        printf("target_func_name is %s\n", target_func_name);
        printf("hook_so_path is %s\n", hook_so_path);
    }


    printf("start inject test\n");

    pid_t pid = get_target_process_pid(pkgname);
    pid_t pid_main = get_target_process_pid(NULL);
    printf("pid is %d\n", pid);
    printf("pmain pid is %d\n", pid_main);
    void *remote_libc_addr = get_libs_addr(pid, LIBC_NAME);
    void *remote_linker_addr = get_libs_addr(pid, LINKER_PATH);
    //void *local_libc_addr = get_libs_addr(-1, LIBC_NAME);
    void *local_libc_addr = get_libs_addr(pid_main, LIBC_NAME);
    void *local_linker_addr = get_libs_addr(pid_main, LINKER_PATH);
    void *remote_mmap_addr = get_remote_func_addr(local_libc_addr, (void *) mmap, remote_libc_addr);
    void *remote_dlopen = get_remote_func_addr(local_linker_addr, (void *) dlopen, remote_linker_addr);
    void *remote_dlsym_addr = get_remote_func_addr(local_linker_addr, (void *) dlsym, remote_linker_addr);
    void *remote_dlclose = get_remote_func_addr(local_linker_addr, (void *) dlclose, remote_linker_addr);

    printf("local libc addr is %lx \n", local_libc_addr);
    printf("local link addr is %lx\n", local_linker_addr);
    printf("remote libc addr is %lx \n", remote_libc_addr);
    printf("remote link addr is %lx \n", remote_linker_addr);

    printf("local mmap addr is %lx \n", (void *) mmap);
    printf("local dlopen addr is %lx \n", (void *) dlopen);
    printf("local dlsym address: %lx\n", (void *) dlsym);
    printf("local dlclose address: %lx\n", (void *) dlclose);

    printf("remote mmap addr is %lx \n", remote_mmap_addr);
    printf("remote dlopen addr is %lx \n", remote_dlopen);
    printf("remote dlsym address: %lx\n", remote_dlsym_addr);
    printf("remote dlclose address: %lx\n", remote_dlclose);


    ptrace_attach(pid);

    struct pt_regs current_regs, org_regs;
// 获取远程进程的寄存器值
    if (ptrace_getregs(pid, &current_regs) == -1) {
        perror("get reg error");
    }
    memcpy(&org_regs, &current_regs, sizeof(current_regs));

    long parameters[6];
    parameters[0] = 0;  // 设置为NULL表示让系统自动选择分配内存的地址
    parameters[1] = 0x1000; // 映射内存的大小
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // 表示映射内存区域可读可写可执行
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // 建立匿名映射
    parameters[4] = -1; //  若需要映射文件到内存中，则为文件的fd
    parameters[5] = 0; //文件映射偏移量
    if (ptrace_call_wrapper(pid, "mmap", remote_mmap_addr, parameters, 6, &current_regs) < 0) {
        printf("call target mmap error\n");
        return -1;
    }

    void *mmap_base = (void *) ptrace_retval(&current_regs);
    printf("mmap ret is %lx\n", mmap_base);

    //将so路径写入目标进程的内存中
    ptrace_write_data(pid, mmap_base, hook_so_path, strlen(hook_so_path) + 1);

    //这里就是稍微调试了一下,看了一下目标进程中对应地址的内容确认上面的东西是不是写进去了
//    printf("\n");
//    int *i;
//    for (i = mmap_base; i < mmap_base + strlen(hook_so_path) + 1; i++) {
//        //printf("addr %x\n", i);
//        printf("---%c\n", (unsigned char) ptrace(PTRACE_PEEKTEXT, pid, i, 0));
//    }
//    printf("\n");

    //准备参数
    parameters[0] = (long) mmap_base;
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;
    //通过ptrace调用
    if (ptrace_call_wrapper(pid, "dlopen", remote_dlopen, parameters, 2, &current_regs) < 0) {
        printf("call target dlopen error");
        return -1;
    }
    printf("dlopen ret is %lx\n", ptrace_retval(&current_regs));

    void *target_so_handle = (void *) ptrace_retval(&current_regs);

    // const char *target_func_name = "hookEntry";
    ptrace_write_data(pid, mmap_base + FUNCTION_NAME_ADDR_OFFSET, target_func_name, strlen(target_func_name) + 1);

    parameters[0] = (long) target_so_handle;
    parameters[1] = (long) (mmap_base + FUNCTION_NAME_ADDR_OFFSET);

    if (ptrace_call_wrapper(pid, "dlsym", remote_dlsym_addr, parameters, 2, &current_regs) < 0) {
        printf("call target dlsym error\n");
        return -1;
    }

    void *hook_func_addr = (void *) (ptrace_retval(&current_regs));
    printf("hook func addr is %lx\n", ptrace_retval(&current_regs));

    char *target_lib_path = get_libs_path(pid, pkgname);
    printf("target lib path is %s\n", target_lib_path);

    //将目标so路径写入目标进程的内存中
    mmap_base += FUNCTION_PARAM_ADDR_OFFSET;
    ptrace_write_data(pid, mmap_base, target_lib_path, strlen(target_lib_path) + 1);
    parameters[0] = mmap_base;
    char *target_function_name = "getkey";
    mmap_base += FUNCTION_PARAM_ADDR_OFFSET;
    ptrace_write_data(pid, mmap_base, target_function_name, strlen(target_function_name) + 1);
    parameters[1] = mmap_base;

    //printf("%lx ,%lx\n",parameters[0],parameters[1]);

    if (ptrace_call_wrapper(pid, target_func_name, hook_func_addr, parameters, 2, &current_regs) < 0) {
        printf("call target %s error", target_func_name);
        return -1;
    }
    printf("hook entry ret is %lx\n", ptrace_retval(&current_regs));

    parameters[0] = target_so_handle;

    if (ptrace_call_wrapper(pid, "dlclose", remote_dlclose, parameters, 1, &current_regs) < -1) {
        printf("call target dlclose error");
        return -1;
    }

    ptrace_setregs(pid, &org_regs);
    ptrace_detach(pid);
    printf("--- hook end ---\n");

    return 0;
}
