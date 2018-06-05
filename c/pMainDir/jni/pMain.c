//
// Created by songyucheng on 18-6-1.
//
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <stdint.h>
#include <wait.h>
#include <dlfcn.h>
//#include <asm/user.h>

#define CPSR_T_MASK     ( 1u << 5 )
#define FUNCTION_NAME_ADDR_OFFSET       0x100
#define FUNCTION_PARAM_ADDR_OFFSET      0x200

//遍历proc下的文件夹 proc/pid/cmdline中,有对应应用的包名
int getTargetProcessPid(char *pkgName) {
    int id;
    pid_t pid = -1;
    DIR *dir;
    FILE *fp;
    char cmdline[256];
    char filename[32];
    struct dirent *entry;

    if (pkgName == NULL) {
        return -1;
    }

    dir = opendir("/proc");
    if (dir == NULL) {
        return -1;
    }
    while ((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                if (strcmp(cmdline, pkgName) == 0) {
                    pid = id;
                    break;
                }

            }
        }
    }
    closedir(dir);
    return pid;
}

//获取对应lib库的地址,so分了多段加载,这里只读基址
void *getLibsAddr(pid_t pid, char *libName) {
    char mapsPath[32];
    long addr = 0;
    if (pid < 0) {
        sprintf(mapsPath, "/proc/self/maps");
    } else {
        sprintf(mapsPath, "/proc/%d/maps", pid);
    }
    FILE *maps = fopen(mapsPath, "r");
    char strLine[1024];
    //  printf("%s", mapsPath);
    while (!feof(maps)) {
        fgets(strLine, 1024, maps);
        if (strstr(strLine, libName) != NULL) {
//            printf("---------\n");
//            printf("%s\n", strLine);
//            printf("%s\n", strtok(strLine, "-"));
//            printf("---------\n");
            fclose(maps);
            addr = strtoul(strtok(strLine, "-"), NULL, 16);

            if (addr == 0x8000)
                addr = 0;
            break;
        }

    }
    fclose(maps);
    return (void *) addr;
}

void *getRemoteFuncAddr(void *localLibAddr, void *localFuncAddr, void *remoteFuncAddr) {
    return (void *) ((long) remoteFuncAddr + (long) localFuncAddr - (long) localLibAddr);
}


int ptraceWriteData(pid_t pid, const uint8_t *dest, const uint8_t *data, size_t size) {
    uint32_t i, j, remain;
    const uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = data;

    //往内存中写入数据
    for (i = 0; i < j; i++) {
        memcpy(d.chars, laddr, 4);
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);

        dest += 4;
        laddr += 4;
    }

    //多出来的一小段
    if (remain > 0) {
        //d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        for (i = 0; i < remain; i++) {
            d.chars[i] = *laddr++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, d.val);
    }

    return 0;
}

//设置寄存器
int ptraceSetregs(pid_t pid, struct pt_regs *regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_setregs: Can not set register values");
        return -1;
    }

    return 0;
}

int ptraceGetregs(pid_t pid, struct pt_regs *regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        //LOGD("Get Regs error, pid:%d", pid);
        return -1;
    }


    return 0;
}

int ptraceContinue(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        printf("pid is %d\n", pid);
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

//使用ptarce 调用远程函数
int ptraceCall(pid_t pid, void *targetFuncAddr, long *params, long paramsLength, struct pt_regs *regs) {
    int i = 0;
    // ARM处理器，函数传递参数，将前四个参数放到r0-r3，剩下的参数压入栈中
    for (i = 0; i < paramsLength && i < 4; i++) {
        regs->uregs[i] = params[i];
    }

    if (i < paramsLength) {
        regs->ARM_sp -= (paramsLength - i) * sizeof(long);    // 分配栈空间，栈的方向是从高地址到低地址
        if (ptraceWriteData(pid, (void *) regs->ARM_sp, (uint8_t *) &params[i], (paramsLength - i) * sizeof(long)) ==
            -1)
            return -1;
    }

    regs->ARM_pc = (uint32_t) targetFuncAddr;
    //  printf("pc point is %x\n", targetFuncAddr);
    if (regs->ARM_pc & 1) {
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;

    if (ptraceSetregs(pid, regs) == -1
        || ptraceContinue(pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptraceContinue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;

}

int ptraceAttach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        perror("ptrace_attach");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status, WUNTRACED);

    return 0;
}

int ptraceDetach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        perror("ptrace_detach");
        return -1;
    }

    return 0;
}

int ptraceCallWrapper(pid_t target_pid, const char *func_name, void *func_addr, long *parameters, int param_num,
                      struct pt_regs *regs) {
    printf("Calling [%s] in target process <%d> \n", func_name, target_pid);
    if (ptraceCall(target_pid, func_addr, parameters, param_num, regs) < 0) {
        return -1;
    }

    if (ptraceGetregs(target_pid, regs) < 0) {
        return -1;
    }
    return 0;
}

long ptraceRetval(struct pt_regs *regs) {
    return regs->ARM_r0;
}

int main() {
    printf("start inject test\n");
    char *pkgname = "com.example.egguncle.hidekeyinjni";
    pid_t pid = getTargetProcessPid(pkgname);
    pid_t pidMain = getTargetProcessPid(NULL);
    printf("pid is %d\n", pid);
    printf("pmain pid is %d\n", pidMain);
    char *libcName = "/system/lib/libc.so";
    char *linkerPath = "/system/bin/linker";
    void *remoteLibcAddr = getLibsAddr(pid, libcName);
    void *remoteLinkerAddr = getLibsAddr(pid, linkerPath);
    //void *localLibcAddr = getLibsAddr(-1, libcName);
    void *localLibcAddr = getLibsAddr(pidMain, libcName);
    void *localLinkerAddr = getLibsAddr(pidMain, linkerPath);
    void *remoteMmapAddr = getRemoteFuncAddr(localLibcAddr, (void *) mmap, remoteLibcAddr);
    void *remoteDlopen = getRemoteFuncAddr(localLinkerAddr, (void *) dlopen, remoteLinkerAddr);
    void *targetDlsymAddr = getRemoteFuncAddr(localLinkerAddr, (void *) dlsym, remoteLinkerAddr);
    void *targetDlclose = getRemoteFuncAddr(localLibcAddr, (void *) dlclose, remoteLinkerAddr);

    printf("local mmap addr is %x \n", (void *) mmap);
    printf("local dlopen addr is %x \n", (void *) dlopen);
    printf("local libc addr is %x \n", localLibcAddr);
    printf("local link addr is %x\n", localLinkerAddr);
    printf("remote libc addr is %x \n", remoteLibcAddr);
    printf("remote link addr is %x \n", remoteLinkerAddr);


    printf("target mmap addr is %x \n", remoteMmapAddr);
    printf("target dlopen addr is %x \n", remoteDlopen);
    printf("target dlsym address: %x\n", targetDlsymAddr);

    const char *hookSoPath = "/data/local/tmp/libhooker.so";
    //FILE *fd = fopen(hookSoPath, "r");


    ptraceAttach(pid);

    struct pt_regs currentRegs, orgRegs;
// 获取远程进程的寄存器值
    if (ptraceGetregs(pid, &currentRegs) == -1) {
        perror("get reg error");
    }
    memcpy(&orgRegs, &currentRegs, sizeof(currentRegs));

    long parameters[6];
    parameters[0] = 0;  // 设置为NULL表示让系统自动选择分配内存的地址
    parameters[1] = 0x1000; // 映射内存的大小
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // 表示映射内存区域可读可写可执行
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // 建立匿名映射
    parameters[4] = -1; //  若需要映射文件到内存中，则为文件的fd
    parameters[5] = 0; //文件映射偏移量

    if (ptraceCallWrapper(pid, "mmap", remoteMmapAddr, parameters, 6, &currentRegs) < 0) {
        printf("call target mmap error\n");
        return -1;
    }

    uint8_t *mmapBase = (uint8_t *) ptraceRetval(&currentRegs);
    printf("mmap ret is %x\n", mmapBase);

    //将so路径写入目标进程的内存中
    ptraceWriteData(pid, mmapBase, hookSoPath, strlen(hookSoPath) + 1);

    //这里就是稍微调试了一下,看了一下目标进程中对应地址的内容确认上面的东西是不是写进去了
//    printf("\n");
//    uint8_t *i;
//    for (i = mmapBase; i < mmapBase + strlen(hookSoPath) + 1; i++) {
//        printf("addr %x\n", i);
//        printf("%c\n", (unsigned char) ptrace(PTRACE_PEEKTEXT, pid, i, 0));
//    }
//    printf("\n");

    //准备参数
    parameters[0] = (long) mmapBase;
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;
    //通过ptrace调用
    if (ptraceCallWrapper(pid, "dlopen", remoteDlopen, parameters, 2, &currentRegs) < 0) {
        printf("call target dlopen error");
        return -1;
    }
    printf("dlopen ret is %x\n", ptraceRetval(&currentRegs));

    void *targetSoHandle = (void *) ptraceRetval(&currentRegs);

    const char *targetFuncName = "hookEntry";
    ptraceWriteData(pid, mmapBase + FUNCTION_NAME_ADDR_OFFSET, targetFuncName, strlen(targetFuncName) + 1);

    parameters[0] = (long) targetSoHandle;
    parameters[1] = (long) (mmapBase + FUNCTION_NAME_ADDR_OFFSET);

    if (ptraceCallWrapper(pid, "dlsym", targetDlsymAddr, parameters, 2, &currentRegs) < 0) {
        printf("call target dlsym error\n");
        return -1;
    }

    void *hookFuncAddr = (void *) (ptraceRetval(&currentRegs));
    printf("hook func addr is %x\n", ptraceRetval(&currentRegs));

    if (ptraceCallWrapper(pid, targetFuncName, hookFuncAddr, parameters, 0, &currentRegs) < 0) {
        printf("call target %s error", targetFuncName);
        return -1;
    }
    printf("hook entry ret is %x\n", ptraceRetval(&currentRegs));

    parameters[0] = targetSoHandle;

    if (ptraceCallWrapper(pid, "dlclose", targetDlclose, parameters, 1, &currentRegs) < -1) {
        printf("call target dlclose error");
        return -1;
    }


    ptraceSetregs(pid, &orgRegs);
    ptraceDetach(pid);

    return 0;
}
