//
// Created by songyucheng on 18-11-6.
//

#include "include/ptrace_util.h"

int ptrace_write_data(pid_t pid, const uint8_t *dest, const uint8_t *data, size_t size) {
#if defined(__arm__)
    uint32_t i, j, remain;
#elif defined(__aarch64__)
    uint64_t i, j, remain;
#endif

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
int ptrace_setregs(pid_t pid, struct pt_regs *regs) {
#if defined (__aarch64__)
    int regset = NT_PRSTATUS;
        struct iovec ioVec;

        ioVec.iov_base = regs;
        ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (long*)regset, &ioVec) < 0) {
        perror("ptrace_setregs: Can not get register values");
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_setregs: Can not set register values");
        return -1;
    }

    return 0;
#endif
}

int ptrace_getregs(pid_t pid, struct pt_regs *regs) {

#if defined (__aarch64__)
    int regset = NT_PRSTATUS;
        struct iovec ioVec;

        ioVec.iov_base = regs;
        ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (long*)regset, &ioVec) < 0) {
        perror("ptrace_getregs: Can not get register values");
        printf(" io %llx, %d", ioVec.iov_base, ioVec.iov_len);
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        //LOGD("Get Regs error, pid:%d", pid);
        return -1;
    }
    return 0;
#endif
}

int ptrace_continue(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        printf("pid is %d\n", pid);
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

//使用ptarce 调用远程函数
int ptrace_call(pid_t pid, void *target_func_addr, long *params, long params_length, struct pt_regs *regs) {
    int i = 0;

#if defined(__arm__)
    int num_param_registers = 4;
#elif defined(__aarch64__)
    int num_param_registers = 8;
#endif

    // ARM处理器，函数传递参数，将前四个参数放到r0-r3，剩下的参数压入栈中
    for (i = 0; i < params_length && i < num_param_registers; i++) {
        regs->uregs[i] = params[i];
    }

    if (i < params_length) {
        regs->ARM_sp -= (params_length - i) * sizeof(long);    // 分配栈空间，栈的方向是从高地址到低地址
        if (ptrace_write_data(pid, (void *) regs->ARM_sp, (uint8_t * ) & params[i], (params_length - i) * sizeof(long)) ==
            -1)
            return -1;
    }

#if defined(__arm__)
    regs->ARM_pc = (uint32_t) target_func_addr;
#elif defined(__aarch64__)
    regs->ARM_pc = (uint64_t) target_func_addr;
#endif
    //  printf("pc point is %x\n", target_func_addr);
    if (regs->ARM_pc & 1) {
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;

    if (ptrace_setregs(pid, regs) == -1
        || ptrace_continue(pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;

}

int ptrace_attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        perror("ptrace_attach");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status, WUNTRACED);

    return 0;
}

int ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        perror("ptrace_detach");
        return -1;
    }

    return 0;
}

int ptrace_call_wrapper(pid_t target_pid, const char *func_name, void *func_addr, long *parameters, int param_num,
                      struct pt_regs *regs) {
    printf("Calling [%s] in target process <%d> \n", func_name, target_pid);
    if (ptrace_call(target_pid, func_addr, parameters, param_num, regs) < 0) {
        return -1;
    }

    if (ptrace_getregs(target_pid, regs) < 0) {
        return -1;
    }
    return 0;
}

long ptrace_retval(struct pt_regs *regs) {
    return regs->ARM_r0;
}
