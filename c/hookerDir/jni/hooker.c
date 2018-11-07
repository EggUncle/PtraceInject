//
// Created by songyucheng on 18-6-2.
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>
#include <dlfcn.h>

#define LOG_TAG "PTRACE_HOOK"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)

char *(*target_function)();

void hook_invoke_handle() {
    LOGD("before target\n");
    char *key = target_function();
    LOGD("key is  :%s\n", key);
    LOGD("after target\n");
}

int hook_entry(char *target_lib_path, char *target_functionName) {

    LOGD("success call hook entry\n");
    LOGD("target lib path is %s\n", target_lib_path);
    void *handle = dlopen(target_lib_path, RTLD_NOW | RTLD_GLOBAL);
    if (handle == NULL) {
        LOGD("open target so error!\n");
        return -1;
    }

    void *symbol = dlsym(handle, target_functionName);
    if (symbol == NULL) {
        LOGD("get sym %s failed!\n", target_functionName);
        return -1;
    }
    target_function = symbol;
    LOGD("target_function %s addr :%lx\n", target_functionName, target_function);
    LOGD("try to invoke target function\n");
    hook_invoke_handle();
    return 0;

}
