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

const char *targetLibPath = "/data/data/com.example.egguncle.hidekeyinjni/lib/libnative-lib.so";

char* (*getKey)();

int hookEntry() {

    LOGD("success call hook entry\n");
    void *handle = dlopen(targetLibPath, RTLD_NOW | RTLD_GLOBAL);
    if (handle == NULL) {
        LOGD("open target so error!\n");
        return -1;
    }

    void *symbol = dlsym(handle, "getkey");
    if (symbol == NULL) {
        LOGD("get getkey error!\n");
        return -1;
    }
    getKey = symbol;
    LOGD("getkey addr :%x\n", getKey);
    char *key = getKey();
    LOGD("key is  :%s\n", key);
    return 0;

}
