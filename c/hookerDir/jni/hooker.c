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
#include <unistd.h>

#define LOG_TAG "PTRACE_HOOK"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)

char *(*target_function)();

char *strim(char *str) {
    char *end, *sp, *ep;
    int len;
    sp = str;
    end = str + strlen(str) - 1;
    ep = end;

    while (sp <= end && isspace(*sp))// *sp == ' '也可以
        sp++;
    while (ep >= sp && isspace(*ep))
        ep--;
    len = (ep < sp) ? 0 : (ep - sp) + 1;//(ep < sp)判断是否整行都是空格
    sp[len] = '\0';
    return sp;
}


void hook_invoke_handle() {
    LOGD("before target\n");
    char *key = target_function();
    LOGD("key is  :%s\n", key);
    LOGD("after target\n");
}

int hook_entry() {
    LOGD("success call hook entry\n");
    char maps_path[32];
    sprintf(maps_path, "/proc/self/maps");
    FILE *maps = fopen(maps_path, "r");
    char str_line[1024];
    char *lib_path;
    while (!feof(maps)) {
        fgets(str_line, 1024, maps);
        if (strstr(str_line, "libnative-lib.so") != NULL) {
            char *path = strtok(str_line, " ");
            while (path != NULL) {
                if (strstr(path,  "libnative-lib.so") != NULL) {
                    lib_path = path;
                    break;
                }
                path = strtok(NULL, " ");
            }
            fclose(maps);
            break;
        }

    }
    fclose(maps);
    lib_path = strim(lib_path);
    LOGD("target lib path is %s %d\n", lib_path, strlen(lib_path));

    char *target_function_name = "getkey";
    void *handle = dlopen(lib_path, RTLD_NOW | RTLD_GLOBAL);
    if (handle == NULL) {
        LOGD("open target so error!\n");
        return -1;
    }

    void *symbol = dlsym(handle, target_function_name);
    if (symbol == NULL) {
        LOGD("get sym %s failed!\n", target_function_name);
        return -1;
    }
    target_function = symbol;
    LOGD("target_function %s addr :%lx\n", target_function_name, target_function);
    LOGD("try to invoke target function\n");
    hook_invoke_handle();
    return 0;

}
