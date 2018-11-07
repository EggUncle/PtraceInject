//
// Created by songyucheng on 18-11-6.
//

#include "include/main_util.h"


//遍历proc下的文件夹 proc/pid/cmdline中,有对应应用的包名
int get_target_process_pid(char *pkg_name) {
    int id;
    pid_t pid = -1;
    DIR *dir;
    FILE *fp;
    char cmdline[256];
    char filename[32];
    struct dirent *entry;

    if (pkg_name == NULL) {
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
                if (strcmp(cmdline, pkg_name) == 0) {
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
void *get_libs_addr(pid_t pid, char *lib_name) {
    char maps_path[32];
    long addr = 0;
    if (pid < 0) {
        sprintf(maps_path, "/proc/self/maps");
    } else {
        sprintf(maps_path, "/proc/%d/maps", pid);
    }
    FILE *maps = fopen(maps_path, "r");
    char str_line[1024];
    //  printf("%s", maps_path);
    while (!feof(maps)) {
        fgets(str_line, 1024, maps);
        if (strstr(str_line, lib_name) != NULL) {
//            printf("---------\n");
//            printf("%s\n", str_line);
//            printf("%s\n", strtok(str_line, "-"));
//            printf("---------\n");
            fclose(maps);
            addr = strtoul(strtok(str_line, "-"), NULL, 16);
//            printf("%ld\n", addr);
//            printf("%lx\n", (void *) addr);
//            printf("==========\n");
            if (addr == 0x8000)
                addr = 0;
            break;
        }

    }
    fclose(maps);
    return (void *) addr;
}

void *get_remote_func_addr(void *local_lib_addr, void *local_func_addr, void *remote_func_addr) {
    return (void *) ((long) remote_func_addr + (long) local_func_addr - (long) local_lib_addr);
}

char *get_libs_path(pid_t pid, char *lib_name) {
    char maps_path[32];
    if (pid < 0) {
        sprintf(maps_path, "/proc/self/maps");
    } else {
        sprintf(maps_path, "/proc/%d/maps", pid);
    }
    FILE *maps = fopen(maps_path, "r");
    char str_line[1024];
    char *target_lib_path;
    while (!feof(maps)) {
        fgets(str_line, 1024, maps);
        if (strstr(str_line, lib_name) != NULL) {
            char *path = strtok(str_line, " ");
            while (path != NULL) {
                if (strstr(path, lib_name) != NULL) {
                    target_lib_path = path;
                    break;
                }
                path = strtok(NULL, " ");
            }
            fclose(maps);
            break;
        }

    }
    fclose(maps);
    target_lib_path = strim(target_lib_path);
    return target_lib_path;
}

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
