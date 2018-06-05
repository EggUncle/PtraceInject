## Ptrace 进程注入

### 0x00 前言
以前就想试下进程注入这个东西,但是相关知识懂得太少了,进度就一直很慢,后来还是想了下感觉还是得头铁的尝试一下看看,这里把整个过程和踩到的坑记下来,也算是个简单的教程吧,我会的不多,但是一路下来还是了解到了不少东西,这里就把一路上用到的也都记下来

### 0x01 目的
首先先明确目标,首先新建一个app项目,里面的jni部分代码是这样的:
```
#include <jni.h>
#include <string>
#include <string.h>
#include <sys/mman.h>

extern "C"
char *getkey() {
    static char key[32];
    strcpy(key, "justakeyfromjni");
    return key;
}

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_example_egguncle_hidekeyinjni_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string key = getkey();
    return env->NewStringUTF(key.c_str());
}
```
我们的目的就是通过进程注入,调用这个app中的getkey函数,获取到"justakeyfromjni"这个字符串,不弄的太复杂.注入的部分从简,使用c语言直接编写一个可执行文件push到手机中运行.

### 0x02 在Android直接执行可执行文件
除了运行app,android中其实也是可以运行可执行文件的,首先需要配置ndk环境,这里就不说ndk环境怎么配置了,有了ndk环境以后,使用交叉编译器编译c代码就可以运行了,先来写一个hello world助助兴.
```
pMain.c
#include <stdio.h>

int main(){
    printf("hello ptrace\n");
    return 0;
}
```
然后就要使用刚刚提到的交叉编译器了,使用gcc进行编译
```
arm-linux-androideabi-gcc pMain.c -o pMain -pie -fPIE
```
pMain.c 就是这个hello world的代码,-o 的参数即是生成的执行文件的名称,我们将它push到data/local/tmp下,然后直接执行./pMain就能看到结果了

![](https://github.com/EggUncle/Demo/blob/master/markdownimg/2018-06-05%2021-26-57%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE.png?raw=true)

### 0x03 Ptrace介绍
>为方便应用软件的开发和调试，从 Unix 的早期版本开始就提供了一种对运行中的进程进行跟踪和控制的手段，那就是系统调用 ptrace()。通过 ptrace()，一个进程可以动态地读/写另一个进程的内存和寄存器，包括其指令空间、数据空间、堆栈以及所有的寄存器。与信号机制（以及其它手段）相结合， 就可以实现让一个进程在另一个进程的控制和跟踪下运行的目的。

>GNU 的调试工具gdb 就是一个典型的实例。通过gdb，软件开发人员可以使一个应用程序在gdb的“监视”和操纵下受控地运行。对于受gdb 控制的进程，可以通过在其程序中设置断点，检查其堆校以确定函数调用路线，检查并改变局部变 量或全局变量的内容等等方法，来进行调试。显然，所有这些手段从概念上说都确实属于进程间“通信”的范畴，但是必须指出，这只是为软件调试而设计和设立的，不应该用于一般的进程间通信。一 般而言，通信是要由双方都介入且互相协调才能完成的。就拿“管道”来说，虽然管道是单向的，但 一定得由一方写，另一方读才能达到目的。再拿信号来说，虽然信号是异步的，也就是接收信号的一 方并不知道信号会在什么时候到来，因而在应用程序中并不主动有意地去检查有否信号到达。但是从 总体而言，接收方知道信号可能会到来，并且为此在应用程序中作出了安排。而当信号真的到来时， 接收方也“知道”其到来，并根据事先的安排作出反应。然而，由 ptrace()所实现的“通信”却完全是单方面的，被跟踪的进程甚至并不知道（从应用程序的角度而言）自己是在受到控制和监视的条件下运行。从这个角度讲，ptrace()其实又不属于“进程间通信”。

>ptrace 提供了一种使父进程得以监视和控制其他进程的方式，它还能够改变子进程巾的寄存器和内核映像，因而可以实现断点调试和系统调用的跟踪。使用ptrace ，你可以在用户层拦截和修改系统调用（这个和 Hook 所要达到的目的类似），父进程还可以便子进程继续执行，并选择是再忽略引起终止的信号。

### 0x04 Ptrace的部分使用方法
在注入之前,简单介绍一下需要用到的ptrace的部分功能<br>
##### 1.PTRACE_ATTACH
attach到其他进程上,pid为目标进程的id
```
ptrace(PTRACE_ATTACH, pid, NULL, 0)
```

##### 2.PTRACE_DETACH
脱离attach的进程,pid为目标进程的id
```
ptrace(PTRACE_DETACH, pid, NULL, 0)
```

##### 3.PTRACE_POKETEXT
向对应进程写入数据,pid为目标进程id,dest为地址,val为写入的数据
```
ptrace(PTRACE_POKETEXT, pid, dest, val);
```

##### 4.PTRACE_POKETEXT
读取对应进程的数据,pid为目标进程id,dest为地址
```
ptrace(PTRACE_PEEKTEXT, pid, dest, 0)
```

##### 5.PTRACE_SETREGS/PTRACE_GETREGS
设置/读取寄存器,pid为目标进程地址
```
ptrace(PTRACE_SETREGS, pid, NULL, regs)
```

##### 6.PTRACE_CONT
继续执行,pid为目标进程地址
```
ptrace(PTRACE_CONT, pid, 0, signal)
```

### 0x05 进程注入的实现
先上一张图简单的描述一下整个注入的流程<br>
![](https://github.com/EggUncle/Demo/blob/master/markdownimg/%E6%9C%AA%E5%91%BD%E5%90%8D%E6%96%87%E4%BB%B6.png?raw=true)

然后单独讲一下每一步的实现<br>
1. attach到目标进程
```
ptraceAttach(pid);
```
这里其实不光要attach到目标进程,还得保存目前寄存器状态,为了一会儿恢复现场.
```
struct pt_regs currentRegs, orgRegs;
// 获取远程进程的寄存器值
if (ptraceGetregs(pid, &currentRegs) == -1) {
    perror("get reg error");
}
memcpy(&orgRegs, &currentRegs, sizeof(currentRegs));
```

2. 在目标进程中调用mmap申请一段空间
```
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
```
这里申请空间就是用来在后续调用dlopen和dlsym时,写入参数用的,这一步执行完以后,就可以在进程中看到自己申请到的空间了,cat proc/pid/map文件,查看mmap对应的返回值,就能看到
![](https://github.com/EggUncle/Demo/blob/master/markdownimg/2018-06-05%2022-16-58%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE.png?raw=true)

3. 将注入的so路径写入目标进程地址中
```
   ptraceWriteData(pid, mmapBase, hookSoPath, strlen(hookSoPath) + 1);
```

4. 调用dlopen,加载hooker.so
```
parameters[0] = (long) mmapBase;
parameters[1] = RTLD_NOW | RTLD_GLOBAL;
//通过ptrace调用
if (ptraceCallWrapper(pid, "dlopen", remoteDlopen, parameters, 2, &currentRegs) < 0) {
    printf("call target dlopen error");
    return -1;
}
```
这里就将hooker.so加载上去了,现在再cat proc/pid/map |grep hook看看
![](https://github.com/EggUncle/Demo/blob/master/markdownimg/2018-06-05%2022-21-17%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE.png?raw=true)
可以看到hooker.so已经加载到目标进程里面去了,出现三行的原因是因为so本身属于elf文件,而elf是分段的.比如代码段,数据段等等,也能看到每个地址后面都有r-xp或者其他字样,这里就是对应的权限不同.

5. 调用dlsym,获取hooker.so中的hookentry符号
```
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
```
6. 调用hookentry
```
if (ptraceCallWrapper(pid, targetFuncName, hookFuncAddr, parameters, 0, &currentRegs) < 0) {
        printf("call target %s error", targetFuncName);
        return -1;
    }
```
这里再贴一下hooker.c的代码

```
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
```

整个过程比较简单,就是加载了目标进程中的so,并获取了目标函数的符号,再调用一下就行,然后我们看一下logcat

![](https://github.com/EggUncle/Demo/blob/master/markdownimg/2018-06-05%2022-29-53%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE.png?raw=true)

可以看到结果也出来了,成功注入了so并且调用了进程中的函数


7.最后不要忘了恢复现场
```
parameters[0] = targetSoHandle;

    if (ptraceCallWrapper(pid, "dlclose", targetDlclose, parameters, 1, &currentRegs) < -1) {
        printf("call target dlclose error");
        return -1;
    }
    ptraceSetregs(pid, &orgRegs);
    ptraceDetach(pid);
```

整个流程下来大致就是这样,并不是很难.

### 0x05 踩到的一些坑
- selinux需要关了,setenforce 0
- adb root
- 查找符号的时候,如果是c++,最好反编译一下看看完整的函数声明
- 编译so的时候按照ndk流程来,最好是用ndk-bulid
- 主要还是菜
