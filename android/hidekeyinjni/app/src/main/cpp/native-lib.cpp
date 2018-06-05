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

