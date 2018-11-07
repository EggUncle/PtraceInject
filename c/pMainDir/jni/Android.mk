LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := ptraceMain
LOCAL_SRC_FILES := main.c \
                    main_util.c \
                    ptrace_util.c

LOCAL_C_INCLUDES += $(PROJECT_PATH)../include

#LOCAL_SRC_FILES := test.c

LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

include $(BUILD_EXECUTABLE)
