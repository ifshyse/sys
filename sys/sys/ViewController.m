//
//  ViewController.m
//  sys
//
//  Created by Stephen on 2019/8/30.
//  Copyright © 2019 Stephen. All rights reserved.
//

#import "ViewController.h"
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <sys/syscall.h>

typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);

#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif  // !defined(PT_DENY_ATTACH)

//1. dlopen + dysym
void disable_gdb() {
    void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);
}

//2. 也可以基于 runtime 符号查找
// runtime to get symbol address, but must link with
// -Wl,-undefined,dynamic_lookup` or you can use `dlopen` and `dlsym`
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);
static void AntiDebug_002() { ptrace(PT_DENY_ATTACH, 0, 0, 0);}

//3. 使用 syscall 实现
void AntiDebug_005() { syscall(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0); }

//4. 内联 svc + ptrace 实现
//其实这种方法等同于直接使用 ptrace, 此时系统调用号是 SYS_ptrace
static __attribute__((always_inline)) void AntiDebug_003() {
#ifdef __arm64__
    __asm__("mov X0, #31\n"
            "mov X1, #0\n"
            "mov X2, #0\n"
            "mov X3, #0\n"
            "mov w16, #26\n"
            "svc #0x80");
#endif
}

// 5. 内联 svc + syscall + ptrace 实现
//其实这种方法等同于使用 syscall(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0), 这里需要注意, 此时的系统调用号是 0, 也就是 SYS_syscall
static __attribute__((always_inline)) void AntiDebug_004() {
#ifdef __arm64__
    __asm__("mov X0, #26\n"
            "mov X1, #31\n"
            "mov X2, #0\n"
            "mov X3, #0\n"
            "mov X4, #0\n"
            "mov w16, #0\n"
            "svc #0x80");
#endif
}

@interface ViewController ()

@end
static dispatch_source_t timer;

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    debugCheck();
//                asm("mov X0,#0\n"
//                    "mov w16,#1\n"
//                    "svc #0x80"
//                    );
}

void debugCheck(){
    timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(0, 0));
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 1.0 * NSEC_PER_SEC, 0.0 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        if (isDebugger()) {
            NSLog(@"检测到了!!");
            disable_gdb();
        }else{
            NSLog(@"正常!!");
        }
    });
    dispatch_resume(timer);
    
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC, 0 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        
    });
    dispatch_resume(timer);
}
//int    sysctl(int *, u_int, void *, size_t *, void *, size_t);
//检测是否被调试
BOOL isDebugger(){
    //控制码
    //    方式一
    //    int name[] = {
    //        CTL_KERN,
    //        KERN_PROC,
    //        KERN_PROC_PID,
    //        getpid()
    //    };
    //    方式二
    int name[4];//里面放字节码.查询信息
    name[0] = CTL_KERN;//内核查看
    name[1] = KERN_PROC;//查询进程
    name[2] = KERN_PROC_PID;//传递的参数是进程的ID(PID)
    name[3] = getpid();//PID的值告诉
    
    struct kinfo_proc info;//接受进程查询结果信息的结构体
    size_t info_size = sizeof(info);//结构体的大小
    int error = sysctl(name, sizeof(name)/sizeof(*name), &info, &info_size, 0, 0);//sizeof(name)/sizeof(*name)或者sizeof(name)/sizeof(int)
    assert(error == 0);//0就是没有错误,其他就是错误码
    /**
     0000 0000 0000 0000 0100 1000 0000 0100//有调试(info.kp_proc.p_flag=18436)
     &
     0000 0000 0000 0000 0000 1000 0000 0000 （P_TRACED）
     结果：
     0000 0000 0000 0000 0000 1000 0000 0000 （不为0）
     
     
     0000 0000 0000 0000 0100 0000 0000 0100//没有调试(info.kp_proc.p_flag=16388)
     &
     0000 0000 0000 0000 0000 1000 0000 0000   （P_TRACED）
     结果：
     0000 0000 0000 0000 0000 0000 0000 0000 （为0）
     
     结果为0没有调试，结果不为0有调试
     */
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
    
}

@end
