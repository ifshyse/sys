//
//  InjectCode.m
//  sys
//
//  Created by Stephen on 2019/8/30.
//  Copyright © 2019 Stephen. All rights reserved.
//

#import "InjectCode.h"
#import "fishhook.h"
#import <sys/sysctl.h>

@implementation InjectCode

//原始函数的地址
int (*sysctl_p)(int *, u_int, void *, size_t *, void *, size_t);
//自定义函数
int mySysctl(int *name, u_int namelen, void *info, size_t *infosize, void *newinfo, size_t newinfosize){
    struct kinfo_proc *myInfo1 = (struct kinfo_proc *)info;
    //if (myInfo1->kp_proc.p_flag) { //我加的
        //NSLog(@"哈哈哈哈哈哈哈哈哈：%d",myInfo1->kp_proc.p_flag);//结果为1
    //}
    if (namelen == 4
        && name[0] == CTL_KERN
        && name[1] == KERN_PROC
        && name[2] == KERN_PROC_PID
        && info
        && (int)*infosize == sizeof(struct kinfo_proc))
    {
        int err = sysctl_p(name, namelen, info, infosize, newinfo, newinfosize);
        //拿出info做判断
        struct kinfo_proc *myInfo = (struct kinfo_proc *)info;
        if((myInfo->kp_proc.p_flag & P_TRACED) != 0){
            //NSLog(@"哈哈哈哈哈哈哈哈哈22：%d",myInfo1->kp_proc.p_flag);//结果为18436（被调试）
            //使用异或取反（使第12位由1标为0）
            myInfo->kp_proc.p_flag ^= P_TRACED;
        }
        return err;
    }
    return sysctl_p(name, namelen, info, infosize, newinfo, newinfosize);
}
+(void)load
{
    //交换
    rebind_symbols((struct rebinding[1]){{"sysctl",mySysctl,(void *)&sysctl_p}}, 1);
}

@end
