#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>

#include "gothook.h"

pid_t (*old_getpid)() = NULL;

pid_t new_getpid() {
	return (*old_getpid)() + 1;
}

int main(int argc, const char *argv[]) {
	// 找到oepn函数的地址
	void * addr = dlsym(NULL, "getpid");
	printf("[+] before hook, pid = %d\n", getpid());
	// 在自己的got表里面去匹配open的地址，并且替换，如果你要hook可执行文件，
	// 第一个参数就写可执行文件的名字，如果你要hook加载的so，第一个参数就写
	// 要加载的so的全路径
	// 第二个参数为你要hook的函数原始的地址
	// 第三个参数为你要把需要hook的目标函数替换为哪个新的函数
	// 第四个是用来保存你原始函数的地址的一个函数指针
	hookFunc("test", addr, (void*)new_getpid, (void**)&old_getpid);
	printf("[+] old_getpid %p\n", old_getpid);
	printf("[+] after hook, pid = %d\n", getpid());
	return 0;
}