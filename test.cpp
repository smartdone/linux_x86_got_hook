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
	void * handle = dlopen("/lib/x86_64-linux-gnu/libc-2.23.so", RTLD_GLOBAL | RTLD_LAZY);
	void * addr = dlsym(handle, "getpid");
	printf("[+] before hook, pid = %d\n", getpid());
	hookFunc("test", addr, (void*)new_getpid, (void**)&old_getpid);
	printf("[+] after hook, pid = %d\n", getpid());
	printf("[+] after hook, pid = %d\n", getpid());
	printf("[+] after hook, pid = %d\n", getpid());
	
	return 0;
}