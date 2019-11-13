# linux_x86_got_hook
> linux下面32位和64位的got表hook

## 使用注意

hook的原理是替换外部函数的地址，所以要正确使用。比如说a.so里面调用了libc.so里面的open方法，那么在a的got表里面就存放了open的地址。所以说我们就先找到libc里面open方法在内存中的地址(用dlsym来找)，然后在加载到内存中的a.so的got表里面去找到存放open地址的地方，然后把它修改成新的函数的地址。也就是说你替换了libc的open函数在a.so里面引用的地址。

## 使用示例

导入`gothook.h`，然后开始你的代码，demo如下：

```cpp
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
	printf("[+] after hook, pid = %d\n", getpid());
		
	return 0;
}
```

## 编译引用

### 编译

支持cmake构建成静态库

```shell
mkdir build
cd build
cmake ../
make
```

cmake 选项

1. `BUILD_32`指定编译32位的静态库
2. `BUILD_64`指定编译64位静态库
3. `TEST`编译测试文件

### 引用

使用`CMAKE_PREFIX_PATH`选项引用此项目编译的文件夹，然后`find_package`找到这个库即可
