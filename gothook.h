#ifndef _GOTHOOK_H_
#define _GOTHOOK_H_

#ifdef __cplusplus
extern "C" {
#endif

#define ELF_HOOK 1
#define DYLIB_HOOK 2

int hookFunc(const char *lib, void *symbol, void *new_func, void **old_func);

#ifdef __cplusplus
}
#endif

#endif