/*
   gcc -DDEBUG=1 -DDEBUG_2_SYSLOG=1 -DDEBUG_2_STDERR=0 -fPIC -shared \
       -o libcoverride.so coverride.c -ldl -Wall -Wextra -Werror
   echo "/path/to/libcoverride.so" | sudo tee -a /etc/ld.so.preload
*/

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#ifndef DEBUG_2_SYSLOG
#define DEBUG_2_SYSLOG 1
#endif

#ifndef DEBUG_2_STDERR
#define DEBUG_2_STDERR 0
#endif

#define DEBUG_PRINT(fmt, ...)                                                  \
  do {                                                                         \
    if (DEBUG) {                                                               \
      if (DEBUG_2_SYSLOG) {                                                    \
        syslog(LOG_INFO | LOG_USER, "override|%s: " fmt, __func__,             \
               __VA_ARGS__);                                                   \
        closelog();                                                            \
      }                                                                        \
      if (DEBUG_2_STDERR)                                                      \
        fprintf(stderr, "override|%s: " fmt, __func__, __VA_ARGS__);           \
    }                                                                          \
  } while (0)

void translate_path(const char **old_str, const char **new_str,
                    char *flexi_str __attribute__((unused)),
                    size_t flexi_str_len __attribute__((unused))) {
  /* do something with me? */
  *new_str = (char *)*old_str;
}

#define TRANSLATE_STR(old_str, new_str)                                        \
  DEBUG_PRINT("%s\n", old_str);                                                \
  char flexi_str[PATH_MAX];                                                    \
  translate_path(&old_str, &new_str, flexi_str, sizeof(flexi_str));            \
  DEBUG_PRINT("%s\n", new_str);

int open(const char *str, int flags, mode_t mode) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  int (*real_open)() = dlsym(RTLD_NEXT, __func__);
  return real_open(__str, flags, mode);
}

DIR *opendir(const char *str) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  DIR *(*real_opendir)() = dlsym(RTLD_NEXT, __func__);
  return real_opendir(__str);
}

int access(const char *str, int mode) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  int (*real_access)() = dlsym(RTLD_NEXT, __func__);
  return real_access(__str, mode);
}

FILE *fopen(const char *str, const char *mode) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  FILE *(*real_fopen)() = dlsym(RTLD_NEXT, __func__);
  return real_fopen(__str, mode);
}

FILE *fopen64(const char *str, const char *mode) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  FILE *(*real_fopen64)() = dlsym(RTLD_NEXT, __func__);
  return real_fopen64(__str, mode);
}

int stat(const char *str, struct stat *buf) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  int (*real_stat)() = dlsym(RTLD_NEXT, __func__);
  return real_stat(__str, buf);
}

int lstat(const char *str, struct stat *buf) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  int (*real_lstat)() = dlsym(RTLD_NEXT, __func__);
  return real_lstat(__str, buf);
}

int __xstat(int ver, const char *str, struct stat *buf) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  int (*real___xstat)() = dlsym(RTLD_NEXT, __func__);
  return real___xstat(ver, __str, buf);
}

int __xstat64(int ver, const char *str, struct stat64 *buf) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  int (*real___xstat64)() = dlsym(RTLD_NEXT, __func__);
  return real___xstat64(ver, __str, buf);
}

int __lxstat(int ver, const char *str, struct stat *buf) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  int (*real___lxstat)() = dlsym(RTLD_NEXT, __func__);
  return real___lxstat(ver, __str, buf);
}

int __lxstat64(int ver, const char *str, struct stat64 *buf) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  int (*real___lxstat64)() = dlsym(RTLD_NEXT, __func__);
  return real___lxstat64(ver, __str, buf);
}

int fstatat(int dirfd, const char *str, struct stat *buf, int flags) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  int (*real_fstatat)() = dlsym(RTLD_NEXT, __func__);
  return real_fstatat(dirfd, __str, buf, flags);
}

int __fxstatat(int ver, int dirfd, const char *str, struct stat *buf,
               int flags) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  int (*real___fxstatat)() = dlsym(RTLD_NEXT, __func__);
  return real___fxstatat(ver, dirfd, __str, buf, flags);
}

ssize_t getxattr(const char *str, const char *name, void *value, size_t size) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  ssize_t (*real_getxattr)() = dlsym(RTLD_NEXT, __func__);
  return real_getxattr(__str, name, value, size);
}

ssize_t lgetxattr(const char *str, const char *name, void *value, size_t size) {
  const char *__str = str;
  TRANSLATE_STR(str, __str)
  ssize_t (*real_lgetxattr)() = dlsym(RTLD_NEXT, __func__);
  return real_lgetxattr(__str, name, value, size);
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
  DEBUG_PRINT("%s %s\n", node, service);
  int (*real_getaddrinfo)() = dlsym(RTLD_NEXT, __func__);
#ifndef GETADDRINFO_EXAMPLE
  return real_getaddrinfo(node, service, hints, res);
#else
  /*
    LD_PRELOAD=$PWD/libcoverride.so \
    python -c 'import socket; print(socket.getaddrinfo("googleapis.com", 80))'
  */
  int ret = real_getaddrinfo(node, service, hints, res);
  if (ret == 0) {
    DEBUG_PRINT("%s %d\n", node, (*res)->ai_family);
    if (strcasestr(node, "googleapis.com") && ((*res)->ai_family == AF_INET)) {
      struct sockaddr_in *addr_in = (struct sockaddr_in *)((*res)->ai_addr);
      DEBUG_PRINT("%s\n", inet_ntoa(addr_in->sin_addr));
      int ret2 = inet_pton(2, "199.36.153.4", &addr_in->sin_addr);
      DEBUG_PRINT("%s %d\n", inet_ntoa(addr_in->sin_addr), ret2);
    }
  }
  return ret;
#endif
}

struct hostent *gethostbyname(const char *name) {
  DEBUG_PRINT("%s\n", name);
  struct hostent *(*real_gethostbyname)() = dlsym(RTLD_NEXT, __func__);
  return real_gethostbyname(name);
}

struct hostent *gethostbyname2(const char *name, int af) {
  DEBUG_PRINT("%s\n", name);
  // LD_PRELOAD=$PWD/libcoverride.so getent hosts google.com
  struct hostent *(*real_gethostbyname2)() = dlsym(RTLD_NEXT, __func__);
  return real_gethostbyname2(name, af);
}
