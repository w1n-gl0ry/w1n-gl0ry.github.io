---
title: "FILE STREAM ORIENTED PROGRAMMING"
date: 2023-08-08T17:37:11+08:00
toc: true
description: FSOP ATTACK
tags: ["ctf", "pwn", "technique"]
draft: false
---


# FILE STRUCTURE

###### tags: `fsop` `technique` `pwn` `hacking`

Nói về `FILE STRUCTURE` attack (FSOP), nếu là 1 người chơi `pwn` chắc hẳn mọi người cũng đã có nghe qua. Bản thân mình cũng mơ hồ về loại tấn công này, nên mình quyết định viết 1 bài research về nó.

Theo mình tìm hiểu, thì kỹ thuật này được [Angelboy](https://github.com/scwuaptx) public qua bài viết [ Play with FILE Structure - Yet Another Binary Exploit Technique](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique).

Mình bắt đầu đi vào các phần cơ bản nhất!
### 1. FILE OPERATOR

`FILE` là 1 kiểu dữ liệu được định nghĩa trong glibc và thường được dùng khi muốn mở 1 file trong ngôn ngữ lập trình C.
    Tất nhiên, nó khác với khái niệm `File Descriptor` mà chúng ta thường dùng.
    Mục đích của việc dùng `FILE` là để việc thao tác với các `file operation` nhanh hơn bằng cách sử dụng `buffer` để giảm thiểu số lượng syscall được gọi (_IO_syscall read, write, ....). Vấn đề này mình sẽ giải thích kĩ hơn ở các phần sau.
### 2. DIVING INTO GLIBC CODE
Mình sẽ sử dụng `GLIBC-2.35` source code để tìm hiểu về `FILE STRUCTURE`.
      [FILE](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/bits/types/FILE.h#L7)
  ```c
  typedef struct _IO_FILE FILE
  ```
Vậy, type `FILE` thực chất là `_IO_FILE` struct

Nhìn sơ qua `_IO_FILE` struct trong glibc 2.35:
     [_IO_FILE](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/bits/types/struct_FILE.h#L49)   

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

Nhìn thoáng qua, rất nhiều kiểu dữ liệu được khai báo trong struct.
    
Ba loại `FILE` cơ bản thường được khai báo trong chương trình (nằm trên binary và trỏ đến structure trên libc):
* _IO_2_1_stderr
* _IO_2_1_stdout
* _IO_2_1_stdin

Riêng `stdout` có thể ở chế độ unbuffered, line-buffered, hoặc fully-buffered.
* Unbuffered - Chương trình sẽ in ra thiết bị xuất chuẩn càng sớm càng tốt (không hạn chế).
* Line-buffered - Chương trình sẽ in ra thiết bị xuất chuẩn khi gặp kí tự new-line.
* Fully-buffered - Chương trình sẽ in ra thiết bị xuất chuẩn khi `stdout buffers` đầy.

[_IO_list-all](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/stdfiles.c#L56)
```c
struct _IO_FILE_plus *_IO_list_all = &_IO_2_1_stderr_;
```

Glibc mặc định biến `_IO_list_all` chứa 1 linked list tất cả các type `FILE` trong binary. Mặc định `_IO_list_all` sẽ trỏ tới `stderr` đầu tiên. Các phần tử tiếp theo sẽ được truy cập qua thuộc tính `_chain` .

```c
pwndbg> p &_IO_list_all
$8 = (_IO_FILE_plus **) 0x7ffff7dd5520 <__GI__IO_list_all>
pwndbg> p _IO_list_all
$9 = (_IO_FILE_plus *) 0x7ffff7dd5540 <_IO_2_1_stderr_>
pwndbg> p _IO_2_1_stderr_.file._chain
$10 = (_IO_FILE *) 0x7ffff7dd5620 <_IO_2_1_stdout_>
pwndbg> p _IO_2_1_stdout_.file._chain
$11 = (_IO_FILE *) 0x7ffff7dd48e0 <_IO_2_1_stdin_>
```

_chain

![chain](https://hackmd.io/_uploads/H1GG2SVn2.png)

 


Đặc biệt, `FILE` còn được bao gồm trong struct `_IO_FILE_plus` 
    
[_IO_FILE_plus](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L324)
```c
struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};
```
`Glibc-2.35` có thêm struct `_IO_FILE_plus` là bản mở rộng của struct `_IO_FILE` vì chỉ có chứa thêm ptr [vtable](https://en.wikipedia.org/wiki/Virtual_method_table), và mọi `FILE` đều dùng chung 1 `vtable`. Thường mọi `FILE` (cả 3 `FILE` cơ bản cũng dùng `_IO_FILE_plus` hơn là `_IO_FILE`).

```c
pwndbg> p _IO_2_1_stdout_
$12 = {
  file = {
    _flags = -72537977,
    _IO_read_ptr = 0x7ffff7dd56a3 <_IO_2_1_stdout_+131> "\n",
    _IO_read_end = 0x7ffff7dd56a3 <_IO_2_1_stdout_+131> "\n",
    _IO_read_base = 0x7ffff7dd56a3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_base = 0x7ffff7dd56a3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_ptr = 0x7ffff7dd56a3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_end = 0x7ffff7dd56a3 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_base = 0x7ffff7dd56a3 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_end = 0x7ffff7dd56a4 <_IO_2_1_stdout_+132> "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7ffff7dd48e0 <_IO_2_1_stdin_>,
    _fileno = 1,
    _flags2 = 0,
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "\n",
    _lock = 0x7ffff7dd6780 <_IO_stdfile_1_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x7ffff7dd47a0 <_IO_wide_data_1>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = -1,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7ffff7dd36e0 <__GI__IO_file_jumps>
}
```
`vtable` có kiểu dữ liệu là `_IO_jump_t` 
[_IO_jump_t](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L293)
```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```

Struct này chứa các con trỏ đến các phương thức IO cần thiết trong lúc xử lí file (fopen, fread, fwrite, fclose,...).

Ví dụ khi thực hiện mở 1 file thông qua fopen():
-> Các bước open file:
* Malloc FILE structure
* Gán vtable vào FILE structure
* Khởi tạo FILE structure
* Liên kết FILE structure vào _IO_list_all
* Call fopen()

_Gán vtable vào FILE structure_
```c
_IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
```
`_IO_file_jumps` là bảng 1 trong nhiều`vtable` đã tồn tại trong chương trình. Khởi tạo `vtable` với `_IO_file_jumps` khi mở file. 
Làm sao để gọi hàm đó ?

```c
typedef void (*_IO_finish_t) (_IO_FILE *, int);
```

Khi thực hiện `_IO_FINISH(FP)`, nó sẽ gọi đến hàm được lưu trong `vtable` của `FILE` được truyền vào, với chỉ mục kiểu `int` là vị trí của hàm `_IO_finish_t` trong bảng `vtable`.

Hmm, mình đã khái quát xong.
Tóm gọn lại, nếu chúng ta có thể ghi đè 1 file structure nào đó, thì ta có thể điều khiển được nơi mà chúng ta có thể ghi, đọc -> READ/WRITE PRIMITIVE . Điều đó khá là dễ dàng nhưng chúng ta cần chú ý các điều kiện.

Vậy mình đặt câu hỏi trong đầu: `Liệu có thể điều khiển được luồng thực thi sang hướng khác nếu như mình có thể ghi đè phân vùng vtable không ?` 

Mình sẽ nói rõ hơn phần đó trong phần cuối cùng !
### 3. LEAK LIBC VIA _IO_FILE (READ PRIMITIVE)

Làm sao chúng ta có thể leak được địa chỉ của libc thông qua FSOP attack ?

Trước hết, tìm hiểu cách hoạt động của hàm `puts` trong C (glibc-2.35).

Chương trình đơn giản sau thực hiện việc in chuỗi ra thiết bị xuất chuẩn
```c
#include <stdio.h>

int main(){
    puts("FSOP ATTACK");
    return 0;
}
```

Mình setup source code và compile với `glibc-2.35` bằng câu lệnh sau
```c
$ wget https://ftp.gnu.org/gnu/glibc/glibc-2.35.tar.gz
$ tar -xvf glibc-2.35.tar.gz
* run binary in gdb
pwndbg> dir glibc-2.35/libio/
```
Sau khi load source code vào chúng ta có thể dễ dàng debug hơn với code C.

Debug binary bằng gdb:
```c
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000000000001149 <+0>:     endbr64
   0x000000000000114d <+4>:     push   rbp
   0x000000000000114e <+5>:     mov    rbp,rsp
   0x0000000000001151 <+8>:     lea    rax,[rip+0xeac]        # 0x2004
   0x0000000000001158 <+15>:    mov    rdi,rax
   0x000000000000115b <+18>:    call   0x1050 <puts@plt>
   0x0000000000001160 <+23>:    mov    eax,0x0
   0x0000000000001165 <+28>:    pop    rbp
   0x0000000000001166 <+29>:    ret
End of assembler dump.
```

Mình đặt breakpoints tại hàm chỗ gọi đên hàm `puts@plt` để xem nó làm gì.

Rõ ràng, nó gọi đến hàm `_IO_puts` trong thư viện 
[_IO_puts](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/ioputs.c#L31)
```c
int
_IO_puts (const char *str)
{
  int result = EOF;
  size_t len = strlen (str);
  _IO_acquire_lock (stdout);

  if ((_IO_vtable_offset (stdout) != 0
       || _IO_fwide (stdout, -1) == -1)
      && _IO_sputn (stdout, str, len) == len
      && _IO_putc_unlocked ('\n', stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (stdout);
  return result;
}

weak_alias (_IO_puts, puts)
```

Ta thấy trong source và assembly, tiếp tục gọi đến `_IO_sputn`.
Sau 1 hồi tìm kiếm thì mình biết là `_IO_sputn` là alias tới `_IO_XSPUTN (__fp, __s, __n)` qua dòng code 
```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
```
Đơn giản là nó jump thẳng tới con trỏ hàm trong `__xsputn` với vtable là của `stdout` FP.

```
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)
```
Kiểm tra vtable của `stdout` trong gdb, ta thấy `__xsputn` trỏ đến `_IO_new_file_xsputn`.

```c
pwndbg> print _IO_file_jumps
$3 = {
  __dummy = 0,
  __dummy2 = 0,
  __finish = 0x7ffff7c86060 <_IO_new_file_finish>,
  __overflow = 0x7ffff7c86e60 <_IO_new_file_overflow>,
  __underflow = 0x7ffff7c86af0 <_IO_new_file_underflow>,
  __uflow = 0x7ffff7c88100 <__GI__IO_default_uflow>,
  __pbackfail = 0x7ffff7c898c0 <__GI__IO_default_pbackfail>,
  __xsputn = 0x7ffff7c856b0 <_IO_new_file_xsputn>             # target
  __xsgetn = 0x7ffff7c85340 <__GI__IO_file_xsgetn>,
  __seekoff = 0x7ffff7c849a0 <_IO_new_file_seekoff>,
  __seekpos = 0x7ffff7c88840 <_IO_default_seekpos>,
  __setbuf = 0x7ffff7c84650 <_IO_new_file_setbuf>,
  __sync = 0x7ffff7c844e0 <_IO_new_file_sync>,
  __doallocate = 0x7ffff7c78060 <__GI__IO_file_doallocate>,
  __read = 0x7ffff7c859d0 <__GI__IO_file_read>,
  __write = 0x7ffff7c84f80 <_IO_new_file_write>,
  __seek = 0x7ffff7c84720 <__GI__IO_file_seek>,
  __close = 0x7ffff7c84640 <__GI__IO_file_close>,
  __stat = 0x7ffff7c84f70 <__GI__IO_file_stat>,
  __showmanyc = 0x7ffff7c89a40 <_IO_default_showmanyc>,
  __imbue = 0x7ffff7c89a50 <_IO_default_imbue>
}
```

Vậy ta cùng xem source hàm `_IO_new_file_xsputn`
[_IO_new_file_xsputn](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/fileops.c#L1196)

```c
size_t
_IO_new_file_xsputn (FILE *f, const void *data, size_t n)
{
  const char *s = (const char *) data;
  size_t to_do = n;
  int must_flush = 0;
  size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
	{
	  const char *p;
	  for (p = s + n; p > s; )
	    {
	      if (*--p == '\n')
		{
		  count = p - s + 1;
		  must_flush = 1;
		  break;
		}
	    }
	}
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  /* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
	count = to_do;
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
      s += count;
      to_do -= count;
    }
  if (to_do + must_flush > 0)
    {
      size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
	/* If nothing else has to be written we must not signal the
	   caller that everything has been written.  */
	return to_do == 0 ? EOF : n - to_do;

      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);

      if (do_write)
	{
	  count = new_do_write (f, s, do_write);
	  to_do -= count;
	  if (count < do_write)
	    return n - to_do;
	}

      /* Now write out the remainder.  Normally, this will fit in the
	 buffer, but it's somewhat messier for line-buffered files,
	 so we let _IO_default_xsputn handle the general case. */
      if (to_do)
	to_do -= _IO_default_xsputn (f, s+do_write, to_do);
    }
  return n - to_do;
}
libc_hidden_ver (_IO_new_file_xsputn, _IO_file_xsputn)

```

Trước khi gọi đến hàm `new_do_write()`, ta để ý ở trên gọi đến `_IO_OVERFLOW()`. 

Vào hàm `_IO_OVERFLOW()` thì trong vtable của `stdout`, nó gọi đến hàm `_IO_new_file_overflow()`

[_IO_new_file_overflow](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/fileops.c#L730)

```c
int
_IO_new_file_overflow (FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
	{
	  _IO_doallocbuf (f);
	  _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	}
      /* Otherwise must be currently reading.
	 If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
	 logically slide the buffer forwards one block (by setting the
	 read pointers to all point at the beginning of the block).  This
	 makes room for subsequent output.
	 Otherwise, set the read pointers to _IO_read_end (leaving that
	 alone, so it can continue to correspond to the external position). */
      if (__glibc_unlikely (_IO_in_backup (f)))
	{
	  size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
	  _IO_free_backup_area (f);
	  f->_IO_read_base -= MIN (nbackup,
				   f->_IO_read_base - f->_IO_buf_base);
	  f->_IO_read_ptr = f->_IO_read_base;
	}

      if (f->_IO_read_ptr == f->_IO_buf_end)
	f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
	f->_IO_write_end = f->_IO_write_ptr;
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}
libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)
```

Lưu ý rằng, tham số thứ 2 đang lưu giá trị `EOF` (ch == EOF).

```c
if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
```
`_IO_do_write()` là hàm cuối cùng được gọi và nó là alias tới `_IO_new_do_write()` 

[_IO_new_do_write](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/fileops.c#L422)

```c
static size_t
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```
Cuối cùng trong hàm `_IO_new_do_write()` nó gọi tới `_IO_SYSWRITE (fp, data, to_do)`.

`_IO_SYSWRITE` trỏ tới key `__write` trong vtable. 
```c
#define _IO_SYSWRITE(FP, DATA, LEN) JUMP2 (__write, FP, DATA, LEN)
#__write = 0x7ffff7c84f80 <_IO_new_file_write>
```

[_IO_new_file_write](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/fileops.c#L1172)
```
ssize_t
_IO_new_file_write (FILE *f, const void *data, ssize_t n)
{
  ssize_t to_do = n;
  while (to_do > 0)
    {
      ssize_t count = (__builtin_expect (f->_flags2
                                         & _IO_FLAGS2_NOTCANCEL, 0)
			   ? __write_nocancel (f->_fileno, data, to_do)
			   : __write (f->_fileno, data, to_do)); -> target
      if (count < 0)
	{
	  f->_flags |= _IO_ERR_SEEN;
	  break;
	}
      to_do -= count;
      data = (void *) ((char *) data + count);
    }
  n -= to_do;
  if (f->_offset >= 0)
    f->_offset += n;
  return n;
}
```

Rõ ràng ta thấy, cuối cùng nó sẽ gọi syscall `write()` để thực hiện in ra màn hình ?

```c
__write (f->_fileno, data, to_do)
```

Mình tóm tắt flow của hàm `puts()` thành 1 sơ đồ sau:

```c
puts(str)
|_ _IO_new_file_xsputn (stdout, str, len)
   |_ _IO_new_file_overflow (stdout, EOF)
      |_ new_do_write(stdout, stdout->_IO_write_base, stdout->_IO_write_ptr - stdout->_IO_write_base)
         |_ _IO_new_file_write(stdout, stdout->_IO_write_base, stdout->_IO_write_ptr - stdout->_IO_write_base)
            |_ write(stdout->fileno, stdout->_IO_write_base, stdout->_IO_write_ptr - stdout->_IO_write_base)

```

-> Mọi thứ đã rõ ràng rồi, mục tiêu của chúng ta là làm sao để thực hiện được `write(stdout->fileno, stdout->_IO_write_base, stdout->_IO_write_ptr - stdout->_IO_write_base)`. Việc cần làm đầu tiên là ta phải bypass được 1 loạt check đồ sộ ở trên.

Lúc gọi đến syscall `write`, mình kiểm tra giá trị của từng biến trong write.
Mình đặt break points ngay hàm `write` và lần lượt kiểm tra
```c
pwndbg> p _IO_2_1_stdout_
$1 = {
  file = {
    _flags = -72537468,
    _IO_read_ptr = 0x5555555592a0 "FSOP ATTACK\n",
    _IO_read_end = 0x5555555592a0 "FSOP ATTACK\n",
    _IO_read_base = 0x5555555592a0 "FSOP ATTACK\n",
    _IO_write_base = 0x5555555592a0 "FSOP ATTACK\n",
    _IO_write_ptr = 0x5555555592ac "",
    _IO_write_end = 0x5555555592a0 "FSOP ATTACK\n",
    _IO_buf_base = 0x5555555592a0 "FSOP ATTACK\n",
    _IO_buf_end = 0x5555555596a0 "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7ffff7df6aa0 <_IO_2_1_stdin_>,
    _fileno = 1,
    _flags2 = 0,
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x7ffff7df8a30 <_IO_stdfile_1_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x7ffff7df69a0 <_IO_wide_data_1>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = -1,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7ffff7df3600 <_IO_file_jumps>
}
```

Lúc này:
`stdout->fileno = 1`
`stdout->_IO_write_ptr = 0x5555555592ac`
`stdout->_IO_write_base = 0x5555555592a0 "FSOP ATTACK\n"`

Giá trị `stdout->_IO_write_ptr - stdout->_IO_write_base` đúng bằng 12, bằng độ dài của chuỗi mà chúng ta muốn in.

1 suy nghĩ hiện lên, nếu ta có thể ghi đè những giá trị này ? Có nghĩa là ta sẽ điều khiển nó in cái gì mà ta muốn :>. Khi đó chúng ta không cần phải quan ngại điều gì cả khi đã có địa chỉ LIBC... Hơn thế nữa là STACK, PIE, .....

Nhưng đời không như là mơ, sự thật ~~nỗ não~~ , chúng ta bắt buộc phải bypass tất cả các điều kiện ở trên nếu chúng ta muốn có **READ PRIMITIVE**.

Các macro được define như sau:
```c
#define _IO_MAGIC 0xFBAD0000 /* Magic number */
#define _OLD_STDIO_MAGIC 0xFABC0000 /* Emulate old stdio. */
#define _IO_MAGIC_MASK 0xFFFF0000
#define _IO_USER_BUF 1 /* User owns buffer; don't delete it on close. */
#define _IO_UNBUFFERED 2
#define _IO_NO_READS 4 /* Reading not allowed */
#define _IO_NO_WRITES 8 /* Writing not allowd */
#define _IO_EOF_SEEN 0x10
#define _IO_ERR_SEEN 0x20
#define _IO_DELETE_DONT_CLOSE 0x40 /* Don't call close(_fileno) on cleanup. */
#define _IO_LINKED 0x80 /* Set if linked (using _chain) to streambuf::_list_all.*/
#define _IO_IN_BACKUP 0x100
#define _IO_LINE_BUF 0x200
#define _IO_TIED_PUT_GET 0x400 /* Set if put and get pointer logicly tied. */
#define _IO_CURRENTLY_PUTTING 0x800
#define _IO_IS_APPENDING 0x1000
#define _IO_IS_FILEBUF 0x2000
#define _IO_BAD_SEEN 0x4000
#define _IO_USER_LOCK 0x8000
```
Lần lượt đọc source và đi qua từng hàm để xem có thể khai thác được gì không:

Để thực hiện được `_IO_do_write()` thì mình lần lượt check từng câu lệnh if trong `_IO_new_file_overflow()`

```c
if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
```

Rõ ràng `f->_flags & _IO_NO_WRITES` buộc phải trả về false thì mới thực hiện tiếp được.
```
   0x7ffff7c86e64 <_IO_file_overflow+4>     push   r12
   0x7ffff7c86e66 <_IO_file_overflow+6>     push   rbp
   0x7ffff7c86e67 <_IO_file_overflow+7>     push   rbx
   0x7ffff7c86e68 <_IO_file_overflow+8>     mov    eax, dword ptr [rdi]
   0x7ffff7c86e6a <_IO_file_overflow+10>    mov    rbx, rdi
 ► 0x7ffff7c86e6d <_IO_file_overflow+13>    test   al, 8
 ```
 `_IO_NO_WRITES = 8`  nên `stdout->_flags & 8 = 0`
 
 * `stdout->_flags & 8 = 0`

Tiếp tục check tiếp, chúng ta phải khiến nó sao cho trả về False
```c
if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
	{
	  _IO_doallocbuf (f);
	  _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	}
```

Có nghĩa `f->_flags & _IO_CURRENTLY_PUTTING != 0`

Kiểm tra giá trị `_IO_CURRENTLY_PUTTING` trong gdb:
```c
   0x7ffff7c86e75 <_IO_file_overflow+21>    mov    ebp, esi
   0x7ffff7c86e77 <_IO_file_overflow+23>    mov    rsi, qword ptr [rdi + 0x20]
 ► 0x7ffff7c86e7b <_IO_file_overflow+27>    test   ah, 8
```

Như vậy `f->_flags & 8 = 1` || `f->_IO_write_base == NULL` -> False

* `f->_flags & 0x0800 = 1`

Giả sử, chúng ta đã bypass qua 2 lần check đó
Ta đã lưu ý `ch` vẫn bằng EOF nên có thể thành công vào hàm `_IO_do_write()`

```c
if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
```

`_IO_do_write()` gọi tới `_IO_new_do_write`
```c
static size_t
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```

`fp->_flags & _IO_IS_APPENDING` cần phải trả về True để không bị vướng vào câu lệnh if hỗn độn ngay dưới nó :>

Nếu không thõa mãn điều kiện này thì ta thử đi vào câu lệnh nhánh if phía dưới:
```c
    if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
```
So sánh giá trị `fp->_IO_read_end` và `fp->_IO_write_base` nếu khác nhau, sẽ gọi hàm `_IO_SYSSEEK()`. Bởi vì giá trị của `fp->_IO_read_end` và `fp->_IO_write_base` đang bằng nhau nên có thể dễ dàng bypass được kiện check. ĐI sâu vào bên trong, `_IO_SYSSEEK()` sẽ gọi syscall `lseek()` với tham số là `offset=fp->_IO_write_base - fp->_IO_read_end`. Vì vậy, nếu `fp->_IO_write_base` < `fp->_IO_read_end` thì `offset` sẽ có giá trị âm và làm cho chương trình báo lỗi. Như vậy, để nó không xảy ra thì ta chỉ cần overwrite LSB của `fp->_IO_write_base` thành null byte, nhưng muốn chắc thì ta cũng overwrite LSB của`fp->_IO_write_base` thành null.

`fp->_flags & _IO_IS_APPENDING = 1` 
```c
   0x7ffff7c8699d <_IO_do_write+45>    mov    rbp, rdx
   0x7ffff7c869a0 <_IO_do_write+48>    push   rbx
   0x7ffff7c869a1 <_IO_do_write+49>    mov    rbx, rdi
   0x7ffff7c869a4 <_IO_do_write+52>    sub    rsp, 8
   0x7ffff7c869a8 <_IO_do_write+56>    mov    r14, qword ptr [rdi + 0xd8]
 ► 0x7ffff7c869af <_IO_do_write+63>    test   dword ptr [rdi], 0x1000       <_IO_2_1_stdout_>
   0x7ffff7c869b5 <_IO_do_write+69>    jne    _IO_do_write+272                <_IO_do_write+272>
```
`_IO_IS_APPENDING = 0x1000` 

* `fp->_flags & 0x1000 == 1`


Vậy, tổng kết như sau:
```
stdout->_flags & _IO_NO_WRITES         == 0
stdout->_flags & _IO_CURRENTLY_PUTTING == 1
stdout->_flags & _IO_IS_APPENDING      == 1
```
_flags & 0x8 = 0 
_flags & 0x800 = 1
_flags & 0x1000 = 1
**-> _flags = 0x1800**

Tương tự với READ PRIMITIVE, WRITE PRIMITIVE cũng cần 1 số điều kiện để chúng có thể hoạt động, chỉ cần chúng ta điều khiển được các giá trị `_IO_read_end`, `_IO_read_ptr`,... là được.
Vậy, chúng ta đã thành công bypass được tất cả các hạn chế và chỉ cần ghi vào `f->_IO_write_ptr` , `f->_IO_write_base` những giá trị phù hợp để khai thác, ta sẽ có được ~~LIBC BASE~~ , khi đã có ~~LIBC BASE~~, ta có thể tiếp tục dùng `FSOP` để điều khiển được luồng thực thi nhờ `VTABLE HIJACKING` như phần trên mình đã nói (và rõ ràng là ở GLIBC-2.35 thì gần như đã full đồ, full giáp nên việc tấn công FSOP rất là khó và phải cần rất nhiều kiến thức và hiểu rõ bản chất để có thể đi sâu hơn trong kĩ thuật này) !

### 4. VTABLE-HIJACKING

Ta đã thành công giải quyết được vấn đề READ/WRITE PRIMITIVE trên GLIBC-2.35, làm sao ta có thể điều khiển được luồng thực thi từ chương trình nếu như không thể bypass được loạt check trên.

### 5. PROTECTION MECHANISM
Từ phiên bản `Glibc-2.24` trở đi, khi ta ghi đè vào vtable thì sẽ không còn chiếm quyền điều khiển được nữa. Bởi vì chương trình sẽ kiểm tra tính hợp lệ của địa chỉ `vtable` trước khi gọi hàm ảo. 

Hai hàm `IO_validate_vtable` and `_IO_vtable_check` được thêm vào. 
```c
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  const char *ptr = (const char *) vtable;
  uintptr_t offset = ptr - __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```

Hàm kiểm tra xem con trỏ vtable có nằm trong phần `__libc_IO_vtables` hay không. Nếu không, nó sẽ tiếp tục gọi đến `_IO_vtable_check` .

```c
void attribute_hidden
_IO_vtable_check (void)
{
#ifdef SHARED
  void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (flag);
#endif
  if (flag == &_IO_vtable_check)
    return;
  {
    Dl_info di;
    struct link_map *l;
    if (_dl_open_hook != NULL
       || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
            && l->l_ns != LM_ID_BASE))
      return;
  }
#else /* !SHARED */
  if (__dlopen != NULL)
    return;
#endif
  __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
}
```
Nếu `vtable` không hợp lệ, chương trình sẽ dừng lại và báo lỗi.



### References

https://chovid99.github.io/posts/file-structure-attack-part-1/
https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/
https://nightrainy.github.io/2019/08/07/play-withe-file-structure-%E6%90%AC%E8%BF%90/
https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/
https://en.wikipedia.org/wiki/Virtual_method_table
https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/
https://blog.kylebot.net/2022/10/22/angry-FSROP/
https://bbs.kanxue.com/thread-273832.htm