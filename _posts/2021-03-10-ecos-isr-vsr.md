---
layout: post
title: Broadcom eCOS | Reversing Interrupt and Exception Handling
author: qkaiser
description: Let's go through the different steps I followed when trying to understand interrupt and exception handling on eCOS.
summary: Let's go through the different steps I followed when trying to understand interrupt and exception handling on eCOS.
date: 2021-03-10 09:00:00
image: /assets/bcm_ecos_isr_vsr.png
tags: [ecos, memory, reversing]
---

![head]({{site.url}}/assets/bcm_ecos_isr_vsr.png)

In this article I'll go through the different steps I followed when trying to understand the interrupt and exception handling on eCOS. I initially wanted to cover this material in the [Reversing eCOS Memory Layout](#) article but I started to divert too much from actual memory mappings.

While it may not be quite clear now, documenting this will be helpful in the future. It will be a time saver when reversing firmware files given that you'll have a clear memory map, and will provide the necessary background when thinking about persistent backdoor mechanisms, custom code injection, or even building your own eCOS debugger.

By reading the eCOS source code for MIPS and doing some [research into dedicated vectors](#), I identified the following locations:

| Vector/Table                  | Address       |
|-------------------------------|---------------|
| Common Vector                 | 0x80000000    |
| Stub Entry Vector             | 0x80000100    |
| Debug Vector                  | 0x80000200    |
| Virtual Service Routine Table | 0x80000300    |  
| Virtual Vector Table          | 0x80000400    |

Let's go through each of these locations one by one.

### Common Vector (0x80000000)

The CPU delivers all exceptions, whether synchronous faults or asynchronous interrupts, to a set of hardware defined vectors. Depending on the architecture, these may be implemented in a number of different ways.

With such a wide variety of hardware approaches, it is not possible to provide a generic mechanism for the substitution of exception vectors directly. Therefore, eCOS translates all of these mechanisms in to a common approach that can be used by portable code on all platforms.

> On MIPS, most exceptions and all interrupts are vectored to a single address at either 0x80000000 or 0xBFC00180. Software is responsible for reading the exception code from the CPU cause register to discover its true source. One of the exception codes in the cause register indicates an external interrupt. Additional bits in the cause register provide a first-level decode for the interrupt source, one of which represents an architecture defined timer. 

Source: [https://ecos.sourceware.org/ecos/docs-latest/ref/hal-vectors-and-vsrs.html](https://ecos.sourceware.org/ecos/docs-latest/ref/hal-vectors-and-vsrs.html)

The mechanism implemented is to attach to each hardware vector a short piece of trampoline code that makes an indirect jump via a table to the actual handler for the exception. This handler is called the Vector Service Routine (VSR) and the table is called the VSR table.

The trampoline code performs the absolute minimum processing necessary to identify the exception source, and jump to the VSR. The VSR is then responsible for saving the CPU state and taking the necessary actions to handle the exception or interrupt. The entry conditions for the VSR are as close to the raw hardware exception entry state as possible - although on some platforms the trampoline will have had to move or reorganize some registers to do its job.

Let's read the content at offset *0x80000000*:

{% highlight sh %}
CM> read_memory -n 32 0x80000000
80000000: 40 1a 68 00  00 00 00 00  33 5a 00 7f  3c 1b 80 00 | @.h.....3Z..<...
80000010: 27 7b 03 00  03 7a d8 20  8f 7b 00 00  03 60 00 08 | '{...z. .{...`..
{% endhighlight %}

By disassembling the obtained bytes, we uncover the trampoline code:

{% highlight bash %}
rasm2 -a mips -b 32 -e -d '401a680000000000335a007f3c1b8000277b0300037ad8208f7b000003600008'
mfc0 k0, t5, 0          ; move from coprocessor 0 into $k0
nop                     ; no operation
andi k0, k0, 0x7f       ; $k0 = $k0 ^ 0x7f
lui k1, 0x8000          ; $k1 = 0x80000000
addiu k1, k1, 0x300     ; $k1 = 0x80000300
add k1, k1, k0          ; $k1 = $k1 + $k0
lw k1, (k1)             ; $k1 = *$k1
jr k1                   ; jump and register to $k1
{% endhighlight %}

It's a perfect match for this piece of assembly from eCOS 2.0 source:

{% highlight asm %}
FUNC_START(other_vector)
     mfc0    k0,cause        # K0 = exception cause
     nop
     andi    k0,k0,0x7F      # isolate exception code
     la  k1,hal_vsr_table    # address of VSR table
     add k1,k1,k0        # offset of VSR entry
     lw  k1,0(k1)        # k1 = pointer to VSR
     jr  k1          # go there
     nop             # (delay slot)
FUNC_END(other_vector)
{% endhighlight %}

The code isolate the exception code and use it as an index for the virtual service routine table. From the trampoline code we disassembled, we know the VSR table starts at offset *0x80000300*.

The **hal_vsr_table** is defined in assembly in ./packages/hal/mips/arch/v2_0/src/vectors.S. We can see that it has 16 entries (64 / 4).

{% highlight asm %}
##  .section ".vsr_table","a"

    .data

    .globl  hal_vsr_table

hal_vsr_table:
    .long   __default_interrupt_vsr
    .rept   63
    .long   __default_exception_vsr
    .endr

#endif
{% endhighlight %}

Let's read 64 bytes starting from offset *0x80000300*:

{% highlight sh %}
Console/vendor> read_memory -n 64 0x80000300

80000300: 80 00 43 ec  80 00 4b d8  80 00 4b d8  80 00 4b d8 | ..C...K...K...K.
80000310: 80 00 4b d8  80 00 4b d8  80 00 4b d8  80 00 4b d8 | ..K...K...K...K.
80000320: 80 00 4b d8  80 00 4b d8  80 00 4b d8  80 00 4b d8 | ..K...K...K...K.
80000330: 80 00 4b d8  80 00 4b d8  80 00 4b d8  80 00 4b d8 | ..K...K...K...K.
{% endhighlight %}

<!-- The functions addresses located at 0x80000380 - 0x80000388 are exception handlers, but they're not related to the VSR trampoline. -->

The virtual service routine table is a table with 16 entries, each of them pointing to a specific function. By comparing the disassembly and the actual assembly from ./packages/hal/mips/arch/v2_0/src/vectors.S, I was able to precisely identify the functions:

- *0x800043ec* - \_\_default\_interrupt\_vsr
- *0x80004bd8* - \_\_default\_exception\_vsr 

To fully understand how the trampoline index the VSR table, I wrote the following Python snippet:

{% highlight python %}
#!/usr/bin/env python3

for i in range(0x7f, 0, -4):
    k = (i ^ 0x7f) >> 2
    offset = 0x80000300 + (i ^ 0x7f)
    if 0x80000340 > offset and offset >= 0x80000300:
        print("{} - 0x{:0x}".format(k, offset))
    elif offset >= 0x80000380 and 80000390 >= offset:
        print("{} - 0x{:0x}".format(k, offset))
{% endhighlight %}

Executing the code will give us the following output:

{% highlight bash %}
python3 vsr_id.py
0 - 0x80000300
1 - 0x80000304
2 - 0x80000308
3 - 0x8000030c
4 - 0x80000310
5 - 0x80000314
6 - 0x80000318
7 - 0x8000031c
8 - 0x80000320
9 - 0x80000324
10 - 0x80000328
11 - 0x8000032c
12 - 0x80000330
13 - 0x80000334
14 - 0x80000338
15 - 0x8000033c
{% endhighlight %}

As we can see, the only valid exception codes that index within the VSR table are values between 0 and 15 included. These are valid exception codes that we can find in the MIPS documentation:

| Exception code|  Name     |   Cause of exception                                  |
|---------------|           |-------------------------------------------------------|
| 0             | Int       | Interrupt (hardware)                                  |
| 1             | Unk       | Unknown                                               |
| 2             | Unk       | Unknown                                               |
| 3             | Unk       | Unknown                                               |
| 4 	        | AdEL      | Address Error exception (Load or instruction fetch)   |
| 5 	        | AdES      | Address Error exception (Store)                       |
| 6 	        | IBE 	    | Instruction fetch Buss Error                          |
| 7 	        | DBE 	    | Data load or store Buss Error                         |
| 8 	        | Sys 	    | Syscall exception                                     |
| 9 	        | Bp 	    | Breakpoint exception                                  |
| 10 	        | RI 	    | Reversed Instruction exception                        |
| 11 	        | CpU 	    | Coprocessor Unimplemented                             |
| 12 	        | Ov 	    | Arithmetic Overflow exception                         |
| 13 	        | Tr 	    | Trap                                                  |
| 14 	        | FPE 	    | Floating Point Exception                              |
| 15            | Unk       | Unknown                                               |

Please note that item 1, 2, 3, and 15 are undocumented.

TODO: insert reversed ghidra code of these functions.

An interesting fact is that, due to the way eCOS firmwares are compiled and assembled, the location of **__default_interrupt_vsr** and **__default_exception_vsr** is the same for all firmwares based on the Broadcom variant of eCOS.

The following piece of code takes advantage of that fact and gather the VSR information from a live system over a serial connection:

{% highlight python %}
#!/usr/bin/env python3
'''
Dump the virtual service routine table information from a live eCOS BFC device.
You must have a serial connection on /dev/ttyUSB0 to either a CM> or RG> shell.

Author: Quentin Kaiser <quentin@ecos.wtf>
'''
import serial
import re

VSR_ADDR = 0x80000300
VSR_NAMES = {
    0x800043ec: "__default_interrupt_vsr",
    0x80004bd8: "__default_exception_vsr",
    0x800042e0: "__default_exception_vsr"
}

CAUSES = [
    "Int - Interrupt (hardware)",
    "Unk - Unknown",
    "Unk - Unknown",
    "Unk - Unknown",
    "AdEL - Address Error exception (Load or instruction fetch)",
    "AdES - Address Error exception (Store)",
    "IBE - Instruction fetch Buss Error",
    "DBE - Data load or store Buss Error",
    "Sys - Syscall exception",
    "Bp - Breakpoint exception",
    "RI - Reversed Instruction exception",
    "CpU - Coprocessor Unimplemented",
    "Ov - Arithmetic Overflow exception",
    "Tr - Trap",
    "FPE - Floating Point Exception",
    "Unk - Unknown"
]

def dump_vector_table():
    with serial.Serial() as ser:
        ser.baudrate = 115200
        ser.port = '/dev/ttyUSB0'
        ser.open()
        ser.write(b"\n")
        ser.readline()
        for i in range(0, 0x10):
            offset = VSR_ADDR + (i * 4)
            ser.write(
                "read_memory -n 4 0x{:0x}\n"\
                .format(offset)\
                .encode('utf-8')
            )
            ser.readline() # echo
            ser.readline() # newline
            output = ser.readline() # content
            ser.readline() # newline
            match = re.findall(b"[0-9-a-f]{8}: ([0-9-a-f ]{11})",output)
            address = int(match[0].replace(b" ", b"").decode('utf-8'), 16)
            if address in VSR_NAMES:
                name = VSR_NAMES[address]
            else:
                name = "UNKNOWN"
            print(
                    "{}: 0x{:0x}\t{:<5}0x{:0x} {}".format(
                    i,
                    offset,
                    name,
                    address,
                    CAUSES[i]
                )
            )

if __name__ == "__main__":
    dump_vector_table()
{% endhighlight %}

Running the code against a Netgear CG3700B device:

{% highlight sh %}
sudo python3 dump_vsr.py
0: 0x80000300	__default_interrupt_vsr                 0x800043ec
1: 0x80000304	__default_exception_vsr                 0x80004bd8
2: 0x80000308	__default_exception_vsr                 0x80004bd8
3: 0x8000030c	__default_exception_vsr                 0x80004bd8
4: 0x80000310	__default_exception_vsr                 0x80004bd8
5: 0x80000314	__default_exception_vsr                 0x80004bd8
6: 0x80000318	__default_exception_vsr                 0x80004bd8
7: 0x8000031c	__default_exception_vsr                 0x80004bd8
8: 0x80000320	__default_exception_vsr                 0x80004bd8
9: 0x80000324	__default_exception_vsr                 0x80004bd8
10: 0x80000328	__default_exception_vsr                 0x80004bd8
11: 0x8000032c	__default_exception_vsr                 0x80004bd8
12: 0x80000330	__default_exception_vsr                 0x80004bd8
13: 0x80000334	__default_exception_vsr                 0x80004bd8
14: 0x80000338	__default_exception_vsr                 0x80004bd8
15: 0x8000033c	__default_exception_vsr                 0x80004bd8
{% endhighlight %}


The visual representation below should help you understand how all these different components interact with each other:

![ecos_isr_vsr_handling]({{site.url}}/assets/ecos_isr_vsr_handling.png)

#### __default_interrupt_vsr

An annotated version of **__default_interrupt_vsr** assembly is provided below to help you dig even more into the subject.

>  MIPS exceptions are handled by a peripheral device to the CPU called coprocessor 0 (cp0). Coprocessor 0 contains a number of registers used to configure exception handling and to report the status of current exceptions.

{% highlight asm %}
__default_interrupt_vsr:

; save ALL registers to the stack, including Hi and Low
800043ec 03 a0 d8 21     move       k1,sp
800043f0 23 bd fe b0     addi       sp,sp,-0x150
800043f4 af ba 00 88     sw         k0,0x88(sp)
800043f8 af a0 00 00     sw         zero,0x0(sp)
800043fc af a1 00 04     sw         at,0x4(sp)
80004400 af a2 00 08     sw         v0,0x8(sp)
80004404 af a3 00 0c     sw         v1,0xc(sp)
80004408 af a4 00 10     sw         a0,0x10(sp)
8000440c af a5 00 14     sw         a1,0x14(sp)
80004410 af a6 00 18     sw         a2,0x18(sp)
80004414 af a7 00 1c     sw         a3,0x1c(sp)
80004418 af a8 00 20     sw         t0,0x20(sp)
8000441c af a9 00 24     sw         t1,0x24(sp)
80004420 af aa 00 28     sw         t2,0x28(sp)
80004424 af ab 00 2c     sw         t3,0x2c(sp)
80004428 af ac 00 30     sw         t4,0x30(sp)
8000442c af ad 00 34     sw         t5,0x34(sp)
80004430 af ae 00 38     sw         t6,0x38(sp)
80004434 af af 00 3c     sw         t7,0x3c(sp)
80004438 af b0 00 40     sw         s0,0x40(sp)
8000443c af b1 00 44     sw         s1,0x44(sp)
80004440 af b2 00 48     sw         s2,0x48(sp)
80004444 af b3 00 4c     sw         s3,0x4c(sp)
80004448 af b4 00 50     sw         s4,0x50(sp)
8000444c af b5 00 54     sw         s5,0x54(sp)
80004450 af b6 00 58     sw         s6,0x58(sp)
80004454 af b7 00 5c     sw         s7,0x5c(sp)
80004458 af b8 00 60     sw         t8,0x60(sp)
8000445c af b9 00 64     sw         t9,0x64(sp)
80004460 af bc 00 70     sw         gp,0x70(sp)
80004464 af be 00 78     sw         s8,0x78(sp)
80004468 af bf 00 7c     sw         ra,0x7c(sp)
8000446c 00 00 20 10     mfhi       a0
80004470 00 00 28 12     mflo       a1
80004474 af a4 00 80     sw         a0,0x80(sp)
80004478 af a5 00 84     sw         a1,0x84(sp)
8000447c af bb 00 74     sw         k1,0x74(sp)

; move values from coprocessor 0 into $t1-$t$3
80004480 40 09 60 00     mfc0       t1,Status
80004484 40 0a 38 00     mfc0       t2,HWREna
80004488 40 0b 70 00     mfc0       t3,EPC

; ; save values $t1-$t3 onto the stack
8000448c af a9 00 8c     sw         t1,0x8c(sp)
80004490 af aa 00 94     sw         t2,0x94(sp)
80004494 af ab 00 90     sw         t3,0x90(sp)

; set global pointer ($gp) to 0x81971b10
80004498 3c 1c 81 97     lui        gp,0x8197
8000449c 27 9c 1b 10     addiu      gp,gp,0x1b10

; $v0 = 0x81925168
800044a0 3c 02 81 92     lui        v0,0x8192
800044a4 24 42 51 68     addiu      v0,v0,0x5168

$a0 = ($v0); $a0 += 1; ($v0) = $a0
800044a8 8c 44 00 00     lw         a0,0x0(v0)=>DAT_81925168                         = 00000001h
800044ac 20 84 00 01     addi       a0,a0,0x1
800044b0 ac 44 00 00     sw         a0,0x0(v0)=>DAT_81925168                         = 00000001h


800044b4 03 a0 80 21     move       s0,sp

; $a0 = stack top (0x8196b470)
; $a1 = stack base (0x8196a470)
; $a3 = sp - base
; # not on interrupt stack if < 0
; delay slot 
800044b8 3c 04 81 97     lui        a0,0x8197
800044bc 24 84 b4 70     addiu      a0,a0,-0x4b90
800044c0 24 85 f0 00     addiu      a1,a0,-0x1000
800044c4 03 a5 38 22     sub        a3,sp,a1
800044c8 04 e0 00 04     bltz       a3,LAB_800044dc
800044cc 00 00 00 00     _nop                               

; t0 = top - sp
; already on interrupt stack if > 0
; delay slot
800044d0 00 9d 40 22     sub        t0,a0,sp
800044d4 1d 00 00 02     bgtz       t0,LAB_800044e0
800044d8 00 00 00 00     _nop

; switch to interrupt stack
; space for old SP (8 to keep dword alignment!)
; save old SP on stack
800044dc 00 80 e8 21     move       sp,a0
800044e0 23 bd ff f8     addi       sp,sp,-0x8
800044e4 af b0 00 00     sw         s0,0x0(sp)=>DAT_8196b468

; make a null frame
800044e8 27 bd ff e0     addiu      sp,sp,-0x20

; hal_intc_decode
; Decode external interrupt via interrupt controller
800044ec 40 03 60 00     mfc0       v1,Status
800044f0 00 00 00 00     nop
800044f4 40 02 68 00     mfc0       v0,Cause
800044f8 00 00 00 00     nop
800044fc 00 43 10 24     and        v0,v0,v1
80004500 00 02 12 02     srl        v0,v0,0x8
80004504 30 42 00 ff     andi       v0,v0,0xff
80004508 3c 03 80 00     lui        v1,0x8000
8000450c 24 63 46 a0     addiu      v1,v1,0x46a0
80004510 00 43 10 20     add        v0,v0,v1
80004514 80 52 00 00     lb         s2,0x0(v0)=>DAT_800046a0

; hal_intc_translate
; Here, s2 contains the number of the interrupt being serviced,
; we need to derive from that the vector number to call in the ISR
; table.
80004518 02 40 88 21     move       s1,s2

; s1 = byte offset of vector
8000451c 00 11 88 80     sll        s1,s1,0x2

; reenable exceptions
80004520 40 02 60 00     mfc0       v0,Status
80004524 3c 03 ff ff     lui        v1,0xffff
80004528 34 63 ff f0     ori        v1,v1,0xfff0
8000452c 00 43 10 24     and        v0,v0,v1
80004530 40 82 60 00     mtc0       v0,Status,0x0
80004534 00 00 00 00     nop
80004538 00 00 00 00     nop
8000453c 00 00 00 00     nop

; $t2 = 0x8137c730 (hal_interrupt_handler, handler table)
80004540 3c 0a 81 38     lui        t2,0x8138
80004544 25 4a c7 30     addiu      t2,t2,-0x38d0

; address of ISR ptr
80004548 01 51 50 20     add        t2,t2,s1

; ISR pointer
8000454c 8d 4a 00 00     lw         t2,0x0(t2)=>->FUN_80e2c5d0                       = 80e2c5d0

; $a1 = 0x8137c750 (hal_interrupt_data)
80004550 3c 05 81 38     lui        a1,0x8138
80004554 24 a5 c7 50     addiu      a1,a1,-0x38b0

; address of data ptr
80004558 00 b1 28 20     add        a1,a1,s1

; data pointer
8000455c 8c a5 00 00     lw         a1,0x0(a1)=>DAT_8137c750

; pass interrupt number
80004560 02 40 20 21     move       a0,s2

; call ISR via t2
80004564 01 40 f8 09     jalr       t2

; delay slot
80004568 00 00 00 00     _nop

; $sp = *$sp
8000456c 8f bd 00 20     lw         sp,0x20(sp)=>DAT_8196b468
; make a null frame
80004570 27 bd ff e0     addiu      sp,sp,-0x20


80004574 00 40 90 21     move       s2,v0

; $a1 = 0x8137c770 (hal_interrupt_objects) 
80004578 3c 05 81 38     lui        a1,0x8138
8000457c 24 a5 c7 70     addiu      a1,a1,-0x3890

; address of object ptr
80004580 00 b1 28 20     add        a1,a1,s1
;  a1 = object ptr
80004584 8c a5 00 00     lw         a1,0x0(a1)=>DAT_8137c770

; arg3 = saved register dump
80004588 02 00 30 21     move       a2,s0

; call into C to finish off
8000458c 0c 38 c2 f2     jal        interrupt_end

; put ISR result in arg0
80004590 00 40 20 21     _move      a0,v0

; return value from isr
80004594 02 40 10 21     move       v0,s2
{% endhighlight %}

#### __default_exception_vsr

An annotated version of **__default_exception_vsr** assembly is provided below to help you dig even more into the subject.

{% highlight asm %}
default_exception_vsr:

; save ALL registers to the stack, including Hi and Low
800042e0 03 a0 d8 21     move       k1,sp
800042e4 23 bd fe b0     addi       sp,sp,-0x150
800042e8 af ba 00 88     sw         k0,0x88(sp)
800042ec af a0 00 00     sw         zero,0x0(sp)
800042f0 af a1 00 04     sw         at,0x4(sp)
800042f4 af a2 00 08     sw         v0,0x8(sp)
800042f8 af a3 00 0c     sw         v1,0xc(sp)
800042fc af a4 00 10     sw         a0,0x10(sp)
80004300 af a5 00 14     sw         a1,0x14(sp)
80004304 af a6 00 18     sw         a2,0x18(sp)
80004308 af a7 00 1c     sw         a3,0x1c(sp)
8000430c af a8 00 20     sw         t0,0x20(sp)
80004310 af a9 00 24     sw         t1,0x24(sp)
80004314 af aa 00 28     sw         t2,0x28(sp)
80004318 af ab 00 2c     sw         t3,0x2c(sp)
8000431c af ac 00 30     sw         t4,0x30(sp)
80004320 af ad 00 34     sw         t5,0x34(sp)
80004324 af ae 00 38     sw         t6,0x38(sp)
80004328 af af 00 3c     sw         t7,0x3c(sp)
8000432c af b0 00 40     sw         s0,0x40(sp)
80004330 af b1 00 44     sw         s1,0x44(sp)
80004334 af b2 00 48     sw         s2,0x48(sp)
80004338 af b3 00 4c     sw         s3,0x4c(sp)
8000433c af b4 00 50     sw         s4,0x50(sp)
80004340 af b5 00 54     sw         s5,0x54(sp)
80004344 af b6 00 58     sw         s6,0x58(sp)
80004348 af b7 00 5c     sw         s7,0x5c(sp)
8000434c af b8 00 60     sw         t8,0x60(sp)
80004350 af b9 00 64     sw         t9,0x64(sp)
80004354 af bc 00 70     sw         gp,0x70(sp)
80004358 af be 00 78     sw         s8,0x78(sp)
8000435c af bf 00 7c     sw         ra,0x7c(sp)
80004360 00 00 20 10     mfhi       a0
80004364 00 00 28 12     mflo       a1
80004368 af a4 00 80     sw         a0,0x80(sp)
8000436c af a5 00 84     sw         a1,0x84(sp)
80004370 af bb 00 74     sw         k1,0x74(sp)

; move values from coprocessor 0 into $t0-$t$6 
80004374 40 08 68 00     mfc0       t0,Cause
80004378 40 09 60 00     mfc0       t1,Status
8000437c 40 0a 38 00     mfc0       t2,HWREna
80004380 40 0b 40 00     mfc0       t3,BadVAddr
80004384 40 0c 18 00     mfc0       t4,EntryLo1
80004388 40 0d 78 00     mfc0       t5,PRId
8000438c 40 0e 70 00     mfc0       t6,EPC

; save values $t0-$t6 onto the stack
80004390 af a8 00 98     sw         t0,0x98(sp)
80004394 af a9 00 8c     sw         t1,0x8c(sp)
80004398 af aa 00 94     sw         t2,0x94(sp)
8000439c af ab 00 9c     sw         t3,0x9c(sp)
800043a0 af ac 00 a4     sw         t4,0xa4(sp)
800043a4 af ad 00 a0     sw         t5,0xa0(sp)
800043a8 af ae 00 90     sw         t6,0x90(sp)

; set global pointer ($gp) to 0x8161e5d0
800043ac 3c 1c 81 62     lui        gp,0x8162
800043b0 27 9c e5 d0     addiu      gp,gp,-0x1a30
; s0 = $sp
800043b4 03 a0 80 21     move       s0,sp
; sp = $sp - 0x20
800043b8 23 bd ff e0     addi       sp,sp,-0x20
; move status register from cp0 into $v0
; apply mask to $v0
; save $v0 back to cp0 status register
800043bc 40 02 60 00     mfc0       v0,Status
800043c0 3c 03 ff ff     lui        v1,0xffff
800043c4 34 63 ff f0     ori        v1,v1,0xfff0
800043c8 00 43 10 24     and        v0,v0,v1
800043cc 40 82 60 00     mtc0       v0,Status,0x0
800043d0 00 00 00 00     nop
800043d4 00 00 00 00     nop
800043d8 00 00 00 00     nop
; call cyg_hal_exception_handler
800043dc 0c 35 07 3d     jal        cyg_hal_exception_handler
{% endhighlight %}

### Stub Entry Vector (0x80000100)

The stub entry vector is supposedly located at *0x80000100*, so let's read 32 bytes from starting from there.

{% highlight sh %}
CM> read_memory -n 32 0x80000100
80000100: 40 1a 68 00  00 00 00 00  33 5a 00 7f  3c 1b 80 00 | @.h.....3Z..<...
80000110: 27 7b 03 00  03 7a d8 20  8f 7b 00 00  03 60 00 08 | '{...z. .{...`..
{% endhighlight %}

The disassembly is exactly the same than the common vector:

{% highlight bash %}
rasm2 -a mips -b 32 -e -d '401a680000000000335a007f3c1b8000277b0300037ad8208f7b000003600008'
mfc0 k0, t5, 0
nop
andi k0, k0, 0x7f
lui k1, 0x8000
addiu k1, k1, 0x300
add k1, k1, k0
lw k1, (k1)
jr k1
{% endhighlight %}

It's a perfect match for this piece of assembly from eCOS 2.0 source:

{% highlight asm %}
FUNC_START(utlb_vector)
     mfc0    k0,cause        # K0 = exception cause
     nop
     andi    k0,k0,0x7F      # isolate exception code
     la  k1,hal_vsr_table    # address of VSR table
     add k1,k1,k0        # offset of VSR entry
     lw  k1,0(k1)        # k1 = pointer to VSR
     jr  k1          # go there
     nop             # (delay slot)
FUNC_END(utlb_vector)
{% endhighlight %}

Similarly, this trampoline will fetch an address from the VSR table and jump to it.

### Debug Vector (0x80000200)

Debug vectors are not used in production system, but let's document it for completeness sake.

Let's read the first 32 bytes starting at offset *0x80000200* and disassemble them with rasm2.

{% highlight sh %}
CM> read_memory -n 32 0x80000200
80000200: 40 1a 68 00  3b 5a 01 00  40 9a 68 00  3c 1a 81 32 | @.h.;Z..@.h.<..2
80000210: 8f 5a 88 58  8f 5a 00 00  8f 5b 00 00  13 60 00 03 | .Z.X.Z...[...`..
80000220: 00 00 00 00  42 00 00 18  00 00 00 00  8f 5d 00 08 | ....B........]..
80000230: 8f 5b 00 0c  40 9b 70 00  03 40 20 21  00 00 00 0f | .[..@.p..@ !....
{% endhighlight %}

Disassembly:

{% highlight bash %}
rasm2 -a mips -b 32 -e -d '401a68003b5a0100409a68003c1a81328f5a88588f5a00008f5b0000136000030000000042000018000000008f5d00088f5b000c409b7000034020210000000f'
mfc0 k0, t5, 0      ; move from coprocessor 0
xori k0, k0, 0x100  ; 
mtc0 k0, t5, 0      ; move to coprocessor 0
lui k0, 0x8132      ; load unsigned integer to $k0
lw k0, -0x77a8(k0)  ; load value from 0x81318858 into $k0
lw k0, (k0)         ;
lw k1, (k0)         ;
beqz k1, 0x2c       ; branch to $k1
nop
eret                ; return from interrupt               
nop
{% endhighlight %}

This is similar to the assembly, although a little more convoluted:

{% highlight asm %}
FUNC_START(debug_vector)
     la  k0,32*4
     la  k1,hal_vsr_table    # Get VSR table
     lw  k1,32*4(k1)     # load debug vector
     jr  k1          # go there
     nop             # (delay slot)
FUNC_END(debug_vector)
{% endhighlight %}

### Virtual Vector Table (0x80000400)

> "Virtual vectors" is the name of a table located at a static location in the target address space. This table contains 64 vectors that point to service functions or data.

> The fact that the vectors are always placed at the same location in the address space means that both ROM and RAM startup configurations can access these and thus the services pointed to.

> The primary goal is to allow services to be provided by ROM configurations (ROM monitors such as RedBoot in particular) with clients in RAM configurations being able to use these services.

> Without the table of pointers this would be impossible since the ROM and RAM applications would be linked separately - in effect having separate name spaces - preventing direct references from one to the other.

> This decoupling of service from client is needed by RedBoot, allowing among other things debugging of applications which do not contain debugging client code (stubs).

Source: [https://ecos.sourceware.org/ecos/docs-latest/ref/hal-calling-if.html](https://ecos.sourceware.org/ecos/docs-latest/ref/hal-calling-if.html)

The virtual vectors table is initialized by the **hal_if_init** function. A simplified decompiled version from an actual firmware is provided below:

{% highlight c %}
void hal_if_init(void)

{
  int address_index;
  int index;

  index = 0;
  address_index = 0;
  do {
    *(undefined4 *)(&DAT_80000400 + address_index) = 0x80d97fb8;
    index = index + 1;
    address_index = index * 4;
  } while (index < 0x40);
  _DAT_80000400 = 0x80015;      //set virtual version table version
  _DAT_80000440 = FUN_80d97f68;     // reset
  _DAT_80000410 = &LAB_80d97f80;    // kill
  _DAT_80000448 = &LAB_80d97ecc;    // microsecond delay
  _DAT_80000420 = &LAB_80d982f0;    // flush instruction cache
  _DAT_8000041c = &LAB_80d98308;    // flush data cache
  _DAT_8000044c = 0;                // debug data
  _DAT_80000438 = 0;                // set serial baud rate
  _DAT_80000430 = set_debug_comm;   // set debug communication channel
  _DAT_80000434 = set_console_comm; // set console communication channel
  _DAT_80000444 = 0;                // console interrupt flag
  return;
{% endhighlight %}

What the function does is initializing the virtual vector table by setting all entries in the vector table so that they point to the function at offset *0x80d97fb8*.

The function at *0x80d97fb8* is what I call `nop_service`:

{% highlight asm %}
undefined nop_service()
        80d97fb8 03 e0 00 08     jr         ra
        80d97fbc 00 00 10 21     _clear     v0
{% endhighlight %}

When all entries are initialized, the code set specific entries.

To understand these specific entries, we can look at the diagram below (inspired by ["Embedded Software Development with eCOS"](https://ecos.sourceware.org/docs.html) by Anthony J. Massa).

![virtual_vector_table_init_sequence]({{site.url}}/assets/virtual_vector_table_init_sequence.png)

Supposedly, this is how the VVT version is built:

> This value contains the total number of virtual vectors in the upper 16 bits, and the definition number of the last supported virtual vectors in the lower 16 bits. For this VVT, the total number of virtual vectors is 64d (0x40), and the definition number of the last virtual vector, Flash ROM Configuration, is 20d (0x14). The version is therefore 0x4014 (**edit**: actually 0x00400014).

Here, the virtual vector table version is set to 0x00080015.

The definition number of the last vector, Flash ROM Configuration is 21d (0x15). The total number of virtual vectors in the upper 16 bits should be 64d (0x40), but is actually 8d (0x8). It's highly probable that Broadcom changed the initial eCOS behavior. We can still rely on the lower 16 bits though.

To interact with the VVT, I wrote a [piece of Python code](#TODO) that lists the entries from a live system by fetching the information over serial.

{% highlight bash %}
python3 dump_vector_table.py
0x80000400	Virtual Vector Table Version            0x80015 
0x80000404	Interrupt Table                         0x80d97fb8 (nop)
0x80000408	Exception Table                         0x80d97fb8 (nop)
0x8000040c	Debug Vector                            0x80d97fb8 (nop)
0x80000410	Kill Vector                             0x80d97f80 
0x80000414	Console I/O Procedure Table             0x81967908 
0x80000418	Debug I/O Procedure Table               0x81967908 
0x8000041c	Flush Data Cache                        0x80d98308 
0x80000420	Flush Instruction Cache                 0x80d982f0 
0x80000424	CPU Data                                0x80d97fb8 (nop)
0x80000428	Board Data                              0x80d97fb8 (nop)
0x8000042c	System Information                      0x80d97fb8 (nop)
0x80000430	Set Debug Communication Channel         0x80d97fc0 
0x80000434	Set Console Communication Channel       0x80d98230 
0x80000438	Set Serial Baud Rate                    0x0 
0x8000043c	Debug System Call                       0x80d97fb8 (nop)
0x80000440	Reset                                   0x80d97f68 
0x80000444	Console Interrupt Flag                  0x0 
0x80000448	Microsecond delay                       0x80d97ecc 
0x8000044c	Debug Data                              0x812b2894 
0x80000450	Flash ROM Configuration                 0x80d97fb8 (nop)
0x80000454	RESERVED                                0x80d97fb8 (nop)
0x80000458	RESERVED                                0x80d97fb8 (nop)
0x8000045c	RESERVED                                0x80d97fb8 (nop)
0x80000460	RESERVED                                0x80d97fb8 (nop)
0x80000464	RESERVED                                0x80d97fb8 (nop)
0x80000468	RESERVED                                0x80d97fb8 (nop)
0x8000046c	RESERVED                                0x80d97fb8 (nop)
0x80000470	RESERVED                                0x80d97fb8 (nop)
0x80000474	RESERVED                                0x80d97fb8 (nop)
0x80000478	RESERVED                                0x80d97fb8 (nop)
0x8000047c	RESERVED                                0x80d97fb8 (nop)
0x80000480	RESERVED                                0x80d97fb8 (nop)
0x80000484	RESERVED                                0x80d97fb8 (nop)
0x80000488	RESERVED                                0x80d97fb8 (nop)
0x8000048c	Install breakpoint                      0x80d97fb8 (nop)
0x80000490	RESERVED                                0x80d97fb8 (nop)
0x80000494	RESERVED                                0x80d97fb8 (nop)
0x80000498	RESERVED                                0x80d97fb8 (nop)
0x8000049c	RESERVED                                0x80d97fb8 (nop)
0x800004a0	RESERVED                                0x80d97fb8 (nop)
0x800004a4	RESERVED                                0x80d97fb8 (nop)
0x800004a8	RESERVED                                0x80d97fb8 (nop)
0x800004ac	RESERVED                                0x80d97fb8 (nop)
0x800004b0	RESERVED                                0x80d97fb8 (nop)
0x800004b4	RESERVED                                0x80d97fb8 (nop)
0x800004b8	RESERVED                                0x80d97fb8 (nop)
0x800004bc	RESERVED                                0x80d97fb8 (nop)
0x800004c0	RESERVED                                0x80d97fb8 (nop)
0x800004c4	RESERVED                                0x80d97fb8 (nop)
0x800004c8	RESERVED                                0x80d97fb8 (nop)
0x800004cc	RESERVED                                0x80d97fb8 (nop)
0x800004d0	RESERVED                                0x80d97fb8 (nop)
0x800004d4	RESERVED                                0x80d97fb8 (nop)
0x800004d8	RESERVED                                0x80d97fb8 (nop)
0x800004dc	RESERVED                                0x80d97fb8 (nop)
0x800004e0	RESERVED                                0x80d97fb8 (nop)
0x800004e4	RESERVED                                0x80d97fb8 (nop)
0x800004e8	RESERVED                                0x80d97fb8 (nop)
0x800004ec	RESERVED                                0x80d97fb8 (nop)
0x800004f0	RESERVED                                0x80d97fb8 (nop)
0x800004f4	RESERVED                                0x80d97fb8 (nop)
0x800004f8	RESERVED                                0x80d97fb8 (nop)
0x800004fc	Virtual Vector Table                    0x80d97fb8 (nop)
{% endhighlight %}

# Conclusion

If you made it through here, congratulations ! Our acquired understanding of the inner workings of eCOS interrupt/exception handling and dedicated vector tables will be helpful in the future when we try to inject GDB stubs into running production firmware. This will also prove useful when we will be designing backdoor persistence by hijacking vector table entries.

As always, if you have any question feel free to contact me via [Twitter](https://twitter.com) or [email](mailto:quentin@ecos.wtf).
