---
layout: post
title: Zyxel | Auto-identifying eCos Firmwares Load Address
description: This is a guest post by cq674350529 on searching (and finding) the correct load address of an eCos firmware image from Zyxel. 
summary: This is a guest post by cq674350529 on searching (and finding) the correct load address of an eCos firmware image from Zyxel.
author: cq674350529
image: assets/ecos_wtf_logo_head.png
date: 2021-03-30 06:00:00
tags: [ecos, zyxel, firmware]
---

*This is a guest post by [cq674350529](https://twitter.com/cq674350529), that the ecos.wtf team translated from Chinese. The original blog post can be found at [https://cq674350529.github.io/](https://cq674350529.github.io/2021/03/04/Zyxel%E8%AE%BE%E5%A4%87eCos%E5%9B%BA%E4%BB%B6%E5%8A%A0%E8%BD%BD%E5%9C%B0%E5%9D%80%E5%88%86%E6%9E%90/). cq674350529 remains the copyright owner of the full article content, illustration included.*

*An editor's note can be found at the end with our take on this :)*

# Preface

We recently analyzed Zyxel devices and found out that binwalk could not properly extract their firmwares. From binwalk's output, we gathered that the [firmware](https://www.zyxel.com/support/download_landing/product/rgs200_12p_13.shtml?c=gb&l=en&pid=20160321160003&tab=Firmware&pname=RGS200-12P) was actually a single eCos binary blob.

```
binwalk RGS200-12P.bin 
DECIMAL HEXADECIMAL DESCRIPTION 
----------------------------------------------- --------------------------------- 
0 0x0 eCos kernel exception handler, architecture: MIPSEL, exception vector table base address: 0x80000200 
128 0x80 eCos kernel exception handler, architecture: MIPSEL, exception vector table base address: 0x80000200 
5475588 0x538D04 Unix path: /home/remus/svn/ivs/IVSPL5-ZyXEL_New/src_0603/build/../build/obj/ecos/ install/include/cyg/libc/stdlib/atox.inl 
5475653 0x538D45 eCos RTOS string reference: "ecos/install/include/cyg/libc/stdlib/atox.inl" 
--snip--
5945083 0x5AB6FB eCos RTOS string reference: "ecos_driver_vid_to_if_index !"
5949577 0x5AC889 eCos RTOS string reference: "ecos_driver_inject vid=%u, length=%u" 
--snip--
6525239 0x639137 eCos RTOS string reference: "eCos/packages/devs/serial/generic/16x5x/current/src/ser_16x5x.c " 
--snip--
```

Without knowledge of the load address for that binary, reverse engineering it with any SRE tool will fail given that cross-references cannot be established.

The screenshot below illustrates what happens when you load such a binary in IDA with the right architecture but the wrong load address. We see that functions are not recognized and the whole segment is left in "unexplored" state. This clearly indicates that the load address is incorrect and we need a way to obtain the load address of that firmware.

![ida_loadbase_0x80000000]({{site.url}}/assets/ida_loadbase_0x80000000.png)

There's not much information about eCos firmware analysis online so we were left blind. We therefore devised a method to derive the firmware load address from fixed addresses present in the binary file.


We searched for relevant information and found this [article](https://blog.csdn.net/qq_20405005/article/details/77971929) discussing eCos vector initialization. It briefly introduces the eCos interrupt and exception handling procedures initialization. It mentioned `0x80000180` but this address is clearly not the load address either.

```
# mips cpu After the exception/interrupt is generated, the cpu will jump to a few specific addresses, 
# BEV=0, generally at 0x80000180, of course there are some other addresses, for details, please see mips books 
# Here is such a code 
FUNC_START(other_vector) 
    mfc0 k0,cause # K0 = exception cause 
    nop 
    andi k0,k0,0x7F # isolate exception code 
    la k1,hal_vsr_table # address of VSR table 
    add k1,k1,k0 # offset of VSR entry 
    lw k1,0(k1 ) # k1 = pointer to VSR 
    jr k1 # go there 
    nop # (delay slot) 
FUNC_END(other_vector)
```

We also looked at the linker file for MIPS TX49. It only mentions `hal_vsr_table` and `hal_virtual_vector_table`, still no load address.

```
// MLT linker script for MIPS TX49
/* this version for ROM startup */ 


     .rom_vectors _vma_: _lma_ \ 
    {KEEP (*(.reset_vector)) \ 
    . = ALIGN( 0x200 ); KEEP (*(.utlb_vector) ) \ 
    . = ALIGN( 0x100 );. =. + 4 ; \ 
    . = ALIGN( 0x80 ); KEEP(*(.other_vector)) \ 
    . = ALIGN( 0x100 ); KEEP(*(.debug_vector))} \ 
    > _region_

// 0-0x200 reserved for vectors
 hal_vsr_table = 0x80000200 ; 
hal_virtual_vector_table = 0x80000300 ;

// search results 
// packages/hal/mips/idt79s334a/current/include/pkgconf/mlt_mips_idt32334_refidt334_rom.ldi
 SECTION_rom_vectors (rom, 0x80200000 , LMA_EQ_VMA) 
// snip
```

## Finding Load Address from Hardware Specs

If you know the exact chip model and version your firmware runs on, it usually is possible to obtain the load address from the corresponding datasheet or manual.

The example below shows the memory mapping for STM32 chips:

![stm32_memory_layout]({{site.url}}/assets/stm32_memory_layout.png)

In addition, for some ARM architectures, the load address can also be speculated through the interrupt vector table. The first two items in the interrupt vector table are respectively the Initial SP value and Reset, where Reset is the reset routine address, which will be executed when the device is powered on/reset, and the possible load address can be estimated based on this address.

<!--In the used cores, an ARM Cortex-M3, the boot process is build around the reset exception. At device boot or reboot the core assumes the vector table at 0x0000.0000. The vector table contains exception routines and the initial value of the stack pointer. On power-on now the microcontroller first loads the initial stack pointer from 0x0000.0000 and then address of the reset vector (0x0000.0004) into the program counter register (R15). The execution continues at this address.-->

Source: [https://blog.3or.de/starting-embedded-reverse-engineering-freertos-libopencm3-on-stm32f103c8t6.html](https://blog.3or.de/starting-embedded-reverse-engineering-freertos-libopencm3-on-stm32f103c8t6.html
)

![arm_vector_table]({{site.url}}/assets/arm_vector_table.png)

Source: [https://developer.arm.com/documentation/dui0552/a/the-cortex-m3-processor/exception-model/vector-table]([https://developer.arm.com/documentation/dui0552/a/the-cortex-m3-processor/exception-model/vector-table)

When there is no corresponding chip datasheet or sdk manuals, you can try to start from the firmware itself and infer the possible load addresses by analyzing some features in the firmware.

For example, [Magpie](https://www.anquanke.com/post/id/198276) does this by identifying the ARM entry table in the firmware, and then guessing the possible load base address based on the addresses in the function entry table.

Another method we saw in [this piece](https://limkopi.me/analysing-sj4000s-firmware/) tries to find fixed addresses within the firmware and derive the load address from it.

## Analysis of eCos firmware loading address

By searching for the "eCos kernel exception handler" string within binwalk source code, we identified the corresponding [magic](https://github.com/ReFirmLabs/binwalk/blob/master/src/binwalk/magic/ecos). The matching section is reproduced below.

```
# eCos kernel exception handlers 
# 
# mfc0 $k0, Cause # Cause of last exception 
# nop # Some versions of eCos omit the nop 
# andi $k0, 0x7F 
# li $k1, 0xXXXXXXXX 
# add $k1, $k0 
# lw $k1 , 0($k1) 
# jr $k1 
# nop 
0 string \x00\x68\x1A\x40\x00\x00\x00\x00\x7F\x00\x5A\x33 eCos kernel exception handler, architecture: MIPSEL, 
>14 leshort !0x3C1B {invalid} 
>18 leshort !0x277B {invalid} 
>12 uleshort x exception vector table base address: 0x%.4X
>16 uleshort x \b%.4X
```

We then checked if we could find the matched section within the firmware with IDA. We loaded the file with the architecture set to MIPSLE and a load address of `0x80000000`.

We then click on Make Code and saw the familiar eCos kernel exception handler with the 0x80000200 fixed address.

Because the firmware file is a bit large (approximately 10MB), it takes a lot of effort to guess the load address based on a single address:

1.  complete analysis is time-consuming (about a few minutes), and to guess multiple addresses, the firmware needs to be analyzed several times;
2. It is also troublesome to manually confirm whether the recognized functions and string cross-references are correct (may include hundreds of functions and string cross-references).

Therefore, it is necessary to find more fixed addresses and more regular addresses to determine the range of the load address.

```
ROM:80000000 # Segment type: Pure code 
ROM:80000000 .text # ROM 
ROM:80000000 mfc0 $k0, Cause # Cause of last exception 
ROM: 80000004 nop 
ROM: 80000008 andi $k0, 0x7F 
ROM: 8000000C li $k1, unk_80000200 
ROM :80000014 add $k1, $k0 
ROM: 80000018 lw $k1, 0($k1) 
ROM: 8000001C jr $k1 
ROM: 80000020 nop
```

Using Hex View I quickly browsed through the firmware and found some regular content, as seen below. Among them, there are some continuous content (in units of 4 bytes), the last 2 bytes of which are the same. Opening up the same sections with IDA View, we see these address either points to code function prologues (for jump instructions) or strings (for string cross-reference). Since the load address is incorrect at this time, the string reference is strange.

![hex_addr_pattern]({{site.url}}/assets/hex_addr_pattern.png)

According to the above rules, all fixed addresses can be extracted from the firmware file. This method helps reducing the potential range of load addresses, and once we got a candidate, we can determine whether it is correct by verifying cross-references soundness.

Magpie determines whether the load address is correct according to whether the code fragment address reference is a function's prologue. Since there are many different instructions set possibilities for a function prologue, we preferred to rely on a simpler method: judge whether a string cross-reference is correct.

For this eCos firmware, the method to determine its load address is as follows:

(1) Using 4 bytes as the unit, judge whether the low/high 2 bytes of the adjacent content are the same, and extract all fixed addresses in the firmware that conforms to this rule. Taking endianness into account, it is judged whether the content in the adjacent light blue box (or red box) is the same.

![hex_search_pattern]({{site.url}}/assets/hex_search_pattern.png)

(2) Once all fixed addresses have been extracted, we filter out illegal addresses and then sort the remaining ones. The first address in the sorted result is the upper limit of the load address range. At the same time, the first half of the sorted result is the address pointing to the code fragment, and the second half is the address pointing to the string. Choose an address from it, and separate the address that points to the string from the address that points to the code. After that, a certain number of addresses are randomly selected from the string address list as the basis for subsequent checks.

(3) We cycle through the derived load addresses range. For each load address candidate, we judge whether the string pointed to by each string reference address selected before is "correct". The load address with the most "hits" corresponding to the string address is most likely the *actual* load address.

A technique to check if a string cross-reference is right is to verify that it points to the beginning of a string. One trick to verify that is to check if the previous byte is '\x00', indicating the end of the previous string. Of course, there's some string reference addresses that point to the middle of a complete string ("string multiplexing"), but most of the addresses still points to the beginning of the complete string.

According to the above ideas, it is inferred that the eCos loading address of the firmware is 0x80040000.

```
python find_ecos_load_addr.py 
--snip--
[+] Top 10 string hit count ... 
load_base: 0x80040000, str_hit_count: 19 
load_base: 0x80019a30, str_hit_count: 11 
load_base: 0x800225a0, str_hit_count: 11 
load_base: 0x80041cd0, str_hit_count: 11 
load_base: 0x800442d0, str_hit_count: 11 
load_base: 0x80019680, str_hit_count: 10 
load_base: 0x80019940, str_hit_count: 10 
load_base: 0x80019af0, str_hit_count: 10 
load_base: 0x80026090, str_hit_count: 10 
load_base: 0x80008b90, str_hit_count: 9
[+] Possible load_base: 0x80040000
```

You can find the script on Github at [https://gist.github.com/cq674350529/74e5b6d31780882c54c80302172ad753](https://gist.github.com/cq674350529/74e5b6d31780882c54c80302172ad753).

## Fixing binwalk

Once we set the correct load address in IDA, the VSR initialization code is found at the beginning of the binary:

```
.text:80040118 li $gp, 0x809A1140 
.text:80040120 li $a0, 0x8099B7D0 
.text:80040128 move $sp, $a0 
.text:8004012C li $v0, loc_80040224 
.text:80040134 li $v1, 0x80000200 
.text:8004013C sw $v0, 4($v1) 
.text:80040140 sw $v0, 8($v1) 
.text:80040144 sw $v0, 0xC($v1) 
.text:80040148 sw $v0, 0x10($v1) 
.text :8004014C sw $v0, 0x14($v1) 
.text:80040150 sw $v0, 0x18($v1) 
.text:80040154 sw $v0, 0x1C($v1) 
.text:80040158 sw $v0, 0x20($v1)
.text:8004015C sw $v0, 0x24($v1) 
```

The value put into $v1 corresponds to the hal_vsr_table address while the value put into $v0 corresponds to the default exception vector table. Based on the value of $v0, we may estimate the load address when considering address alignment.

```
# mips cpu After the exception/interrupt is generated, the cpu will jump to a few specific addresses, 
# BEV=0, generally at 0x80000180, of course there are some other addresses, for details, please see mips books 
# Here is such a code 
FUNC_START(other_vector) 
    mfc0 k0,cause # K0 = exception cause 
    nop 
    andi k0,k0,0x7F # isolate exception code 
    la k1,hal_vsr_table # address of VSR table 
    add k1,k1,k0 # offset of VSR entry 
    lw k1,0(k1 ) # k1 = pointer to VSR 
    jr k1 # go there 
    nop # (delay slot) 
FUNC_END(other_vector)

# Take out the exception ExcCode from the cause, and then go to hal_vsr_table to take the corresponding processing vsr, the content of hal_vsr_table is filled by hal_mon_init

	.macro hal_mon_init 
	la a0,__default_interrupt_vsr 
	la a1,__default_exception_vsr # <=== 
	la a3,hal_vsr_table # <=== 
	sw a0,0(a3) 
	sw a1,1*4(a3) 
	sw a1,2*4(a3) 
	sw a1,3*4(a3) 
	sw a1,4*4(a3) 
	sw a1,5*4(a3) 
	sw a1,6*4(a3) 
	sw a1,7*4(a3) 
    sw a1,8* 4(a3) 
	# ... 
    .endm 
# Filled here are __default_interrupt_vsr and __default_exception_vsr, 
# ExcCode=0 is interrupt, and the others are exceptions, which means that an interrupt will call __default_interrupt_vsr, and an exception will be called __default_exception_vsr.
```

According to the code features mentioned above, we can define a binwalk matching rule that will output those values when scanning an eCos firmware file.

```
binwalk RGS200-12P.bin 

DECIMAL HEXADECIMAL DESCRIPTION 
----------------------------------------------- --------------------------------- 
0 0x0 eCos kernel exception handler, architecture: MIPSEL, exception vector table base address: 0x80000200 
128 0x80 eCos kernel exception handler, architecture: MIPSEL, exception vector table base address: 0x80000200 
300 0x12C eCos vector table initialization handler, architecture: MIPSEL, default exception vector table base address: 0x80040224, hal_vsr_table base address: 0x80000200 
--snip--
```

We sent a [pull request](https://github.com/ReFirmLabs/binwalk/pull/520) to binwalk with our new matching rules for eCos.

## Other

### Automatic Analysis

Even when we set the correct architecture and load address, IDA would not automatically analyze the binary. In contrast, Ghidra immediately analyzed it and successfully identified the functions and established strings cross-references. To execute analysis with IDA, you need to manually click on 'Make Code'. To make analysis automatic with IDA, one would need to write an eCos loader plugin.

### Function Name Recovery

eCos firmware files do not have import/export tables or debug symbols so it is impossible to distinguish common system functions, such as memcpy(), strcpy(), etc. However, we found out that Zyxel firmwares are quite verbose and usually contains debug logs indicating the currently called function. We can take advantage of it to manually rename functions.

![function_name_recover_sample]({{site.url}}/assets/function_name_recover_sample.png)

### Function Calling Convention

The common function calling conventions for MIPS32 is the O32 ABI: $a0-$a3 registers are used for function parameter transfer, redundant parameters are passed through the stack, and the return value is stored in the $v0-$v1 registers.

The tested eCos firmware follows the [N32 ABI](https://en.wikipedia.org/wiki/MIPS_architecture#Calling_conventions). The biggest difference is that the $a0-$a7 registers are used for function parameter transfer (corresponding in O32 ABI to $a0-$a3, $t0-$t3).

![mips_n32_call_convention_sample]({{site.url}}/assets/mips_n32_call_convention_sample.png)

IDA supports changing the ABI mode in the processor options, but only modifying this parameter does not seem to work. To make it work, you also need to set the compiler and its ABI name.

![ida_processor_compiler_option]({{site.url}}/assets/ida_processor_compiler_option.png)


## Conclusion

Over the course of this article we went over different methodologies used to identify load addresses of raw binary firmwares. We devised a way to find the load address of an eCos firmware file from Zyxel, wrote a proof-of-concept and demonstrated that it works.

As a byproduct, we also enhanced binwalk pattern matching capabilities for eCos and documented how to properly load these firmware images in IDA and Ghidra.

The proof-of-concept code can be found at [https://gist.github.com/cq674350529/74e5b6d31780882c54c80302172ad753](https://gist.github.com/cq674350529/74e5b6d31780882c54c80302172ad753)

## References

- [ecos vector.S analysis II: exception/interrupt](https://blog.csdn.net/qq_20405005/article/details/77971929)
- [Starting Embedded Reverse Engineering: FreeRTOS, libopencm3 on STM32F103C8T6](https://blog.3or.de/starting-embedded-reverse-engineering-freertos-libopencm3-on-stm32f103c8t6.html)
- [Magpie: ARM firmware base address location tool development](https://www.anquanke.com/post/id/198276)
- [limkopi.me: Analysing SJ4000's firmware](https://limkopi.me/analysing-sj4000s-firmware/)
- [MIPS calling conventions](https://en.wikipedia.org/wiki/MIPS_architecture#Calling_conventions)

## Editor's Note

While bruteforcing load address range and validating load address candidates by checking cross-references to strings or function prologues is not a new idea (see [rbasefind](https://github.com/sgayou/rbasefind), [basefind.py](https://github.com/mncoppola/ws30/blob/master/basefind.py), and [basefind.cpp](https://github.com/mncoppola/ws30/blob/master/basefind.cpp)), the article is interesting in that we can observe cq674350529 thought process when trying to find a way to rapidly find the Zyxel firmware load address.

They made two additions to eCos research: better binwalk matching rules, and identifying the right calling convention for eCos on MIPS (I described this calling convention in [Broadcom eCos Reversing the OS Memory Layout]({{site.url}}/2021/03/10/ecos-memory-layout), but didn't know at the time it was the N32 ABI). 

For those interested in the subject, here is how basefind works against the Zyxel firmware: 

```
time python basefind.py --min_addr 0x80000000 --max_addr 0x800f0000 RGS200-12P.bin
Scanning binary for strings...
Total strings found: 36491
Scanning binary for pointers...
Total pointers found: 589161
Trying base address 0x80000000
--snip--
Top 20 base address candidates:
0x80040000	17906
0x80048000	7031
0x8004b000	6858
0x80034000	6771
0x80032000	6629
0x8003d000	6612
0x80071000	6557
0x80060000	6521
0x8004c000	6486
0x80009000	6435
0x8005e000	6418
0x80028000	6411
0x8000b000	6390
0x80057000	6390
0x80003000	6356
0x8002a000	6353
0x80079000	6234
0x8002f000	6116
0x80014000	6111
0x8000d000	6071
python basefind.py --min_addr 0x80000000 --max_addr 0x800f0000 RGS200-12P.bin  17,00s user 1,25s system 99% cpu 18,254 total
```

While translating this piece, all I could think about was that there must be an even easier way to derive the load address using either the content of interrupt and exception handlers, or their relative offsets. We cannot rely on the reset function given that it simply jumps to the MIPS reset vector at 0xbfc00000, and while addresses of initialization functions such as `hal_if_init` are static accross firmwares of the same brand/constructor (e.g. Broadcom eCos), they're clearly not when you start comparing vendors. This means we cannot derive the load address by simply looking at known functions offsets.

For the time being, the bruteforce technique is the way to go if you don't know your eCos firmware load address.



