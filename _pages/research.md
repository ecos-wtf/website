---
layout: page
title: Research
---

# Research

Existing tooling, source code, vulnerability reports, logs, and overall research products I found online. Definitely not exhaustive.

!["Tor825, High Heaton Library, Newcastle upon Tyne" by Newcastle Libraries is marked under CC0 1.0. To view the terms, visit https://creativecommons.org/licenses/cc0/1.0/]({{site.url}}/assets/tor825_high_heaton_library_newcastle_upon_tyne.jpg)

You think it's missing something ? Drop me an [email]({{site.url}}/about) and I'll do my best to update it.

### Books

- ["Embedded Software Development with eCos"](https://www.amazon.com/Embedded-Software-Development-Anthony-2002-12-05/dp/B01FKUUW2A) by Anthony J. Massa - Nice book but only goes over the eCOS documentation without providing actual guidance.

### Tools

- bcm2-utils - [https://github.com/jclehner/bcm2-utils/](https://github.com/jclehner/bcm2-utils/)
- Broadcom open source - [https://github.com/Broadcom/aeolus](https://github.com/Broadcom/aeolus)

### Source Code

- eCOS source - [https://ecos.sourceware.org/getstart.html](https://ecos.sourceware.org/getstart.html)
- Netgear eCOS source - [https://kb.netgear.com/2649/NETGEAR-Open-Source-Code-for-Programmers-GPL](https://kb.netgear.com/2649/NETGEAR-Open-Source-Code-for-Programmers-GPL)
- Technicolor eCOS source (BFC 5.5.10)- [https://github.com/tch-opensrc/TC72XX_BFC5.5.10mp1_OpenSrc](https://github.com/tch-opensrc/TC72XX_BFC5.5.10mp1_OpenSrc) 
- Technicolor eCOS source (BFC 5.7.1) - [https://github.com/tch-opensrc/TC72XX_BFC5.7.1mp1_OpenSrc](https://github.com/tch-opensrc/TC72XX_BFC5.7.1mp1_OpenSrc)

### Vulnerability Reports

The infamous cable haunt:

- _"Vulnerability Report: Broadcom chip based cable modems"_ by **Lyrebirds** - [https://cablehaunt.com/](https://cablehaunt.com/)
- _"Identifying the Cable Haunt Vulnerability Using the Centrifuge Platform"_ by **refirmlabs** - [https://www.refirmlabs.com/identifying-the-cable-haunt-vulnerability/](https://www.refirmlabs.com/identifying-the-cable-haunt-vulnerability/)

Pre-shared key derivation from known data is always a bad idea:

- _"Reversing Kablonet WiFi Password generation on NetMASTER modems"_  by **Mustafa Dur** - [https://www.mustafadur.com/blog/kablonet/](https://www.mustafadur.com/blog/kablonet/)

People (re)-discovering overflows in eCOS based cable modems. Crash dumps but no exploit.

- Buffer overflow in Thomson, rediscovered in 2017 - [https://research.kudelskisecurity.com/2017/01/06/do-not-create-a-backdoor-use-your-providers-one/](https://research.kudelskisecurity.com/2017/01/06/do-not-create-a-backdoor-use-your-providers-one/)
- Buffer overflow in Technicolor and Thomson circa 2014 - [https://frankowicz.me/blad-w-popularnych-routerach-od-upc-technicolor-tc7200-i-thomson-twg870-umozliwiajacy-zdalny-restart-urzadzenia/](https://frankowicz.me/blad-w-popularnych-routerach-od-upc-technicolor-tc7200-i-thomson-twg870-umozliwiajacy-zdalny-restart-urzadzenia/)
- Buffer overflow in Motorola SB5101 circa 2010 - [https://www.exploit-db.com/exploits/13775](https://www.exploit-db.com/exploits/13775)

Although not really about eCOS environment itself, this talk is an interesting introduction to how DOCSIS is actually deployed by ISPs:

- _"Beyond your cable modem"_ by **Alexander Graf** - [https://media.ccc.de/v/32c3-7133-beyond_your_cable_modem](https://media.ccc.de/v/32c3-7133-beyond_your_cable_modem)

### People dumping info online

Some interesting logs dumped by people in online forums or personal blogs. You can find more by Googling for "eCOS BFC".

- Someone discovers serial port on Netgear CG3700 - [https://forum.adsl-bc.org/viewtopic.php?f=58&t=88992](https://forum.adsl-bc.org/viewtopic.php?f=58&t=88992)
- CG3100D bootloader log - [https://www.technovelty.org/files/cg3100d/cg3100d-bootloader-ecos.txt](https://www.technovelty.org/files/cg3100d/cg3100d-bootloader-ecos.txt)
- Another spiboot log - [https://gist.github.com/yamori813/f070f4ef0d86d976fb9758dd27ddb221](https://gist.github.com/yamori813/f070f4ef0d86d976fb9758dd27ddb221)
- Cisco EPC3208G - [https://oldwiki.archive.openwrt.org/toh/cisco/epc3208g](https://oldwiki.archive.openwrt.org/toh/cisco/epc3208g)
- Cisco EPC3208G log - [https://pastebin.com/1jZQHNz4](https://pastebin.com/1jZQHNz4)
- TC7200 - [https://deviwiki.com/wiki/Technicolor_TC7200_\(Thomson\)](https://deviwiki.com/wiki/Technicolor_TC7200_\(Thomson\))
- Ubee DDW2602 - [http://en.techinfodepot.shoutwiki.com/wiki/Ubee_DDW2602](http://en.techinfodepot.shoutwiki.com/wiki/Ubee_DDW2602)
- BBox Fibre Bouygue - [https://lafibre.info/bbox-fibre/broadcom-bcm-3380/](https://lafibre.info/bbox-fibre/broadcom-bcm-3380/) and [https://lafibre.info/images/bbox/201208_Bbox_fibre_Broadcom_BCM_3380.txt](https://lafibre.info/images/bbox/201208_Bbox_fibre_Broadcom_BCM_3380.txt)

### Hacking Groups

- Cable Modem Hacking community - [http://www.haxorware.com/](http://www.haxorware.com/)

### eCOS running on ICS devices

- _"Multiple Vulnerabilities in MOXA ioLogik E1200 Series"_ by **Applied Risk** - [https://applied-risk.com/resources/multiple-vulnerabilities-in-moxa-iologik-e1200-series](https://applied-risk.com/resources/multiple-vulnerabilities-in-moxa-iologik-e1200-series)
- Interesting research on injecting GDB stubs in eCOS firmware for what appears to be MOXA firmware builds - [https://github.com/robidev/ecos_gdb](https://github.com/robidev/ecos_gdb)
