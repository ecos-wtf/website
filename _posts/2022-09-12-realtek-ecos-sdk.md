---
layout: post
title: Realtek eCos SDK SIP ALG buffer overflow
description: A bug in a Realtek software development kit (SDK) means any third party devices with software that uses the SDK could inherit a vulnerability in their Session Initiation Protocol (SIP) implementations.
summary: A bug in a Realtek software development kit (SDK) means any third party devices with software that uses the SDK could inherit a vulnerability in their Session Initiation Protocol (SIP) implementations.
date:   2021-09-11 09:00:00
image: assets/faraday_sec_preso.png
tags: [ecos, realtek]
---

![logo]({{site.url}}/assets/faraday_sec_preso.png)

People from Faraday Security presented excellent research at DEFCON 30 this year on the *"hidden attack surface of OEM IoT devices"*.

Their talk discussed the different research steps they took, culminating with the discovery
and exploitation of CVE-2022-27255.

This vulnerability is a buffer overflow vulnerability affecting Realtek's eCos SDK, specifically the SIP ALG parser. It can be triggered from WAN by unauthenticated attackers using a single
UDP packet. There is no workaround except for vendors to update their Realtek's dependencies. The SIP parser is always enabled, regardless of device settings.

You can find all their research products on Github at [https://github.com/infobyte/cve-2022-27255](https://github.com/infobyte/cve-2022-27255).
