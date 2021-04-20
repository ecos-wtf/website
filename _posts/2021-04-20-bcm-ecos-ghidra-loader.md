---
layout: post
title: Broadcom eCos | Ghidra Loader Release
description: We're releasing a custom Ghidra loader for Broadcom's ProgramStore firmware format.
summary: We're releasing a custom Ghidra loader for Broadcom's ProgramStore firmware format.
date:   2021-04-20 09:00:00
image: assets/programstore-loader-ghidra.png
tags: [ecos, ghidra]
---

We've released a Broadcom ProgramStore firmware image loader for Ghidra (9.1.2 and 9.2).

{:.foo}
![import dialog]({{site.url}}/assets/programstore-loader-ghidra.png)

This loader will auto-detect ProgramStore firmware images from their header and display header information in a dialog box. On load, it takes care of decompressing the raw binary and loads both .text and .data sections.

Ready-to-use extensions can be found in the [releases](https://github.com/ecos-wtf/programstore-loader/releases) section, while source code is available at [https://github.com/ecos- wtf/programstore-loader](https://github.com/ecos- wtf/programstore-loader).
