---
title: "Application Provenance"
description: "Build provenance and attestations for the LinnemanLabs web server binary"
type: "provenance"
layout: "app"
---

The application server is a custom Go binary built with security and observability as first-class concerns.

You can view the full application source code for [linnemanlabs-web on Github](https://github.com/keithlinneman/linnemanlabs-web)

This page displays provenance information for the currently running server binary, including source information, build attestations, vulnerability scans, SBOMs, licensing and container metadata.

In the future, this page will expand to include attestations across the full trust hierarchy, from Layer 7 application self-verification down through OS-enforced signed execution (IMA/EVM), dm-verity verified filesystems on golden images, kernel lockdown mode, UEFI Secure Boot, and TPM-based hardware attestation. The goal is a verifiable chain from the hardware root of trust to the running application establishing cryptographic proof from silicon to application with all of the code open-sourced along the way.