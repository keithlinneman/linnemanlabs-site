---
title: "Application Provenance"
description: "Build provenance and attestations for the LinnemanLabs web server binary"
type: "provenance"
layout: "app"
---

Provenance for the currently running server binary - source information, build attestations, vulnerability scans, SBOMs, licensing, and container metadata. The application is a custom Go binary built with security and observability as primary concerns.

Source: [linnemanlabs-web on GitHub](https://github.com/keithlinneman/linnemanlabs-web)

Source: [build-system on GitHub](https://github.com/keithlinneman/build-system)

This page currently covers application-level provenance. I'm working toward extending attestations down through the full trust hierarchy - OS-level integrity (IMA/EVM), dm-verity verified filesystems, kernel lockdown, UEFI Secure Boot, and TPM-based hardware attestation - so that every layer is cryptographically anchored to the one below it.