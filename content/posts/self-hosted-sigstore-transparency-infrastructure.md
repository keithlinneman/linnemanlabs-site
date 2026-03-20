---
date: '2026-03-18T00:00:00Z'
title: "Running Your Own Transparency Infrastructure with Fulcio, Rekor, TesseraCT and Timestamp-Authority"
summary: "From YubiKey CA root to trust bundles to signed artifacts - the architecture, trust decisions, and security implications behind running a self-hosted Sigstore stack."
tags: ["Supply Chain Security", "Certificate Transparency", "Sigstore", "Rekor", "TesseraCT", "Fulcio", "Rekor-Tiles", "Timestamp-Authority", "Infrastructure Security"]
categories: ["Engineering"]
---

## Background

Like most of my infrastructure projects, this started off with researching a new tool (cosign) that closes an existing gap in a robust, elegant way. That turned into researching Rekor, then Timestamp-Authority, then Fulcio, then TesseraCT. The end result is 4 new production services in my infrastructure.

## System Architecture

Fulcio is a certificate authority that issues short-lived code-signing certificates based on OIDC identity. Rekor is a transparency log that records signed artifacts and provides tamper-evident inclusion proofs. TesseraCT is a certificate transparency log that records every certificate Fulcio issues. Timestamp-Authority provides RFC 3161 signed timestamps that let verifiers confirm the signature happened during the certificate’s validity window, even after the certificate itself has expired.

<!-- mermaid chart is in content/charts/ -->
{{< imgmodal src="/img/transparency/linnemanlabs-transparency-architecture.png" alt="Diagram of LinnemanLabs Transparency Infrastructure" mode="shrink" caption="LinnemanLabs Transparency Architecture Diagram" >}}

## PKI Architecture

The Root CA private key is on an offline hardware security token (YubiKey). The Root CA cert is generated with a 10 year lifetime.

Fulcio CA and TSA signing keys are non-exportable in AWS KMS and held in a separate account exclusively used for KMS keys. All signing operations occur via cross-account KMS API calls. The certificates are generated with a 3 year lifetime.

Rekor and TesseraCT checkpoint signing keys are non-exportable in AWS KMS and similarly held in a separate account.

The root signing process and key ceremony procedures will be covered in a future post.

<!-- mermaid chart is in content/charts/ -->
{{< imgmodal src="/img/transparency/linnemanlabs-pki-architecture.png" alt="Diagram of LinnemanLabs PKI Architecture" mode="shrink" caption="LinnemanLabs PKI Architecture Diagram" >}}

In my current implementation and client/tooling tests, P256 was the only ec KMS-backed checkpoint-signing option that verified end-to-end, so I standardized on P256 for Rekor and TesseraCT checkpoints. P384 signed successfully but failed client-side verification because no note verifier type byte existed for it. Ed25519 via KMS loaded but failed to hash for note signing.

## Build Pipeline Integration

Builds are triggered by tag pushes to GitHub. The workflow requests two GitHub OIDC ID tokens (one for fulcio, one for AWS IAM) and uses them for two independent signing paths.

First, cosign requests a short-lived certificate from Fulcio using the first OIDC token with `audience=sigstore`. Fulcio verifies the token, embeds the workflow identity into the certificate's x509 extensions, logs the issuance to TesseraCT, and returns the cert. Cosign signs the artifact, requests a timestamp from Timestamp-Authority, submits for inclusion in Rekor, and writes the bundle.

Second, the workflow assumes an IAM role via the second GitHub OIDC token with `audience=sts.amazonaws.com` scoped to tagged pushes from the specific repo/ref. Using this role cosign signs the artifact using an application-specific KMS key. This produces a second independent bundle.

Both bundles are pushed alongside the artifact to S3 and ECR. The IAM role assumption is gated on an OIDC subject claim matching our repo name and `ref:refs/tags/v*`, meaning only tagged pushes can sign or push artifacts. A detailed walkthrough of how each of these gates holds up under attack is in my [modeling hackerbot-claw post](/posts/modeling-hackerbot-claw-attack-against-my-cicd-pipeline).

## Deploy Time Verification

At deploy time, two verifications must pass before a binary is configured for execution.

The KMS bundle is verified against the application-specific public key baked into the golden AMI. This confirms the artifact was signed by a key only the build pipeline can access.

The keyless bundle is verified with cosign using certificate attribute checks - OIDC issuer, certificate identity, workflow trigger, workflow name, and repository. These checks confirm the artifact was signed during a tagged push from the correct workflow/repo/ref/etc, not from a pull request or any other event type or other repository, etc. Without narrowly pinning the expected issuer and workflow identity attributes, verification can accept signatures from a much broader set of GitHub workflows than intended.

Both verifications must pass. Either one failing prevents execution and produces a log entry for investigation.

## Why I Self-Host This

This stack exists because I want to own the full chain from root CA to signed artifact to transparency log entry and have the flexibility to build whatever I want on top. The public sigstore instance is excellent and covers most use cases. Self-hosting adds operational cost but gives me independence from external availability, full control over my trust roots, and a deep understanding of every component in the signing and verification path.

While a self-hosted transparency stack may not fit everyone's threat model, I close gaps because I know from experience that gaps get found by people who weren't even looking for you specifically.

The next steps are SPIRE integration for workload identity, TUF for trust root distribution, and expanding the dual-logging to include both my own and the public sigstore transparency logs.