# Deployment Cost & Platform Selection

> Corrected analysis. The headline figures below are **ballparks** — cloud
> pricing changes; confirm with each provider's calculator before committing.
> The platform *compatibility* analysis is the part that matters most and is
> independent of price.

## Match the platform to the attestation the code actually uses

This repo's attestation path is the **AMD SEV-SNP guest report**:
`snp_verify.fetch_report_ioctl()` reads `/dev/sev-guest` via `ioctl(SNP_GET_REPORT)`,
and `snpguest` verifies the **VCEK → ASK → ARK** chain. That model is native on:

| Platform | TEE / attestation | Works with this repo's code? |
|:---|:---|:---|
| **GCP N2D (EPYC Milan) / C3D (Genoa)** | SEV-SNP guest report | ✅ **Primary target** — native `/dev/sev-guest` |
| **Azure DCas v5 / ECas v5** | SEV-SNP guest report | ✅ Yes (minor: endpoint/cert wiring). *More* compatible than AWS |
| **Bare-metal AMD EPYC (7003+)** | SEV-SNP guest report | ✅ Yes (you run the hypervisor) |
| **AWS m6a/c6a (Nitro)** | **Nitro NSM** (COSE/CBOR, AWS-signed) | ⚠️ **NOT** as-is — needs a separate Nitro attestation adapter |
| IBM LinuxONE | SEL / HPVS native | ✅ (enterprise mainframe; expensive) |
| OCI Ampere / standard VMs | none | ❌ no attestation |

**Common error to avoid:** AWS Nitro Enclaves ≠ AMD SEV-SNP. AWS *does* offer
SEV-SNP on some AMD instances, but its enclave/attestation story is Nitro-based
(an AWS-signed NSM document), which this repo does not verify. Treating
"AWS c6a + Nitro Enclaves" as a drop-in for the SEV-SNP path is incorrect.

## Cheapest platform that matches the code (persistent)

**GCP `n2d-standard-2`** (2 vCPU, 8 GiB, EPYC Milan), Confidential VM with
`--confidential-compute-type=SEV_SNP`:
- On-demand base ≈ **$0.071/vCPU-hr class → ~$50/mo**, less sustained-use discount.
- Confidential-VM premium is a real per-vCPU + per-GiB surcharge (~$6/mo on this size).
- **Estimated ~$45–52/mo on-demand** (verify on the GCP calculator).

Azure `DC2as v5` (2 vCPU, 8 GiB, SEV-SNP) is a comparable second choice if you
prefer Azure; budget a small amount of wiring for Azure's attestation endpoint.

AWS only becomes a valid option after a Nitro NSM attestation adapter is built;
until then its price is irrelevant for this codebase.

## Spot / preemptible — testing only

Spot SEV-SNP VMs are far cheaper (GCP N2D spot ≈ ~$10–15/mo) **but unsuitable
for persistent autonomous trading**: an interruption destroys the enclave and
forces full re-attestation **plus a Nitrokey touch** to restart — i.e. unattended
downtime and manual intervention. Use spot only for deployment testing.

## Other hard requirements
- **Nitrokey FIDO2** is the human root-of-trust and lives at the **KRS side**
  (your trusted box / a TEE), NOT in the cloud trading VM.
- The KRS itself should run in a TEE or on hardware you control, or the operator
  hosting it could snapshot its memory. See `KRS_POLICY.md`.

## Recommendation
Persistent: **GCP `n2d-standard-2`** (the platform the code targets). Confirm live
pricing on the provider calculator. Treat AWS as future work (Nitro adapter), and
never run the live trader on spot.
