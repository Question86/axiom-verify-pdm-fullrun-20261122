# AXIOM predictive maintenance verification · 22 November 2026

Two original browser submissions completed the native AXIOM predictive maintenance path on 22 November 2026. This repository gives a reviewer the evidence needed to check both runs and compare them with the [published June synthetic run](https://github.com/Question86/axiom-verify-controlled-fullrun-20260616T201455/tree/3a17ec5ec85487bf6bd79291b58fd3c8cb5dab90).

## Verify

Clone this repository and run from its root with Python 3.9 or later.

```sh
python verify.py
python verify.py --json
```

The first command prints the comparison for a human reader. The second returns the reference and both November runs as JSON, with exit code 0 on success and 1 on failure. The default check uses the standard library and does not contact a service or execute an AXIOM binary.

| Evidence | June synthetic baseline | November CSV | November MAT |
| --- | --- | --- | --- |
| Source | Controlled synthetic CSV | CWRU 105, samples `[4096, 8192)`, DE and FE | CWRU 105, full record, BA, DE and FE |
| Samples per channel | 65,536 | 4,096 | 121,265 |
| Technical closure | `COMPLETED` | `COMPLETED` | `COMPLETED` |
| Result | `REGION_DETECTED` | `REGION_DETECTED` | `INCONCLUSIVE` · sensitivity conflict |
| Recorded tail probabilities | `1/129`, June detector calibration | `1/2001` primary · `1/129` sensitivity | `27/2001` primary · `10/129` sensitivity |
| Recorded C++ / Python / CUDA comparison | `PASS` | `PASS` | `PASS` |
| Native runner wall time | Unrecorded | 81.887 s | 477.038 s |
| Commercial release | Outside the June comparison | Closed | Closed |

The November cases overlap in source samples and use different channel sets and search families. They are two reference executions of one lane. The comparison shows how the evidence and decision rules behave across the published runs. The observations do not estimate accuracy, relative runtime performance, or field failure rates.

## What the verifier checks

- Rehashes the exact public evidence set and rejects changes, missing files or additional files under `evidence/`.
- Binds native job and run IDs across closure, hash chain, parity, reliability and billing. Checks that the runner inventory contains the raw SHA-256 of the closure file. The runner durations and original invocation references are published as a separate projection in each `run.json`.
- Reconstructs all 59 stage hashes and the final chain hash for each completed November run. The seed is `deterministic_run_id` for the first stage, followed by the preceding stage hash for each subsequent stage. The stage digest hashes the UTF-8 seed followed by canonical JSON with `stage_chain_hash` removed. The final digest hashes the canonical ordered list of the 59 digests. Canonical JSON here uses sorted keys, compact separators and UTF-8.
- Rehashes 13 present payloads against each 14-entry signed subject, verifies the subject and public key digests, and checks the recorded native CUDA contract and C++/Python/CUDA comparison. One original API contract report per run remains outside the public bundle because it contains account-specific identifiers. Its digest is still part of the signed subject.
- Recounts the stored 2,000 primary and 128 sensitivity null maxima. The add-one tail fractions and the prespecified `alpha = 0.05` decision rule yield the recorded result, including the MAT sensitivity conflict.
- Checks that the two executions were registered computations with release, billing and paid artifact export disabled. The computational result and these commercial controls are separately visible.

## Additional checks

To independently verify each ECDSA P-256 signature against the supplied public key:

```sh
python -m pip install cryptography
python verify.py --verify-signatures --json
```

You can also reconstruct the observed statistic from the publisher's [CWRU 105.mat](https://engineering.case.edu/sites/default/files/105.mat) file (inner-race `IR007_0` on the [CWRU data page](https://engineering.case.edu/bearingdatacenter/12k-drive-end-bearing-fault-data)). The script checks the file hash, uses the recorded channels and sample selection, and checks the winning window and the observed score with an independently implemented CPU calculation.

```sh
python -m pip install numpy scipy
python recompute_observed.py /path/to/105.mat
```

For a fresh independent check of June, clone the linked repository, check out the commit in [baseline.json](baseline.json), and run its `python verify.py`. The November verifier reads that pinned comparison snapshot locally.

## Evidence boundaries

The files under `evidence/csv/` and `evidence/mat/` are selected byte-preserved native artifacts, plus the separately labelled `run.json` projections. The public set excludes the full runtime exports, private browser and machine paths, and original source bytes. Go to CWRU for the source measurement. The signature check validates the signed subject against the bundled key. Its scope is cryptographic consistency under that key.

The triple-parity files concern the recorded parity inputs and final arithmetic. The optional CPU command reconstructs the observed score and recounts stored null maxima. A fresh generation of the primary and IAAFT surrogates, a new GPU execution, and assessment of detector performance on independent machines are separate checks.

Start with [the CSV closure](evidence/csv/proof/a_to_j_runtime_closure_report.json), [the MAT closure](evidence/mat/proof/a_to_j_runtime_closure_report.json), or the [file checksum inventory](checksums.sha256).
