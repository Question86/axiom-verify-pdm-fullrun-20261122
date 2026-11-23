#!/usr/bin/env python3
"""Verify the published AXIOM PdM evidence and compare it with the June baseline."""

import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
SHA256 = re.compile(r"[0-9a-f]{64}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha256(path):
    return digest(path.read_bytes())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load(path):
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict), f"Expected a JSON object in {path.name}")
    return value


def verify_bundle():
    manifest = {}
    for line in (ROOT / "checksums.sha256").read_text(encoding="ascii").splitlines():
        expected, relative = line.split("  ", 1)
        path = Path(relative)
        require(
            SHA256.fullmatch(expected) and path.parts[:2] in {("evidence", "csv"), ("evidence", "mat")}
            and not path.is_absolute() and ".." not in path.parts and relative not in manifest,
            f"Invalid manifest entry {relative}",
        )
        manifest[relative] = expected
    files = [p for p in (ROOT / "evidence").rglob("*") if p.is_file() or p.is_symlink()]
    require(not any(p.is_symlink() for p in files), "Symbolic links in evidence")
    require({p.relative_to(ROOT).as_posix() for p in files} == set(manifest), "Evidence set differs from manifest")
    for relative, expected in manifest.items():
        require(sha256(ROOT / relative) == expected, f"File hash mismatch: {relative}")
    return len(manifest)


def verify_chain(root, chain, closure, source_hash):
    require(chain["overall_status"] == "PASS" and not chain["blocking_errors"], "Failed hash chain")
    require(sha256(root / closure["pipeline_hash_chain_ref"]) == closure["pipeline_hash_chain_artifact_hash"],
            "Closure hash-chain file binding")
    require([row["hash_value"] for row in chain["root_source_hashes"]] == [source_hash], "Source hash differs")
    seed = chain["deterministic_run_id"]
    previous = None
    hashes = []
    for index, stage in enumerate(chain["stage_records"]):
        require(stage["stage_index"] == index and stage["stage_status"] == "PASS", f"Stage {index} status or index")
        require(stage["previous_stage_chain_hash"] == previous, f"Stage {index} predecessor")
        preimage = dict(stage)
        claimed = preimage.pop("stage_chain_hash")
        previous = digest(seed.encode() + canonical(preimage))
        require(previous == claimed, f"Stage {index} hash")
        hashes.append(previous)
        seed = previous
    require(len(hashes) == 59 and digest(canonical(hashes)) == chain["final_chain_hash"], "Final chain hash")
    return len(hashes)


def verify_signature(root, omitted, check_signature):
    subject_path = root / "proof/proof_signature_subject.json"
    key_path = root / "proof/proof_signature_public_key.blob"
    meta = load(root / "proof/proof_signature_metadata.json")
    subject = load(subject_path)
    key = key_path.read_bytes()
    signed = subject["artifacts"]
    require(meta["signature_algorithm"] == "ecdsa_p256_sha256_raw_v1", "Signature algorithm")
    require(sha256(subject_path) == meta["signature_subject_file_hash"], "Signed subject file hash")
    require(digest(canonical(subject)) == meta["signature_subject_hash"], "Canonical signed subject hash")
    require(len(key) == 72 and key[:8] == b"ECS1\x20\x00\x00\x00", "P-256 public key encoding")
    require(digest(key) == meta["trusted_public_key_file_hash"] == meta["signature_key_id"], "Public key hash")
    require(len(signed) == len({row["relative_path"] for row in signed}) == 14, "Signed digest count")
    unavailable = set()
    for row in signed:
        relative = row["relative_path"]
        path = root / relative
        require(path.resolve().is_relative_to(root), "Signed path escapes evidence root")
        if relative in omitted:
            require(not path.exists(), "An excluded original has appeared in the public bundle")
            unavailable.add(relative)
        else:
            require(sha256(path) == row["sha256_hex"], f"Signed payload hash mismatch: {relative}")
    require(unavailable == {"api/canonical_jobs_api_contract_report.json"}, "Unexpected signed payload exclusion")
    if check_signature:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        raw = bytes.fromhex(meta["signature_value"])
        require(len(raw) == 64, "Raw P-256 signature length")
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + key[8:])
        der = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        try:
            public.verify(der, canonical(subject), ec.ECDSA(hashes.SHA256()))
        except Exception as exc:
            raise ValueError("ECDSA verification failed against the bundled public key") from exc
    return len(signed) - len(unavailable), subject


def tail(distribution, observed, expected_draws):
    maxima = distribution["draw_order_maxima"]
    require(distribution["requested_draw_count"] == len(maxima) == len(distribution["raw_draw_hashes"]) == expected_draws,
            "Distribution size and draw identity")
    require(all(math.isfinite(value) for value in maxima), "Non-finite null maximum")
    numerator = 1 + sum(value >= observed for value in maxima)
    denominator = len(maxima) + 1
    require((numerator, denominator) == (distribution["upper_tail_numerator"], distribution["upper_tail_denominator"]),
            "Stored tail arithmetic differs from recount")
    return numerator, denominator


def verify_run(label, check_signature):
    root = ROOT / "evidence" / label
    run = load(root / "run.json")
    closure = load(root / "proof/a_to_j_runtime_closure_report.json")
    inventory = load(root / "proof/execution_evidence_inventory.json")
    chain = load(root / "proof/pipeline_hash_chain.json")
    cuda = load(root / "qa/native_cuda_execution_contract_report.json")
    parity = load(root / "qa/signal_region_triple_parity_compare.json")
    reliability = load(root / "reliability_report.json")
    billing = load(root / "billing_integrity_gate_report.json")
    api = load(root / "api_v2/job_status_response.json")
    require(closure["status"] == "COMPLETED" and not closure["blocking_errors"], "Runtime did not complete")
    require(closure["cache_reuse_detected"] is False, "Cached runtime artifact root")
    for record in (closure, chain, cuda, parity, reliability, billing):
        require((record["run_id"], record["job_id"]) == (run["native_run_id"], run["native_job_id"]), "Native run/job identity")
    require(api["job_id"] == run["native_job_id"] and api["status"] == "COMPLETED" and api["execution_completed"],
            "API completion identity")
    require(inventory["status"] == "PASS" and inventory["owner_closure_ref"] == "proof/a_to_j_runtime_closure_report.json",
            "Process evidence inventory")
    require(inventory["owner_closure_sha256"] == sha256(root / inventory["owner_closure_ref"]), "Runner closure byte binding")
    require((root / "proof/execution_evidence_inventory.sha256").read_text().strip()
            == sha256(root / "proof/execution_evidence_inventory.json"), "Runner inventory file hash")
    recorded = {row["artifact_id"]: row["sha256"] for row in inventory["records"]}
    require(run["execution"]["original_invocation_sha256"] == recorded["execution_invocation"]
            and run["execution"]["original_stdout_sha256"] == recorded["execution_stdout"]
            and sha256(root / "proof/execution_stderr.txt") == recorded["execution_stderr"],
            "Public projection reference or stderr hash differs")
    require(run["execution"]["exit_code"] == 0 and (root / "proof/execution_stderr.txt").stat().st_size == 0,
            "Recorded process exit or stderr")
    stages = verify_chain(root, chain, closure, run["source"]["sha256"])
    signed_payloads, subject = verify_signature(root, run["omitted_signed_payloads"], check_signature)
    require((subject["run_id"], subject["job_id"]) == (run["native_run_id"], run["native_job_id"]), "Signed run identity")
    require(cuda["status"] == "PASS" and cuda["native_backend_identity"] == "native_cuda"
            and cuda["python_heavy_compute_path"] is False, "Native CUDA contract")
    mismatch = [v for k, v in parity.items() if k.endswith("_mismatch") or k.endswith("_mismatch_count")]
    require(parity["status"] == "PASS" and len(mismatch) == 10 and all(v == 0 for v in mismatch), "Triple-parity mismatch")
    for engine in ("cpp", "cuda", "python"):
        participant = load(root / f"qa/signal_region_{engine}_parity_result.json")
        name = f"{engine}_parity_result_hash"
        require(participant[name] == parity[name] and participant["status"] == "PASS"
                and participant["verdict_state"] == api["verdict_state"], f"{engine} parity participant binding")

    nulls = root / "scientific_nulls"
    decision = load(nulls / "pdm_verdict_result_v2.json")
    primary_path = nulls / "pdm_primary_distribution_v2.json"
    sensitivity_path = nulls / "pdm_grouped_sensitivity_result_v2.json"
    primary, sensitivity = load(primary_path), load(sensitivity_path)
    require(decision["primary_distribution_hash"] == sensitivity["primary_distribution_hash"] == sha256(primary_path)
            and decision["sensitivity_result_hash"] == sha256(sensitivity_path), "Distributions do not bind to verdict")
    require(decision["execution_binding_hash"] == primary["execution_binding_hash"] == sensitivity["execution_binding_hash"]
            and primary["family_hash"] == sensitivity["family_hash"], "Statistical execution or family mismatch")
    observed = primary["observed_maximum"]
    require(math.isfinite(observed), "Non-finite observed statistic")
    p, s = tail(primary, observed, 2000), tail(sensitivity, observed, 128)
    require(p == (decision["primary_p_numerator"], decision["primary_p_denominator"])
            and s == (decision["sensitivity_p_numerator"], decision["sensitivity_p_denominator"]), "Verdict tail counts")
    alpha = Fraction(decision["alpha_numerator"], decision["alpha_denominator"])
    require(alpha == Fraction(1, 20), "Decision threshold differs")
    reject_p, reject_s = Fraction(*p) <= alpha, Fraction(*s) <= alpha
    require((reject_p, reject_s) == (decision["primary_rejects_h0"], decision["sensitivity_rejects_h0"]), "Decision test flags")
    require(reject_p, "Expected a primary rejection on this reference")
    numerical = "GLOBAL_H0_REJECTED_CANDIDATE" if reject_s else "INCONCLUSIVE"
    verdict = "REGION_DETECTED" if reject_s else "INCONCLUSIVE"
    require(decision["status"] == numerical and decision["productive_authorized"] == reject_s
            and decision["conflict_status"] == ("NO_CONFLICT" if reject_s else "CONFLICT"), "Numerical decision")
    require(verdict == api["verdict_state"] == reliability["verdict_state"] == billing["verdict_state"], "Verdict projection")
    require(billing["billable"] is False and billing["execution_purpose"] == api["execution_purpose"] == "registered_computation"
            and billing["primary_failure_code"] == "BLOCK_REGISTERED_COMPUTATION_NOT_BILLABLE"
            and all(api[field] is False for field in ("billing_authorized", "customer_release_authorized", "paid_artifact_export_authorized")),
            "Commercial gate records differ")

    return {
        "case": label, "native_run_id": run["native_run_id"], "browser_job_id": run["browser_job_id"],
        "input": run["source"], "runner_seconds": run["execution"]["duration_ms"] / 1000,
        "runtime_status": closure["status"], "verdict": verdict, "primary_p": f"{p[0]}/{p[1]}",
        "sensitivity_p": f"{s[0]}/{s[1]}", "chain_stages_recomputed": stages,
        "signed_payloads_rehashed": signed_payloads, "signature_status": "VERIFIED" if check_signature else "NOT_CHECKED",
        "triple_parity": parity["status"], "billable": billing["billable"], "execution_purpose": api["execution_purpose"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Return results and comparison as JSON")
    parser.add_argument("--verify-signatures", action="store_true", help="Also verify both ECDSA signatures (requires cryptography)")
    args = parser.parse_args()
    try:
        count = verify_bundle()
        baseline = load(ROOT / "baseline.json")
        runs = [verify_run(label, args.verify_signatures) for label in ("csv", "mat")]
    except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
        if args.json:
            print(json.dumps({"status": "FAIL", "error": str(exc)}))
        else:
            print(f"RESULT: FAIL ({exc})", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"status": "PASS", "evidence_files": count, "baseline": baseline, "runs": runs}, indent=2))
    else:
        print(f"{count} evidence files checked. Stage hashes, signed artifacts and decision arithmetic matched.")
        print(f"June baseline: {baseline['verdict']} ({baseline['reported_p']}), {baseline['input_kind']}")
        for run in runs:
            print(f"{run['case'].upper()}: {run['verdict']}, primary {run['primary_p']}, sensitivity {run['sensitivity_p']}, "
                  f"{run['runner_seconds']:.3f}s runner time, billing closed")
        print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
