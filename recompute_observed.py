#!/usr/bin/env python3
"""Recompute the observed PdM statistic from the publisher's CWRU 105.mat file."""

import argparse
import math
from pathlib import Path
import sys

from verify import ROOT, load, require, sha256, tail, verify_bundle

WINDOW = 512
STRIDE = 256


def observed_windows(values, np, hilbert):
    scores = []
    for start in range(0, len(values) - WINDOW + 1, STRIDE):
        window = values[start : start + WINDOW]
        envelope = np.abs(hilbert(window - window.mean(axis=0), axis=0)) ** 2
        power = np.abs(np.fft.rfft(envelope - envelope.mean(axis=0), axis=0)[1:]) ** 2
        channel_power = power.sum(axis=0)
        require((channel_power > 0).all(), "Degenerate channel spectrum")
        scores.append(float((power / channel_power).max(axis=0).mean()))
    winner = max(range(len(scores)), key=scores.__getitem__)
    return winner, scores[winner], len(scores)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_mat", type=Path, help="The original 105.mat from CWRU")
    args = parser.parse_args()
    try:
        import numpy as np
        from scipy.io import loadmat
        from scipy.signal import hilbert

        verify_bundle()
        evidence = ROOT / "evidence"
        require(sha256(args.input_mat) == load(evidence / "mat/run.json")["source"]["sha256"],
                "The provided file is not byte-identical to the MAT input used in the run")
        raw = loadmat(args.input_mat)
        for label in ("csv", "mat"):
            root = evidence / label
            source = load(root / "run.json")["source"]
            start, end = source["source_sample_range"]
            channels = [raw[f"X105_{channel}_time"].ravel() for channel in source["channels"]]
            values = np.column_stack(channels)[start:end]
            require(len(values) == source["sample_count"] and np.isfinite(values).all(), "Source sample bounds or values")
            winner, score, windows = observed_windows(values, np, hilbert)
            primary = load(root / "scientific_nulls/pdm_primary_distribution_v2.json")
            sensitivity = load(root / "scientific_nulls/pdm_grouped_sensitivity_result_v2.json")
            require(winner == primary["observed_winner_ordinal"]
                    and math.isclose(score, primary["observed_maximum"], rel_tol=1e-12, abs_tol=1e-14),
                    f"{label}: observed winner or score differs")
            p = tail(primary, score, 2000)
            s = tail(sensitivity, score, 128)
            print(f"{label.upper()}: {windows} windows; winner {winner}; "
                  f"observed statistic {score:.16g}; stored-null recount {p[0]}/{p[1]}, {s[0]}/{s[1]}")
    except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
        print(f"RESULT: FAIL ({exc})", file=sys.stderr)
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
