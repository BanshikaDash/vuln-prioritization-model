"""
Score the baselines on dataset.csv (or any CSV with a `label` column).

    python evaluate_baselines.py dataset.csv
    python evaluate_baselines.py dataset.csv --scores cvss_base epss paper_score ml_score

Metrics (higher is better for all):
  AP         average precision (area under the precision-recall curve)
  recall@k%  share of truly exploited CVEs found in the top k% of the ranking
  lift@5%    recall@5% divided by 5% (1.0 = no better than random)
Ties are broken at random (average of 5 shuffles) so coarse scores like CVSS
are not helped or hurt by row order.
"""
import argparse
import csv
import math
import random


def _ranked(labels, scores, seed):
    idx = list(range(len(labels)))
    random.Random(seed).shuffle(idx)
    idx.sort(key=lambda i: -scores[i])  # stable: the shuffle decides ties
    return [labels[i] for i in idx]


def average_precision(labels, scores, seeds=5):
    total = sum(labels)
    if total == 0:
        return float("nan")
    vals = []
    for s in range(seeds):
        hits = ap = 0
        for rank, y in enumerate(_ranked(labels, scores, s), 1):
            if y:
                hits += 1
                ap += hits / rank
        vals.append(ap / total)
    return sum(vals) / len(vals)


def recall_at(labels, scores, frac, seeds=5):
    total = sum(labels)
    if total == 0:
        return float("nan")
    k = max(1, math.ceil(frac * len(labels)))
    return sum(sum(_ranked(labels, scores, s)[:k]) / total for s in range(seeds)) / seeds


def evaluate(labels, scores_by_name):
    out = {}
    for name, sc in scores_by_name.items():
        r5 = recall_at(labels, sc, 0.05)
        out[name] = {
            "AP": average_precision(labels, sc),
            "recall@1%": recall_at(labels, sc, 0.01),
            "recall@5%": r5,
            "recall@10%": recall_at(labels, sc, 0.10),
            "lift@5%": r5 / 0.05,
        }
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv_in")
    ap.add_argument("--scores", nargs="+", default=["cvss_base", "epss", "paper_score"])
    args = ap.parse_args(argv)

    with open(args.csv_in, newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f)]
    rows = [r for r in rows if all(r.get(c) not in (None, "") for c in args.scores)]
    labels = [int(r["label"]) for r in rows]
    scores = {c: [float(r[c]) for r in rows] for c in args.scores}
    n, pos = len(labels), sum(labels)
    print(f"{n} CVEs, {pos} exploited in the window ({100 * pos / n:.2f}%)\n")
    res = evaluate(labels, scores)
    cols = ["AP", "recall@1%", "recall@5%", "recall@10%", "lift@5%"]
    print(f"{'score':<14}" + "".join(f"{c:<12}" for c in cols))
    for name, m in res.items():
        print(f"{name:<14}" + "".join(f"{m[c]:<12.3f}" for c in cols))
    print(f"{'random':<14}{pos / n:<12.3f}{0.01:<12.3f}{0.05:<12.3f}{0.10:<12.3f}{1.0:<12.3f}")
    return res


if __name__ == "__main__":
    main()
