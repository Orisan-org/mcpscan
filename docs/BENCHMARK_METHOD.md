# Benchmark method

## Conflict of Interest Statement

**TODO-FOUNDER before benchmark publication:** replace this subsection with the
founder's direct conflict-of-interest statement. Do not treat the scaffold below
as the final statement.

The benchmark includes `mcpscan`, which is built by Orisan. That creates an
obvious conflict of interest. This document records the controls used to make
the benchmark reproducible, reviewable, and separable from scanner marketing.

### Pre-freeze exposure

Placeholder: before label freeze, the harness was validated against
`reference_filesystem` and `reference_memory`. Those two servers' labels must
cite external maintainer documentation because they were used during harness
validation before the corpus labels were frozen.

## Preregistration

Corpus selection criteria, strata quotas, label schema, dummy credential policy,
and failure handling are defined in [CORPUS_PREREGISTRATION.md](CORPUS_PREREGISTRATION.md).

Servers must be selected from the preregistered rules before benchmark labels
are finalized. Candidate failures remain data and are not silently removed.

## Label Freeze

Before publishing benchmark scores, record the git commit hash containing the
frozen label files:

```text
label_freeze_commit: TODO
label_freeze_date: TODO
```

After freeze, label changes must be documented in the corpus changelog with:

- server id
- property id
- previous label
- new label
- rationale
- reviewer
- date

Unmapped findings trigger label review before scores are finalized. If an
unmapped finding represents a real property, update the labels. If it represents
a scanner/mapping issue, update the mapping or record the reviewed false
positive. Label changes are logged in the corpus changelog.

Scores use adjusted severity where available. A finding only enters
precision/recall when its adjusted severity is `low` or above. Scored findings
mapped to `real_threat` are true positives. Scored findings mapped to
`by_design`, `benign`, or no labeled property are false positives. A
`real_threat` property with no scored finding is a false negative. Unmapped
findings are counted pessimistically in provisional output and block
finalization until reviewed.

`real_threat_retention_rate` is computed over real-threat properties with at
least one mapped finding. Missed real-threat properties are already represented
by recall and must not be double-counted in this verdict-retention metric.

## Inter-rater Reliability

At least two reviewers should independently label a subset of servers before
benchmark publication. Record:

- reviewer handles
- server ids reviewed
- disagreement count
- final resolution

Inter-rater reliability metrics are pending until the full corpus is labeled.

## Dispute Process

Anyone can dispute a label or mapping by opening an issue with:

- server id
- property id or finding id
- proposed change
- evidence
- reproduction notes

Disputes that change labels after freeze must update the corpus changelog.

## Reproduction

Benchmark reproduction requires:

1. A clean checkout at the recorded benchmark commit.
2. A disposable container or VM with no real credentials.
3. The pinned corpus manifest.
4. The frozen label files.
5. The scoring command and generated artifacts.

Scores are provisional until `scripts/score_corpus.py --finalize` succeeds with
an empty unmapped findings queue.
