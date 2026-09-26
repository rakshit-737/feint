# ADR 0001: Domain constraints as declarative feature-space schemas

- Status: accepted
- Date: 2026-09-26

## Context

Textbook adversarial evaluations of network IDSs perturb every feature freely, producing
flows with negative packet counts, server replies the attacker cannot forge, or a
"mean packet size" inconsistent with bytes / packets. Those numbers overstate the attacker.
The alternative, *problem-space* attacks (rewrite pcaps, replay, re-run CICFlowMeter), is
faithful but slow and ties the study to one feature extractor.

## Decision

Model the attacker in feature space with a per-dataset `Schema` (`feint/schema.py`) that
declares one role per feature:

| role | meaning | CIC-IDS2017 | UNSW-NB15 |
| --- | --- | --- | --- |
| `up` | attacker may only increase (delay, add packets, pad) | duration, fwd_pkts, fwd_bytes, fwd_pkt_len_max | dur, spkts, sbytes |
| `free` | attacker sets any value in a range | init_win_fwd in [0, 65535] | sttl in [1, 255], swin in [0, 255] |
| `integer` | stays integral | fwd_pkts | spkts |
| `derived` | recomputed from base features, never set | mean_iat, fwd_bpp, pkt_ratio, bytes_per_s | smean, dmean, sload, dload, rate, sinpkt |
| fixed | everything else (server side, protocol-bound, context) | bwd_*, syn_count, dst_port, init_win_bwd | dpkts, dbytes, dttl, dwin, trans_depth, ct_*, proto_* |

Cross-feature `relations` add, for CIC, `fwd_bytes <= fwd_pkts * MTU` and
`mean <= fwd_pkt_len_max <= min(fwd_bytes, MTU)`; for UNSW, every added packet carries at
least 40 header bytes and at most an MTU. `project()` maps any perturbed matrix onto the
realisable set, `is_valid()` checks it, every constrained attack projects after every step,
and the tests assert 100 % validity.

Derived features are *recomputed on load* for clean data too, so clean and adversarial flows
obey the same equations (for UNSW-NB15 the recomputed values match the published columns to
about 1e-6).

## Consequences

- Robust features (`Schema.robust_features()`) fall out automatically: features that neither
  the attacker nor any derivation from attacker-controlled features can move. They drive the
  robust-feature model and the poisoning sanitiser.
- The model is an approximation. It ignores, for example, that adding packets also lengthens
  duration, that `ct_*` context counters depend on the attacker's connection rate, and that
  some attacks (DoS) *need* their volume, so padding may defeat the attack's purpose. These
  are listed as limitations. The schema errs toward giving the attacker slightly *more* power.
- New datasets need a new schema; attack and hardening code is schema-agnostic.
