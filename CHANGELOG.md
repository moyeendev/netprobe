# Changelog

All notable changes are recorded here. The project follows semantic versioning.

## [Unreleased]

## [0.1.0] - 2026-11-20

First public release.

### Added
- Unified record schema and session clock: every probe emits through one `Session`, stamped
  with session-relative monotonic time; wall time derived from a single anchor; drift recorded
  in the run manifest.
- Probes: delay (UDP echo, TCP connect, ICMP; RFC 3550 jitter), bandwidth (TCP with
  `TCP_INFO` sampling and optional pacing), stress (token-bucket UDP, safety-gated), sniff
  (`AF_PACKET`/scapy capture to nanosecond pcap with per-bin summaries), congestion
  (derived onset/decision/recovery).
- Correlation and report: aligned timeline, load phases, lagged correlation, pcap evidence,
  self-contained HTML/JSON/CSV report.
- Capability-based privilege model with sudo offer; load-generator safety policy.
- CLI (`netprobe run`, `delay`, `bandwidth`, `stress`, `sniff`, `report`, `analyze`,
  `server`, `privileges`) and Python API.
- 61 unprivileged tests, CI on Python 3.10–3.13, Docker netem testbed and evaluation scripts.
- Release workflow, `CITATION.cff`, `.zenodo.json`, `RELEASING.md`.
