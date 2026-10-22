# 1. Record architecture decisions

Date: 2026-10-22
Status: accepted

## Context

blindsight asks users to trust it at the moment they sign a transaction that can
move a treasury. Many of its decisions are invisible in the code: which Safe
versions are supported and why, what counts as a trusted contract, why some
crates are forbidden, why a detector has a given severity. Reviewers need the
reasoning and the rejected alternatives, not only the result.

## Decision

Significant decisions are recorded as Architecture Decision Records in
`docs/adr/`, numbered sequentially (`NNNN-short-title.md`), with the sections
Context, Decision, Alternatives, Consequences. An accepted record is never
rewritten; a later record supersedes it and both link to each other.

## Alternatives

- Comments in code only: they explain how, rarely why, and cannot hold
  alternatives.
- A single design document: it goes stale and hides the order in which
  decisions were made.

## Consequences

Each decision that changes behaviour, trust assumptions or dependencies comes
with an ADR in the same commit.
