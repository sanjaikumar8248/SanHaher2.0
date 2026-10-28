# SanHasher 2.0 — Higher Authority Model

## Permission boundary
Higher Authority is the only role allowed to administer accounts/access and delete/restore evidence.

Analysts, examiners, and investigators can use the forensic functions allowed to their account, but cannot:
- create users
- grant access
- revoke access
- delete evidence
- restore deleted evidence
- modify audit history
- modify the immutable access register

## Evidence lifecycle
ACTIVE -> DELETED (30-day recovery) -> ARCHIVED_30D_EXPIRED

There is no DELETE-FROM-DATABASE or permanent destruction operation.

## Audit rule
No audit or access event is edited. Corrections are represented by new events. Access events are hash-chained with `previous_event_hash` and `event_hash`.
