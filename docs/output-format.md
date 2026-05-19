# guard JSONL decision log — output format

**This document has moved.**

The canonical schema, writer guarantees, and consumer responsibilities live
in [`docs/JSONL_FORMAT.md`](JSONL_FORMAT.md). That document is a strict
superset of the v1.0 spec previously documented here and covers everything
v1.1 added (`type`, `permission_mode`, `internal_error` records, the
redirect-pointer protocol).

## Why this file still exists

Older external links (READMEs, observability docs, internal wikis) may
point at `docs/output-format.md`. This stub is the redirect target so
those links don't 404. New documentation should link to
`docs/JSONL_FORMAT.md` directly.
