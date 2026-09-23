# Upstream intelligence sync

`data/upstream/candidates.json` is a **review-only** catalogue. The scanner does
not read it. Updating it cannot add network probes, passwords, media retrieval,
or exploit checks. Promotion to an active vendor fingerprint requires a separate
reviewed change, independent evidence, and regression tests.

The initial adapters read Cameradar's MIT-licensed RTSP route list and only the
informational metadata of one MIT-licensed Nuclei Dahua detection template.
The latter's HTTP requests, matchers and payloads are never exported. Routes
containing credential-like fields, userinfo, unexpanded placeholders, or
invalid characters are discarded. Remaining routes are *unverified candidates*,
not assertions of vendor identity or stream accessibility. Each record links
to an exact upstream commit, repository, path and license; the normalized
catalogue is deterministic and deduplicated. Third-party permission notices
are retained in `data/upstream/THIRD_PARTY_LICENSES.txt`.

PwnEye and Cam-Amber are GPL-licensed. They are not mirrored into CamSniff's
MIT dataset: any import from those projects requires an explicit license review
or a separately distributed adapter. No executable code, credential pairs,
payloads, vulnerability proofs, or media are synchronized from any source.

To fetch current upstream contents and open a reviewable change locally:

```bash
python3 scripts/helpers/sync_upstream_intel.py
python3 -m unittest discover -s tests -v
git diff -- data/upstream/candidates.json
```

The weekly/dispatch GitHub Action performs the same fetch and tests, then opens
or updates an `automation/upstream-intel` PR only when the catalogue changes.
It needs `contents: write` and `pull-requests: write` permissions. For PR CI to
trigger from automated pushes, supply a repository secret `CAMSYNC_PR_TOKEN`
with appropriately scoped token permissions; pushes made solely with the
default `GITHUB_TOKEN` do not trigger ordinary `pull_request` workflows. The
sync job still runs the offline regression suite before opening a PR.

Reviewers should check the upstream commits and licenses, candidate quality,
source additions, rejection counts, and any suspicious sudden growth. Do not
merge unverified candidates directly into the scanner's live dictionaries.
