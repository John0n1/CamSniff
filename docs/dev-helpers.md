## Development helpers

The top-level `Makefile` bundles a few convenience targets:

```bash
make build        # dpkg-buildpackage -us -uc (Debian package build)
make clean        # drop build artefacts and staging directories
make lint         # shellcheck + bash -n across project scripts
make dev          # run lint plus a smoke dpkg-buildpackage --dry-run
```

All targets respect the repository layout, so you can iterate locally before publishing `.deb` builds.

Key entrypoints in the tree:

* `scripts/camsniff.sh` — orchestrator (call via `sudo`).
* `scripts/core/` — mode/port profiles and shared knobs.
* `scripts/setup/` — dependency/bootstrap helpers.
* `scripts/probes/` — credential probe + SSDP/ONVIF helpers.
* `scripts/tools/analyze.sh` — quick stats for `dev/results/<run>/`.
