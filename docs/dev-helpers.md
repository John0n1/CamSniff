## Development helpers

The top-level `Makefile` bundles a few convenience targets:

```bash
make build        # dpkg-buildpackage -us -uc (Debian package build)
make clean        # drop build artefacts and staging directories
make run MODE=war # invoke sudo ./scripts/camsniff.sh --mode war
make lint         # shellcheck + bash -n across project scripts
make dev          # run lint plus a smoke dpkg-buildpackage --dry-run
```

All targets respect the repository layout, so you can iterate locally before publishing `.deb` builds.