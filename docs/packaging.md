## Debian packaging status

The refreshed `debian/` directory targets Debian 13 (trixie), Kali, and Ubuntu contrib suites. Key characteristics:

- `debian/control` advertises `Section: contrib/net`, Vcs pointers, and runtime dependencies aligned with the shell-based toolchain.
- Icons are installed into the hicolor theme, and the desktop entry launches `camsniff` without hard-coded elevation.
- `debian/watch` follows the canonical GitHub release feed for automated monitoring.

### Building packages

```bash
dpkg-buildpackage -us -uc
```

or leverage the project makefile:

```bash
make build
```

Run builds in a clean tree. If previous root-level builds created directories such as `debian/.debhelper/`, `debian/camsniff/`, or `scripts/venv/`, remove them with elevated privileges (`sudo rm -rf …`) or rebuild inside a container.

Keep the top-level `VERSION` file and `debian/changelog` in sync when publishing new releases.
