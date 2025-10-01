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

### Source uploads and signing

1. Export the upstream tarball (only required when releasing to Debian or mentors):

	```bash
	git archive --format=tar.gz --output ../camsniff_$(cat VERSION).orig.tar.gz --prefix camsniff-$(cat VERSION)/
	```

2. Ensure the tree is pristine and drop debhelper artefacts:

	```bash
	debian/rules clean
	```

3. Build a signed source package (replace `<keyid>` with your GPG key):

	```bash
	dpkg-buildpackage -S -sa -k<keyid>
	```

	Passing `-sa` guarantees the orig tarball is uploaded even when Debian already has an older revision.

4. Review the generated `.changes` and `.dsc` files using `lintian` before uploading:

	```bash
	lintian ../camsniff_*_source.changes
	```

### Continuous integration hints

- The package advertises a CLI autopkgtest (`debian/tests/version`) that runs `camsniff --version` and `--help`. Execute it locally with:

  ```bash
  autopkgtest . -- schroot unstable-amd64-sbuild
  ```

- Include `DEB_SIGN_KEYID=<keyid>` in the environment (or configure `~/.devscripts`) so tools like `debuild` and `gbp buildpackage` sign artefacts automatically.
