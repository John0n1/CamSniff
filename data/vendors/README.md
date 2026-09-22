Vendor dictionaries
===================

Each vendor directory can include two optional files:

- `http-paths.txt` for HTTP snapshot templates
- `rtsp-paths.txt` for RTSP stream templates
- `fingerprint.yaml` for declarative vendor-identification evidence

Fingerprint modules
-------------------

Modules combine independent observations instead of identifying a vendor from
a shared port. Supported evidence groups are `oui`, `http`, `onvif`, `rtsp`,
`ssdp`, and `paths`; values are case-insensitive regular expressions.

```yaml
vendor: Example
family: network-camera
type: camera
fingerprints:
  http: ['ExampleCam']
  onvif: ['Example Corporation']
  paths: ['/vendor-api/']
probes:
  rtsp_paths: ['/stream/main']
  snapshot_paths: ['/snapshot.jpg']
```

Invalid modules are ignored safely. Keep expressions narrow and require
evidence backed by vendor documentation or sanitized device captures.

Format
------

HTTP entries:

```text
template|port|channel|stream|label
```

RTSP entries:

```text
template|port|channel|stream|transport|label
```

Templates may include `{{ip_address}}`, `{{username}}`, `{{password}}`,
`{{port}}`, `{{channel}}`, and `{{stream}}`.

Notes
-----

- Keep lists short and high-signal.
- Prefer paths confirmed by vendor docs or field testing.
- Avoid including credentials.
