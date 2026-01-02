Vendor dictionaries
===================

Each vendor directory can include two optional files:

- `http-paths.txt` for HTTP snapshot templates
- `rtsp-paths.txt` for RTSP stream templates

Format
------

HTTP entries:

```
template|port|channel|stream|label
```

RTSP entries:

```
template|port|channel|stream|transport|label
```

Templates may include `{{ip_address}}`, `{{username}}`, `{{password}}`,
`{{port}}`, `{{channel}}`, and `{{stream}}`.

Notes
-----

- Keep lists short and high-signal.
- Prefer paths confirmed by vendor docs or field testing.
- Avoid including credentials.
