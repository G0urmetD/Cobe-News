# Signing keys

`pgdg-ACCC4CF8.asc` – the signing key of the PostgreSQL project's Debian repository (apt.postgresql.org), fingerprint
`B97B 0AFC AA1A 47F0 44F2 44A0 7FCC 7D46 ACCC 4CF8`, SHA-256
`0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76`. The app image (Dockerfile) and the release
workflow install `postgresql-client-18` from that repository and check this file's checksum before use – kept here so
that a build never depends on downloading it from www.postgresql.org.
