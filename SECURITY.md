# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

Use GitHub's **Security → Report a vulnerability** button on this repository, or
email the maintainer. Include the affected version, reproduction steps and any
proof-of-concept. You will get an acknowledgement within 72 hours.

Please do **not** run automated scanners against a deployment you do not own.

## What was fixed in this release

The following were found in the original build and have been fixed. Each one
has a regression test in the `hkvm-pocs` suite.

| Was | Now |
|-----|-----|
| The WebSocket console and SSH terminal accepted **any** anonymous client | The upgrade is authenticated: the session cookie is verified, the session is looked up, and the VM has to belong to the caller (admins may access any VM). The SSH destination comes from the VM record, never from the client. |
| `DELETE /api/vms/:vm_id` and the `/stats` and `/logs` routes had **no ownership check** | All three go through one `loadOwnedVm()` helper, so "can I see it" and "can I change it" can never disagree. |
| `disk_size` was interpolated into a **shell string** | Validated against `^\d{1,5}(\.\d+)?\s*(K\|M\|G\|T\|P\|E)i?B?$` before it is stored, and every `qemu-img`/`cp` call now passes an **argument array** (`execFile`), so no shell is involved. |
| The ISO attach route allowed **path traversal** (`../../../../etc/shadow`) | The file name is reduced to a bare basename, refused if it carries a directory component, and resolved with a containment check. The same check runs where the ISO is attached at boot. |
| `extra_args` was appended verbatim to the **QEMU command line** | The field is no longer accepted, and the stored value is no longer used. |
| `ssh_port` was unvalidated | Must be a port between 1024 and 65535. |
| The **session secret was hardcoded** | Read from `SESSION_SECRET`, or generated randomly on first boot and persisted in the data directory with mode 0600. |
| The session cookie had `secure: false`, no `sameSite`, and the id was **not rotated at login** | `httpOnly`, `sameSite: 'lax'`, `secure` in production, `saveUninitialized: false`, and `req.session.regenerate()` on every login. |
| A well-known **`admin`/`admin`** account was created on first boot | The password comes from `HKVM_ADMIN_PASSWORD`, or is generated randomly and printed once. |
| `/api/login` had **no rate limit** and ran bcrypt synchronously | Rate limited per address and per account, and the hash comparison is asynchronous. Unknown accounts still perform a dummy comparison, so the response time does not reveal whether an account exists. |
| The **admin dashboard** rendered `activation.machine_id` and `activation.panel_version` into `innerHTML` without escaping | Those sinks are escaped. The licence server is a separate deployment and is not part of this repository. |
| Template downloads followed **any** redirect and could reach the panel's own network | The URL is validated (scheme allow-list, and the resolved address must not be private/loopback/link-local), re-checked on every redirect, the redirect target is resolved against the current URL, and the download size is capped. |
| API keys were accepted in the **query string** | Header only. |
| `/api/settings`, `/api/os-templates`, `/api/cpu-models`, `/api/smbios`, `/api/network-types`, `/api/dns-providers` and `/api/iso-list` were **unauthenticated** | All require authentication. |
| Cloud-init `username`, `password` and `hostname` were interpolated **raw** into the `#cloud-config` document | YAML-quoted, and values containing line breaks are rejected. |

## What you still need to do

The panel speaks plain HTTP and trusts the reverse proxy in front of it.
Put it behind one that:

- terminates TLS,
- **authenticates every request**, including WebSocket upgrades, and
- restricts which source addresses may reach it.

The panel binds `0.0.0.0` and its own WebSocket authentication relies on the
session cookie, so without an authenticating proxy the console and the SSH
terminal are reachable by anyone who can open a socket to the port.

## Configuration

| Variable | Purpose |
|---|---|
| `SESSION_SECRET` | Session signing key. Minimum 32 characters. If unset, one is generated and stored in the data directory. |
| `HKVM_ADMIN_PASSWORD` | Password for the `admin` account on first boot. If unset, a random one is generated and printed **once**. |
| `HKVM_DATA_DIR` | Where the database and the generated session secret live. |
| `HKVM_TRUST_PROXY` | Set to `1` when behind a TLS-terminating proxy, so `Secure` cookies are set correctly. |
| `HKVM_SECURE_COOKIES` | Set to `1` to force the `Secure` cookie flag outside production. |
| `HKVM_LOGIN_LIMIT_PER_IP` | Login attempts per address per 15 minutes (default 30). |
| `HKVM_LOGIN_LIMIT_PER_ACCOUNT` | Login attempts per account per 15 minutes (default 5). |
| `HKVM_ALLOW_PRIVATE_DOWNLOADS` | Set to `1` to allow template downloads from private addresses. |

## Known limitations

- **`bcryptjs` is pure JavaScript**, so a password comparison is CPU-bound
  even when it is called asynchronously. The rate limits cap how much of
  that can happen, but for a busy public deployment consider the native
  `bcrypt` package, which runs the comparison on libuv's thread pool.
- Sessions are held in memory (`MemoryStore`), so they are lost when the
  panel restarts and are not shared between processes. Use a persistent
  store (for example `connect-sqlite3`) if you run more than one worker.
