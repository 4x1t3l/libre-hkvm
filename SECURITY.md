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

## Known issues in this release

This project is published as-is. The following issues are known and are
listed here so that operators can make an informed decision about how to
deploy it. They are tracked in the issue tracker.

### 1. WebSocket console and SSH terminal are unauthenticated — **critical**

`app.js` creates the WebSocket server with `new WebSocket.Server({ server })`.
There is no `verifyClient` option and no `upgrade` handler, and the
`connection` handler never inspects the session cookie or an API key.

* `ws://host/console/<vm_id>` returns the VM's serial console log.
* `ws://host/ssh-terminal` will open an SSH session to any `host:port`,
  `username` and `password` the client supplies, and relay the shell back.
  The `owner_id` of the VM is read from the database and then never
  compared with anything.

**Impact:** anyone who can reach the HTTP port can read a tenant's console
and use the panel as an open SSH proxy into your network segment.

**Workaround:** do not expose the panel directly. Put it behind a reverse
proxy that authenticates every request (including WebSocket upgrades) and
restricts access by source address.

### 2. `DELETE /api/vms/:vm_id` does not check ownership — **critical**

Every other VM route scopes non-admins with `AND owner_id = ?`. The delete
route does not, so any authenticated user can delete any user's VM - disk
image, seed ISO, log file and database row.

**Workaround:** no workaround available at the application layer. Restrict
access to the API to trusted users only.

### 3. `disk_size` reaches a shell command unvalidated — **critical**

`disk_size` is interpolated into a shell string passed to `execSync()` /
`execPromise()` without quoting and without validation, so shell
metacharacters are honoured.

**Workaround:** the panel must not be reachable by untrusted users.

### 4. ISO attach does not sanitise the filename — **critical**

`path.join(ISO_DIR, iso_file)` allows `..` segments, so a host file outside
the ISO directory can be attached as a CD-ROM to a tenant's VM.

### 5. The session secret is hardcoded and the cookie flags are weak — **high**

The session secret is a constant in `app.js`, so it is identical for every
installation and is readable by anyone with the source. The cookie is set
with `secure: false` and no `sameSite` attribute.

**Workaround:** front the panel with TLS and do not expose it over plain
HTTP.

### 6. Default administrator account — **high**

An `admin` / `admin` account is created automatically on first boot and is
never forced to change.

**Workaround:** change the password immediately after the first login.

### 7. No CSRF protection and no rate limiting — **medium**

There is no CSRF token on any state-changing route, and `/api/login` has no
rate limit or lockout, so it can be used for credential stuffing and for
CPU-exhaustion denial of service.

### 8. `?api_key=` query parameter — **medium**

API keys are accepted in the query string as well as the `X-API-Key` header,
which leaks them into proxy logs, `Referer` headers and browser history.

## Hardening checklist before exposing this panel

- [ ] Put it behind an authenticating reverse proxy (nginx, Caddy, ...).
- [ ] Terminate TLS there; the panel itself speaks plain HTTP.
- [ ] Restrict the source addresses that may reach the panel.
- [ ] Change the default administrator password.
- [ ] Set a unique `SESSION_SECRET` (see item 5).
- [ ] Keep the panel off the public internet if you can.
