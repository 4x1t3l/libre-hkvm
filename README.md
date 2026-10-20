# HKVM Panel

Web-based KVM/QEMU virtual machine management panel.

Express + EJS + SQLite + WebSocket console + SSH terminal, packaged as a
single self-contained binary with [`pkg`](https://github.com/vercel/pkg).

- Multi-user with roles (`user` / `admin`)
- VM lifecycle: create, start, stop, restart, resize disk, reinstall, snapshots
- Browser console over WebSocket, with a live QEMU log tail
- Built-in SSH terminal to the guest over `ssh2`
- OS template library with cached downloads and per-VM cloud-init seeds
- Port forwarding, resource limits, bandwidth quota accounting
- Discord OAuth login, API keys for automation
- Admin area for users, templates, API keys and panel settings

---

## Requirements

| | |
|---|---|
| Node.js | 20 or newer (22+ recommended) |
| Host OS | Linux with KVM (`/dev/kvm`); Windows also works for management-only use |
| QEMU | `qemu-system-x86_64`, `qemu-img` |
| Optional | `genisoimage` / `mkisofs` / `cloud-utils` for cloud-init seed images |
| Optional | `websocat` or `nc` for the guest SSH terminal |

## Install

```bash
git clone <your-repo-url> hkvm-panel
cd hkvm-panel
npm install
npm start
```

> **npm 11+ note.** `sqlite3` and `ssh2` need their install scripts to build a
> native binding. npm 11 blocks those by default. The repository already
> ships an `allowScripts` block in `package.json`, so a plain `npm install`
> works. If you hit `Cannot find module 'node_sqlite3.node'`, run:
>
> ```bash
> npm install-scripts approve sqlite3 ssh2
> npm rebuild sqlite3 ssh2
> ```

The panel listens on **:8080** and creates its database at `~/.hkvm/hkvm.db`.
A default `admin` / `admin` account is created on first boot — **change it
immediately** (Admin → Users).

## Configuration

All optional, via environment variables or a `.env` file in the project root
(the app calls `dotenv.config()`). See `.env.example`.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | HTTP port |
| `HKVM_DATA_DIR` | `~/.hkvm` | Where the SQLite database lives |
| `PANEL_NAME` | `HKVM Panel` | Name shown in the UI |
| `PANEL_VERSION` | `V3.0` | Version string shown in the UI |
| `DEFAULT_LOGO_URL` | an imgur URL | Logo used by the EJS templates |

VM images, ISOs, templates and cloud-init seeds live under `~/vms/`:

```
~/vms/vm-<id>-disk.qcow2     VM disk images
~/vms/vm-<id>-seed.iso       cloud-init seed images
~/vms/iso/                  uploaded ISOs
~/vms/templates/            cached OS template images
~/vms/cloudvm/              cloud-init working directories
```

## Building a single binary

```bash
npm install -g pkg
npm run build          # -> dist/app
```

`pkg` bundles `app.js` plus `views/**` and `public/**` into a single
executable. The default target is `node20-linux-x64`, because `pkg` 5.8.1
is the latest release and ships base binaries up to node20.

To build for a newer Node.js you need a matching base binary and
`PKG_NODE_PATH` pointing at it:

```bash
export PKG_NODE_PATH=/path/to/node22-base-binaries
npm run build
```

Add more targets by editing the `pkg` block in `package.json`.

## Project layout

```
app.js              the entire application (routes, DB, WebSocket, CLI)
views/              EJS templates
  users/              user-facing pages
  admin/              admin pages
  partials/           shared layout fragments
public/             static assets (css, images)
```

## API

Authenticated with a session cookie or an `X-API-Key` header.

```
GET    /api/vps                list your VMs
POST   /api/vps                create a VM
PUT    /api/vms/:id/edit       update configuration
DELETE /api/vms/:id            delete a VM
POST   /api/vms/:id/start      start / stop / restart / reinstall / snapshot
GET    /api/vms/:id/console    console log
GET    /api/vms/:id/edit       configuration
GET    /api/settings           panel settings
POST   /api/admin/users        user management (admin)
POST   /api/admin/api-keys     issue an API key (admin)
```

## Security

**Read [SECURITY.md](SECURITY.md) before you expose this panel to the
internet.** It lists the known issues in this release — notably that the
WebSocket console and SSH terminal are unauthenticated, that
`DELETE /api/vms/:id` has no ownership check, and that `disk_size` reaches a
shell command. There is a hardening checklist at the bottom of that file.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

MIT — see [LICENSE](LICENSE).

Originally developed as a commercial product with a licence server; the
licence check has been removed in this open-source edition.
