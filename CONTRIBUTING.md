# Contributing

Thanks for helping out.

## Getting it running

```bash
npm install
npm run dev          # nodemon
npm start            # plain node
```

The panel needs QEMU and (on Linux) `/dev/kvm` to actually create VMs, but
it starts and serves the UI without them, which is enough for UI work.

## Style

- 2-space indent, semicolons, single quotes - match the surrounding code.
- Keep the routes in `app.js` grouped the way they already are.
- `app.js` is one large file by design; please do not split it up in a
  pull request unless it is a deliberate, discussed change.

## Before you open a pull request

```bash
node --check app.js     # syntax
npm start               # does it boot?
```

CI does the same plus a smoke test and a `pkg` build.

## Security

Please read [SECURITY.md](SECURITY.md) first. Several routes are
unauthenticated by design in this release. If you are fixing one of them,
that is very welcome - open an issue first so we can agree on the approach,
especially for the WebSocket console, where the fix changes the shape of the
upgrade handler.

Do not report vulnerabilities in a public issue. Use the private reporting
button.

## Licence

By contributing you agree that your contribution is licensed under the MIT
licence, the same as the rest of the project.
