# APlane SDKs

SDKs for integrating applications and agents with `apsigner`.

This repository contains the public client SDKs only. The main APlane
application, signer, shell, LogicSig providers, and operational tooling live in
the AGPL-licensed `aplane-algo/aplane` repository.

## Packages

| SDK | Directory | Package |
| --- | --- | --- |
| Go | `go/` | `github.com/aplane-algo/aplane-sdks/go` |
| Python | `python/` | `aplane` |
| TypeScript | `typescript/` | `aplane` |

Shared signer API contract fixtures live under `contracts/signerapi/` and are
used by all SDK test suites.

## Development

Go:

```bash
cd go
go test ./...
```

Python:

```bash
cd python
pytest -v
```

TypeScript:

```bash
cd typescript
npm install
npm test
```

## License

MIT. See `LICENSE`.
