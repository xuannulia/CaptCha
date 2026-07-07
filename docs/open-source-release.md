# Open Source Release Notes

This document records the remaining owner decisions and release gates before publishing CaptCha as an open-source repository. It complements `docs/release-checklist.md` and `make release-audit`.

## Release Gate

Do not publish the repository as open source until all of these are true:

- A `LICENSE` file exists at the repository root and matches `AGPL-3.0-only`.
- `SECURITY.md` names a private vulnerability reporting channel.
- `make verify` passes.
- `make browser-smoke` passes for UI-facing changes.
- `make docker-build` passes in an environment with Docker daemon access.
- `make release-audit` passes.

## License Decision

CaptCha is licensed as `AGPL-3.0-only`.

This keeps the public release open for study, self-hosting, commercial use, and redistribution, while discouraging modified closed-source network services based on the open edition. If a third party modifies the AGPL edition and provides it to users over a network, they must provide the corresponding source under the AGPL terms.

The project owner may still develop separate proprietary editions from code they own. If outside contributions are accepted and the owner wants to reuse those contributions in a proprietary edition, the project needs a Contributor License Agreement or another explicit inbound licensing process. Until that process exists, treat external code contributions as AGPL-only.

## Security Reporting Channel

`SECURITY.md` names `loser@iloser.cn` as the private vulnerability reporting channel.

The public issue tracker should not be the first place for exploit details, bypass recipes, or working payloads.

## What Can Stay Public

CaptCha is designed so security does not depend on closed frontend code. The open release can include:

- Runtime rendering code.
- Admin console code.
- HTTP and gRPC contracts.
- Server-side challenge generation and validation logic.
- Demo captcha materials whose licenses are owned by the project.

Private deployment state must stay outside the repository:

- Admin, gRPC, metrics, collector, inference, or application secrets.
- Production policy thresholds and private IP lists.
- Real model artifacts if they are not intended for the open release.
- Private object storage URLs, presigned URLs, and deployment credentials.

## Docker Verification

`make release-audit` checks whether Docker daemon is reachable because `make docker-build` is a release gate. If local Docker Desktop is not running, run the Docker build in CI or another machine with Docker enabled:

```bash
make docker-build
make release-audit
```

`make docker-build` passes `DOCKER_GOPROXY` and `DOCKER_GOSUMDB` into the Docker builds. The defaults favor local network reachability. To use the official Go services instead:

```bash
DOCKER_GOPROXY=https://proxy.golang.org,direct DOCKER_GOSUMDB=sum.golang.org make docker-build
```

If the build is only verified in CI, record the CI run URL in the release notes before tagging.
