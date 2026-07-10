# Upstream base

Fork base — image `docker.io/cognee/cognee-mcp:main`.

| Field | Value |
|---|---|
| Image | `docker.io/cognee/cognee-mcp:main` |
| Image ID | `14732afe08f0` |
| Captured | ~July 2026 (image was ~2 weeks old at vendoring time) |
| MCP SDK | `mcp==1.27.0` (official, OAuth-capable SDK; NOT the `fastmcp` package) |
| Co-located cognee-API | `cognee/cognee:main` v1.2.2 (MCP lags: v1.1.0) |

## What's in `upstream/`
Unmodified sources from the image: `src/` (server.py, cognee_client.py, …),
`tests/`, `apps-src/`, `Dockerfile`, `pyproject.toml`, `uv.lock`, `entrypoint.sh`.
`.venv` was NOT vendored (built for a different arch, multiple GB) — restore via `uv sync`.

## Working rule
- Keep `upstream/` as close to the original as possible so our changes read as a
  clean diff and can be split into separate PRs (see SPEC.md §7).
- To bump the base: re-pull the image, `rsync` over `upstream/`, commit separately
  as "bump upstream to <digest>", then rebase our changes on top.

## How to re-pull the base (reference)
```bash
cid=$(podman create docker.io/cognee/cognee-mcp:main)
podman cp "$cid:/app" ./_tmp && podman rm "$cid"
rsync -a --exclude='.venv' --exclude='__pycache__' ./_tmp/ upstream/
```
