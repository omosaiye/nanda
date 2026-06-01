# Release Checklist

Use this checklist for `v0.2-local-prototype`.

Release tag:

```sh
git tag v0.2-local-prototype
git push origin v0.2-local-prototype
```

## Preflight

- Confirm the working tree is clean:

  ```sh
  git status --short
  ```

- Confirm `docs/RELEASE_NOTES_v0.2.md` and user-facing docs are updated.
- Run a secret scan before tagging.
- Confirm milestone tags are present locally:

  ```sh
  git tag --list 'm15-*' 'm16-*' 'm17-*' 'm18-*' 'v0.2-local-prototype'
  ```

## Verification

- Run formatting:

  ```sh
  go fmt ./...
  ```

- Run uncached unit tests:

  ```sh
  go test -count=1 ./...
  ```

- Run Postgres-backed integration tests:

  ```sh
  NANDA_POSTGRES_DSN='postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable' go test -p 1 -count=1 -v ./...
  ```

- Run the repository verification script:

  ```sh
  ./scripts/verify.sh
  ```

- Optionally run the v0.2 release helper:

  ```sh
  ./scripts/release-check-v02.sh
  ```

- Run a clean-clone smoke test:
  - Clone the repository into a temporary directory.
  - Start local Postgres with Docker Compose.
  - Run `make verify`.
  - Run `make run-local` and `scripts/demo-local.sh`.
- Run the local demo script against the release candidate:

  ```sh
  ./scripts/demo-local.sh
  ```

- After the demo, check local metrics:

  ```sh
  curl -sS http://localhost:8080/metrics
  ```

## Tag and Publish

- Confirm the intended tag is `v0.2-local-prototype`.
- Create the tag from the reviewed commit.
- Push the tag.
- Create a GitHub release from `v0.2-local-prototype`.
- Include release notes, known limitations, and any upgrade notes.
