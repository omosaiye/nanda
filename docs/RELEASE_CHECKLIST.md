# Release Checklist

Use this checklist for `v0.1-local-prototype` and future local-prototype releases.

Example release tag:

```sh
git tag v0.1-local-prototype
git push origin v0.1-local-prototype
```

## Preflight

- Ensure `git status` is clean.
- Confirm release notes and user-facing docs are updated.
- Run a secret scan before tagging.

## Verification

- Run unit tests:

  ```sh
  go test ./...
  ```

- Run Postgres-backed integration tests:

  ```sh
  NANDA_POSTGRES_DSN='postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable' go test -v ./...
  ```

- Run the repository verification script:

  ```sh
  scripts/verify.sh
  ```

- Run a clean-clone smoke test:
  - Clone the repository into a temporary directory.
  - Start local Postgres with Docker Compose.
  - Run `make verify`.
  - Run `make run-local` and `scripts/demo-local.sh`.

## Tag and Publish

- Confirm the intended tag, for example `v0.1-local-prototype`.
- Create the tag from the reviewed commit.
- Push the tag.
- Create a GitHub release from `v0.1-local-prototype` or a future version tag.
- Include release notes, known limitations, and any upgrade notes.
