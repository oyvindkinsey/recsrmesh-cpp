# Contributing

C++20, formatted with clang-format (Google-based, 100 cols, 4-space indent —
see `.clang-format`). Run before opening a PR:

```sh
make format   # or: pre-commit install && pre-commit run -a
make build
```

Build output goes to `build-local/` by default (override with
`make build BUILD_DIR=...`); it is gitignored.
