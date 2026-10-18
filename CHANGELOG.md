# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.2] - 2026-10-18

### Fixed

- Prefix micro-ecc symbols with `recsrmesh_` to avoid link collisions with ESP-IDF's BT tinycrypt micro-ecc.

## [1.1.1] - 2026-10-18

### Fixed

- Include micro-ecc via a relative path so converted IDF component builds find it without an extra include directory.

## [1.1.0] - 2026-10-18

### Added

- Crypto backend abstraction: PSA Crypto on Mbed TLS 4, legacy API on
  Mbed TLS 2/3 (SHA-256, HMAC-SHA-256, AES-128-OFB, RNG).
- micro-ecc secp192r1 ECDH for MASP (Mbed TLS 4 removed the curve),
  verified against an independent ECDH known-answer vector.

## [1.0.0] - 2026-10-18

### Added

- clang-format / CMake build tooling, CI, and contributor templates.
