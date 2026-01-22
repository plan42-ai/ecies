# Project Context

## Purpose
Provide an ECIES (Elliptic Curve Integrated Encryption Scheme) implementation for Go so services can encrypt and decrypt payloads using shared public/private key pairs.

## Tech Stack
- Go 1.24
- Standard library crypto primitives
- Test utilities via testify

## Project Conventions

### Code Style
Follow gofmt formatting and idiomatic cryptography naming (public/private keys, curves, ciphertext). `make lint` runs golangci-lint for static checks.

### Architecture Patterns
Single Go package exposing encrypt/decrypt helpers and key serialization utilities. Focused surface area with clear error handling for cryptographic operations.

### Testing Strategy
`go test ./...` verifies encryption/decryption flows and edge cases. Keep tests deterministic with fixed key fixtures.

### Git Workflow
Feature branches merged via PR. Tag releases with `make tag` when publishing updated cryptography helpers.

## Domain Context
Library is consumed by other Plan42 services for secure messaging. Correct curve selection and key handling are critical; avoid API changes that would break compatibility with existing encrypted payloads.

## Important Constraints
- Maintain backward compatibility for ciphertext formats when possible.
- Keep dependencies minimal to reduce attack surface; prefer standard library crypto.
- Handle secrets carefully in tests and examples; avoid logging sensitive material.

## External Dependencies
None beyond Go's crypto libraries.
