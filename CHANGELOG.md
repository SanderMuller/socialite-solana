# Changelog

All notable changes to `sandermuller/socialite-solana` are documented here.

## v0.1.1 - 2026-05-11

### Added

- **PSR-3 logger injection** via `Provider::setLogger(LoggerInterface)`. Each SIWS failure path logs a `warning` with the exception class in `context.exception` plus non-PII details (signature byte length, expiry delta, missing-param flags). Successful challenge issuance + signature verification log at `info`. Resolution: setter-supplied logger wins, otherwise a container-bound `LoggerInterface`, otherwise `NullLogger`. See README "Logging" for the per-event context table.
- New explicit dependency: `psr/log: ^3.0` (already pulled transitively by Laravel).

### Notes

- No breaking changes. All existing API surface (HTTP wrappers, framework-agnostic methods, exception hierarchy, ChallengeStore contract) is unchanged.

## v0.1.0 - 2026-05-11

Initial release. Adds a `solana` driver to [Laravel Socialite](https://laravel.com/docs/socialite) for [Sign-In With Solana](https://docs.phantom.app/solana/sign-in-with-solana) (SIWS / CAIP-122).

### What ships

- **CAIP-122 / Phantom SIWS challenge** with per-request nonce, configurable TTL, and atomic single-use enforcement
- **Ed25519 verification** via [`sandermuller/solana-pubkey`](https://github.com/SanderMuller/solana-pubkey), accepts base58 or base64 signatures
- **Framework-agnostic public API** alongside the HTTP wrappers:
  - `Socialite::driver('solana')->buildChallengeFor(string $publicKey): array`
  - `Socialite::driver('solana')->verifyCredentials(string, string, string, string): User`
  - `Socialite::driver('solana')->challenge(): JsonResponse` — HTTP wrapper
  - `Socialite::driver('solana')->user(): User` — HTTP wrapper
- **Typed exception hierarchy** under `SanderMuller\SocialiteSolana\Exceptions\` (all extend `\InvalidArgumentException` for backward-compat):
  - `SolanaAuthException` (abstract)
  - `MissingChallengeParameterException`, `InvalidPublicKeyException`, `ChallengeNotFoundException`, `ChallengeExpiredException`, `MessageMismatchException`, `AddressMismatchException`, `InvalidSignatureException`
- **Pluggable challenge storage** via the `ChallengeStore` contract — `SessionChallengeStore` default for browser flows, `CacheChallengeStore` for Sanctum / bearer-token flows, or bind your own implementation in the container
- **Atomic nonce consumption**: concurrent verifiers on the same valid bundle resolve to exactly one success
- **Example Phantom blade view** with a reusable `signMessageBase58(wallet, message)` JS helper

### Requirements

- PHP 8.3 or 8.4
- Laravel 11, 12, or 13
- `ext-sodium`
