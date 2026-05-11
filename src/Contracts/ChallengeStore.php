<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana\Contracts;

use SanderMuller\SocialiteSolana\Challenge;

/**
 * Storage backend for SIWS challenges.
 *
 * Implementations bind a freshly issued challenge to its nonce, look it up by
 * nonce on callback, and forget it once a verification succeeds. The package
 * ships a session-backed default (binds to the Laravel session cookie) and a
 * cache-backed implementation (suitable for API / bearer-token flows where no
 * session exists).
 */
interface ChallengeStore
{
    public function put(Challenge $challenge): void;

    public function find(string $nonce): ?Challenge;

    /**
     * Atomically remove the challenge.
     *
     * Returns true if this call is the one that actually removed it, false if
     * the challenge had already been consumed (for example by a concurrent
     * verifier on the same nonce). The Provider uses this as the single
     * "claim" point so that two parallel verifyCredentials() calls with the
     * same valid bundle cannot both succeed.
     */
    public function forget(string $nonce): bool;
}
