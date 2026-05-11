<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana;

/**
 * Server-issued SIWS challenge — the data the store keeps between
 * `buildChallengeFor()` and `verifyCredentials()`.
 */
final readonly class Challenge
{
    public function __construct(
        public string $nonce,
        public string $message,
        public string $address,
        public int $expiresAt,
    ) {}

    public function hasExpired(int $now): bool
    {
        return $now > $this->expiresAt;
    }
}
