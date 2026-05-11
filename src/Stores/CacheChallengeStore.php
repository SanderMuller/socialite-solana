<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana\Stores;

use Illuminate\Contracts\Cache\Repository as Cache;
use SanderMuller\SocialiteSolana\Challenge;
use SanderMuller\SocialiteSolana\Contracts\ChallengeStore;

/**
 * Cache-backed store. Use for API / bearer-token flows where no session
 * cookie binds the challenge to a browser. The 32-character random nonce
 * itself is the unguessable handle (~160 bits of entropy); the caller is
 * trusted to keep it secret between issue and verify, exactly as bearer
 * tokens are.
 */
final readonly class CacheChallengeStore implements ChallengeStore
{
    private const string KEY_PREFIX = 'solana_auth_challenge:';

    public function __construct(private Cache $cache) {}

    public function put(Challenge $challenge): void
    {
        $ttl = max(1, $challenge->expiresAt - time());

        $this->cache->put(
            self::KEY_PREFIX . $challenge->nonce,
            [
                'message' => $challenge->message,
                'address' => $challenge->address,
                'expires_at' => $challenge->expiresAt,
            ],
            $ttl,
        );
    }

    public function find(string $nonce): ?Challenge
    {
        $payload = $this->cache->get(self::KEY_PREFIX . $nonce);

        if (! is_array($payload)
            || ! isset($payload['message'], $payload['address'], $payload['expires_at'])
            || ! is_string($payload['message'])
            || ! is_string($payload['address'])
            || ! is_int($payload['expires_at'])
        ) {
            return null;
        }

        return new Challenge(
            nonce: $nonce,
            message: $payload['message'],
            address: $payload['address'],
            expiresAt: $payload['expires_at'],
        );
    }

    public function forget(string $nonce): bool
    {
        $key = self::KEY_PREFIX . $nonce;
        $existing = $this->cache->pull($key);

        return $existing !== null;
    }
}
