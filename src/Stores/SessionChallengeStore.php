<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana\Stores;

use Illuminate\Contracts\Session\Session;
use SanderMuller\SocialiteSolana\Challenge;
use SanderMuller\SocialiteSolana\Contracts\ChallengeStore;

/**
 * Default store. Binds the challenge to the user's Laravel session cookie,
 * so a stolen nonce alone cannot be replayed from a different browser.
 */
final readonly class SessionChallengeStore implements ChallengeStore
{
    private const string KEY_PREFIX = 'solana_auth_challenge:';

    public function __construct(private Session $session) {}

    public function put(Challenge $challenge): void
    {
        $this->session->put(self::KEY_PREFIX . $challenge->nonce, [
            'message' => $challenge->message,
            'address' => $challenge->address,
            'expires_at' => $challenge->expiresAt,
        ]);
    }

    public function find(string $nonce): ?Challenge
    {
        $payload = $this->session->get(self::KEY_PREFIX . $nonce);

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
        $existing = $this->session->pull($key);

        return $existing !== null;
    }
}
