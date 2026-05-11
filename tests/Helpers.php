<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana\Tests;

use Psr\Log\AbstractLogger;
use SanderMuller\SolanaPubkey\Base58;
use SanderMuller\SolanaPubkey\PublicKey;
use Stringable;

/**
 * In-memory PSR-3 logger for asserting log emissions.
 *
 * @property list<array{level: mixed, message: string|Stringable, context: array<string, mixed>}> $records
 */
final class ArrayLogger extends AbstractLogger
{
    /**
     * @var list<array{level: mixed, message: string|Stringable, context: array<string, mixed>}>
     */
    public array $records = [];

    /**
     * @param mixed $level
     * @param array<string, mixed> $context
     */
    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = [
            'level' => $level,
            'message' => $message,
            'context' => $context,
        ];
    }

    /**
     * @return list<array{level: mixed, message: string|Stringable, context: array<string, mixed>}>
     */
    public function recordsWithException(string $exceptionClass): array
    {
        return array_values(array_filter(
            $this->records,
            fn (array $r) => ($r['context']['exception'] ?? null) === $exceptionClass,
        ));
    }
}

/**
 * @return array{publicKey: string, secretKey: string, publicKeyBase58: string}
 */
function generateKeypair(): array
{
    $kp = sodium_crypto_sign_keypair();
    $publicKey = sodium_crypto_sign_publickey($kp);
    $secretKey = sodium_crypto_sign_secretkey($kp);

    return [
        'publicKey' => $publicKey,
        'secretKey' => $secretKey,
        'publicKeyBase58' => PublicKey::fromBytes($publicKey)->toBase58(),
    ];
}

function signMessageBase58(string $message, string $secretKey): string
{
    $signature = sodium_crypto_sign_detached($message, $secretKey);

    return Base58::encode($signature);
}
