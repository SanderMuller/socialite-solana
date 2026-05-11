<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana\Tests;

use Collectiq\SolanaPhpSdk\PublicKey;
use Collectiq\SolanaPhpSdk\Util\Buffer;

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
        'publicKeyBase58' => (new PublicKey($publicKey))->toBase58(),
    ];
}

function signMessageBase58(string $message, string $secretKey): string
{
    $signature = sodium_crypto_sign_detached($message, $secretKey);

    return Buffer::fromString($signature)->toBase58String();
}
