<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana\Tests;

use SanderMuller\SolanaPubkey\Base58;
use SanderMuller\SolanaPubkey\PublicKey;

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
