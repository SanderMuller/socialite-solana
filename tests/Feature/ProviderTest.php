<?php declare(strict_types=1);

use BadMethodCallException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use Laravel\Socialite\Facades\Socialite;
use SanderMuller\SocialiteSolana\Provider;

use function SanderMuller\SocialiteSolana\Tests\generateKeypair;
use function SanderMuller\SocialiteSolana\Tests\signMessageBase58;

beforeEach(function (): void {
    Session::start();
});

function makeProvider(Request $request): Provider
{
    $driver = Socialite::driver('solana');
    $driver->setRequest($request);

    return $driver;
}

function buildChallenge(string $publicKey): array
{
    $request = Request::create('/auth/solana/redirect', 'POST', ['publicKey' => $publicKey]);
    $response = makeProvider($request)->challenge();

    return $response->getData(true);
}

it('returns SIWS challenge', function (): void {
    $kp = generateKeypair();

    $payload = buildChallenge($kp['publicKeyBase58']);

    expect($payload)
        ->toHaveKeys(['message', 'nonce'])
        ->and($payload['message'])->toContain('example.test wants you to sign in')
        ->and($payload['message'])->toContain($kp['publicKeyBase58'])
        ->and($payload['message'])->toContain("Nonce: {$payload['nonce']}")
        ->and($payload['nonce'])->toBeString()->not->toBe('');
});

it('rejects challenge without publicKey', function (): void {
    makeProvider(Request::create('/auth/solana/challenge', 'POST'))->challenge();
})->throws(InvalidArgumentException::class, 'publicKey is required');

it('rejects challenge with invalid publicKey', function (): void {
    makeProvider(Request::create('/auth/solana/challenge', 'POST', [
        'publicKey' => 'not-a-real-pubkey',
    ]))->challenge();
})->throws(InvalidArgumentException::class, 'Invalid Solana public key');

it('redirect() throws because Solana sign-in does not redirect', function (): void {
    makeProvider(Request::create('/', 'GET'))->redirect();
})->throws(BadMethodCallException::class, 'does not use HTTP redirects');

it('verifies a valid signature and returns the user', function (): void {
    $kp = generateKeypair();
    $payload = buildChallenge($kp['publicKeyBase58']);

    $signature = signMessageBase58($payload['message'], $kp['secretKey']);

    $callback = Request::create('/auth/solana/callback', 'POST', [
        'publicKey' => $kp['publicKeyBase58'],
        'signature' => $signature,
        'message' => $payload['message'],
        'nonce' => $payload['nonce'],
    ]);

    $user = makeProvider($callback)->user();

    expect($user->getId())->toBe($kp['publicKeyBase58'])
        ->and($user->getName())->toBe($kp['publicKeyBase58'])
        ->and($user->getEmail())->toBeNull();
});

it('rejects a tampered message', function (): void {
    $kp = generateKeypair();
    $payload = buildChallenge($kp['publicKeyBase58']);
    $signature = signMessageBase58($payload['message'], $kp['secretKey']);

    $callback = Request::create('/auth/solana/callback', 'POST', [
        'publicKey' => $kp['publicKeyBase58'],
        'signature' => $signature,
        'message' => $payload['message'] . ' tampered',
        'nonce' => $payload['nonce'],
    ]);

    makeProvider($callback)->user();
})->throws(InvalidArgumentException::class, 'does not match expected message');

it('rejects when address differs from challenge', function (): void {
    $kp = generateKeypair();
    $imposter = generateKeypair();
    $payload = buildChallenge($kp['publicKeyBase58']);
    $signature = signMessageBase58($payload['message'], $imposter['secretKey']);

    $callback = Request::create('/auth/solana/callback', 'POST', [
        'publicKey' => $imposter['publicKeyBase58'],
        'signature' => $signature,
        'message' => $payload['message'],
        'nonce' => $payload['nonce'],
    ]);

    makeProvider($callback)->user();
})->throws(InvalidArgumentException::class, 'Signer address does not match challenge address');

it('rejects an invalid signature for the right address', function (): void {
    $kp = generateKeypair();
    $imposter = generateKeypair();
    $payload = buildChallenge($kp['publicKeyBase58']);
    $signature = signMessageBase58($payload['message'], $imposter['secretKey']);

    $callback = Request::create('/auth/solana/callback', 'POST', [
        'publicKey' => $kp['publicKeyBase58'],
        'signature' => $signature,
        'message' => $payload['message'],
        'nonce' => $payload['nonce'],
    ]);

    makeProvider($callback)->user();
})->throws(InvalidArgumentException::class, 'Invalid signature');

it('rejects an unknown nonce', function (): void {
    $kp = generateKeypair();
    $payload = buildChallenge($kp['publicKeyBase58']);
    $signature = signMessageBase58($payload['message'], $kp['secretKey']);

    $callback = Request::create('/auth/solana/callback', 'POST', [
        'publicKey' => $kp['publicKeyBase58'],
        'signature' => $signature,
        'message' => $payload['message'],
        'nonce' => 'unknown-nonce',
    ]);

    makeProvider($callback)->user();
})->throws(InvalidArgumentException::class, 'challenge expired or invalid');

it('rejects an expired challenge', function (): void {
    config()->set('services.solana.ttl', 60);
    $kp = generateKeypair();
    $payload = buildChallenge($kp['publicKeyBase58']);
    $signature = signMessageBase58($payload['message'], $kp['secretKey']);

    $stored = Session::get('solana_auth_challenge:' . $payload['nonce']);
    $stored['expires_at'] = time() - 1;
    Session::put('solana_auth_challenge:' . $payload['nonce'], $stored);

    $callback = Request::create('/auth/solana/callback', 'POST', [
        'publicKey' => $kp['publicKeyBase58'],
        'signature' => $signature,
        'message' => $payload['message'],
        'nonce' => $payload['nonce'],
    ]);

    makeProvider($callback)->user();
})->throws(InvalidArgumentException::class, 'has expired');

it('rejects callback missing required parameters', function (): void {
    makeProvider(Request::create('/auth/solana/callback', 'POST'))->user();
})->throws(InvalidArgumentException::class, 'Missing required parameters');

it('accepts a base64-encoded signature', function (): void {
    $kp = generateKeypair();
    $payload = buildChallenge($kp['publicKeyBase58']);

    $rawSignature = sodium_crypto_sign_detached($payload['message'], $kp['secretKey']);
    $base64Signature = base64_encode($rawSignature);

    $callback = Request::create('/auth/solana/callback', 'POST', [
        'publicKey' => $kp['publicKeyBase58'],
        'signature' => $base64Signature,
        'message' => $payload['message'],
        'nonce' => $payload['nonce'],
    ]);

    $user = makeProvider($callback)->user();

    expect($user->getId())->toBe($kp['publicKeyBase58']);
});

it('does not burn the nonce when verification fails, allowing a retry', function (): void {
    $kp = generateKeypair();
    $imposter = generateKeypair();
    $payload = buildChallenge($kp['publicKeyBase58']);

    // First attempt: wrong signer for the right address — must fail.
    $bad = Request::create('/auth/solana/callback', 'POST', [
        'publicKey' => $kp['publicKeyBase58'],
        'signature' => signMessageBase58($payload['message'], $imposter['secretKey']),
        'message' => $payload['message'],
        'nonce' => $payload['nonce'],
    ]);
    try {
        makeProvider($bad)->user();
        expect(false)->toBeTrue('expected first attempt to throw');
    } catch (InvalidArgumentException) {
        // expected
    }

    // Second attempt with the real signer must succeed — nonce was not burned.
    $good = Request::create('/auth/solana/callback', 'POST', [
        'publicKey' => $kp['publicKeyBase58'],
        'signature' => signMessageBase58($payload['message'], $kp['secretKey']),
        'message' => $payload['message'],
        'nonce' => $payload['nonce'],
    ]);

    $user = makeProvider($good)->user();
    expect($user->getId())->toBe($kp['publicKeyBase58']);
});

it('burns the nonce after a successful verification', function (): void {
    $kp = generateKeypair();
    $payload = buildChallenge($kp['publicKeyBase58']);
    $signature = signMessageBase58($payload['message'], $kp['secretKey']);

    $first = Request::create('/auth/solana/callback', 'POST', [
        'publicKey' => $kp['publicKeyBase58'],
        'signature' => $signature,
        'message' => $payload['message'],
        'nonce' => $payload['nonce'],
    ]);
    makeProvider($first)->user();

    // Replaying the same valid signature must now fail — nonce consumed.
    makeProvider(clone $first)->user();
})->throws(InvalidArgumentException::class, 'challenge expired or invalid');

it('falls back to app.url host when domain config is empty', function (): void {
    config()->set('services.solana.domain');

    $kp = generateKeypair();
    $payload = buildChallenge($kp['publicKeyBase58']);

    expect($payload['message'])->toContain('example.test wants you to sign in');
});
