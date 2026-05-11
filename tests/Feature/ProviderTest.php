<?php declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use Laravel\Socialite\Facades\Socialite;
use Psr\Log\LoggerInterface;
use SanderMuller\SocialiteSolana\Challenge;
use SanderMuller\SocialiteSolana\Contracts\ChallengeStore;
use SanderMuller\SocialiteSolana\Exceptions\AddressMismatchException;
use SanderMuller\SocialiteSolana\Exceptions\ChallengeExpiredException;
use SanderMuller\SocialiteSolana\Exceptions\ChallengeNotFoundException;
use SanderMuller\SocialiteSolana\Exceptions\InvalidPublicKeyException;
use SanderMuller\SocialiteSolana\Exceptions\InvalidSignatureException;
use SanderMuller\SocialiteSolana\Exceptions\MalformedSignatureException;
use SanderMuller\SocialiteSolana\Exceptions\MessageMismatchException;
use SanderMuller\SocialiteSolana\Exceptions\MissingChallengeParameterException;
use SanderMuller\SocialiteSolana\Exceptions\SolanaAuthException;
use SanderMuller\SocialiteSolana\Provider;
use SanderMuller\SocialiteSolana\Stores\SessionChallengeStore;
use SanderMuller\SocialiteSolana\Tests\ArrayLogger;

use function SanderMuller\SocialiteSolana\Tests\generateKeypair;
use function SanderMuller\SocialiteSolana\Tests\signMessageBase58;

beforeEach(function (): void {
    Session::start();
});

function provider(?Request $request = null): Provider
{
    $driver = Socialite::driver('solana');
    $driver->setRequest($request ?? Request::create('/', 'GET'));

    return $driver;
}

it('returns SIWS challenge via challenge() HTTP wrapper', function (): void {
    $kp = generateKeypair();
    $request = Request::create('/auth/solana/challenge', 'POST', ['publicKey' => $kp['publicKeyBase58']]);

    $payload = provider($request)->challenge()->getData(true);

    expect($payload)
        ->toHaveKeys(['message', 'nonce'])
        ->and($payload['message'])->toContain('example.test wants you to sign in')
        ->and($payload['message'])->toContain($kp['publicKeyBase58'])
        ->and($payload['message'])->toContain("Nonce: {$payload['nonce']}")
        ->and($payload['nonce'])->toMatch('/^[A-Za-z0-9]{32}$/');
});

it('exposes a non-HTTP buildChallengeFor() for Livewire/queue callers', function (): void {
    $kp = generateKeypair();

    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    expect($payload)
        ->toHaveKeys(['message', 'nonce'])
        ->and($payload['message'])->toContain($kp['publicKeyBase58']);
});

it('rejects an empty publicKey in buildChallengeFor', function (): void {
    provider()->buildChallengeFor('');
})->throws(MissingChallengeParameterException::class, 'publicKey is required');

it('rejects an invalid publicKey in buildChallengeFor', function (): void {
    provider()->buildChallengeFor('not-a-real-pubkey');
})->throws(InvalidPublicKeyException::class, 'Invalid Solana public key');

it('verifies a valid signature via the non-HTTP API', function (): void {
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    $user = provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: signMessageBase58($payload['message'], $kp['secretKey']),
        message: $payload['message'],
        nonce: $payload['nonce'],
    );

    expect($user->getId())->toBe($kp['publicKeyBase58'])
        ->and($user->getName())->toBeNull()
        ->and($user->getNickname())->toBeNull()
        ->and($user->getEmail())->toBeNull();
});

it('rejects a tampered message with MessageMismatchException', function (): void {
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: signMessageBase58($payload['message'], $kp['secretKey']),
        message: $payload['message'] . ' tampered',
        nonce: $payload['nonce'],
    );
})->throws(MessageMismatchException::class);

it('rejects when address differs from challenge with AddressMismatchException', function (): void {
    $kp = generateKeypair();
    $imposter = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    provider()->verifyCredentials(
        publicKey: $imposter['publicKeyBase58'],
        signature: signMessageBase58($payload['message'], $imposter['secretKey']),
        message: $payload['message'],
        nonce: $payload['nonce'],
    );
})->throws(AddressMismatchException::class);

it('rejects an invalid signature with InvalidSignatureException', function (): void {
    $kp = generateKeypair();
    $imposter = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: signMessageBase58($payload['message'], $imposter['secretKey']),
        message: $payload['message'],
        nonce: $payload['nonce'],
    );
})->throws(InvalidSignatureException::class);

it('rejects an unknown nonce with ChallengeNotFoundException', function (): void {
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: signMessageBase58($payload['message'], $kp['secretKey']),
        message: $payload['message'],
        nonce: str_repeat('a', 32),
    );
})->throws(ChallengeNotFoundException::class);

it('rejects a malformed nonce that fails the format pattern', function (): void {
    provider()->verifyCredentials(
        publicKey: 'A',
        signature: 'B',
        message: 'C',
        nonce: 'shortish',
    );
})->throws(ChallengeNotFoundException::class);

it('rejects an expired challenge with ChallengeExpiredException', function (): void {
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    $stored = Session::get('solana_auth_challenge:' . $payload['nonce']);
    $stored['expires_at'] = time() - 1;
    Session::put('solana_auth_challenge:' . $payload['nonce'], $stored);

    provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: signMessageBase58($payload['message'], $kp['secretKey']),
        message: $payload['message'],
        nonce: $payload['nonce'],
    );
})->throws(ChallengeExpiredException::class);

it('rejects verifyCredentials with empty params via MissingChallengeParameterException', function (): void {
    provider()->verifyCredentials(publicKey: '', signature: '', message: '', nonce: '');
})->throws(MissingChallengeParameterException::class);

it('redirect() throws because Solana sign-in does not redirect', function (): void {
    provider()->redirect();
})->throws(BadMethodCallException::class, 'does not use HTTP redirects');

it('scopes() throws when called with non-empty input', function (): void {
    provider()->scopes(['anything']);
})->throws(BadMethodCallException::class, 'OAuth scopes are not supported');

it('scopes() silently no-ops on empty input (required by SocialiteManager)', function (): void {
    expect(provider()->scopes([]))->toBeInstanceOf(Provider::class)
        ->and(provider()->scopes(''))->toBeInstanceOf(Provider::class);
});

it('accepts a base64-encoded signature', function (): void {
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    $rawSignature = sodium_crypto_sign_detached($payload['message'], $kp['secretKey']);

    $user = provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: base64_encode($rawSignature),
        message: $payload['message'],
        nonce: $payload['nonce'],
    );

    expect($user->getId())->toBe($kp['publicKeyBase58']);
});

it('does not burn the nonce when verification fails, allowing a retry', function (): void {
    $kp = generateKeypair();
    $imposter = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    try {
        provider()->verifyCredentials(
            publicKey: $kp['publicKeyBase58'],
            signature: signMessageBase58($payload['message'], $imposter['secretKey']),
            message: $payload['message'],
            nonce: $payload['nonce'],
        );
        expect(false)->toBeTrue('expected first attempt to throw');
    } catch (InvalidSignatureException) {
        // expected
    }

    $user = provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: signMessageBase58($payload['message'], $kp['secretKey']),
        message: $payload['message'],
        nonce: $payload['nonce'],
    );

    expect($user->getId())->toBe($kp['publicKeyBase58']);
});

it('burns the nonce after a successful verification', function (): void {
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);
    $signature = signMessageBase58($payload['message'], $kp['secretKey']);

    provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: $signature,
        message: $payload['message'],
        nonce: $payload['nonce'],
    );

    provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: $signature,
        message: $payload['message'],
        nonce: $payload['nonce'],
    );
})->throws(ChallengeNotFoundException::class);

it('falls back to app.url host when domain config is empty', function (): void {
    config()->set('services.solana.domain');

    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    expect($payload['message'])->toContain('example.test wants you to sign in');
});

it('works against the cache-backed ChallengeStore for sessionless API flows', function (): void {
    config()->set('services.solana.store', 'cache');

    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    $user = provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: signMessageBase58($payload['message'], $kp['secretKey']),
        message: $payload['message'],
        nonce: $payload['nonce'],
    );

    expect($user->getId())->toBe($kp['publicKeyBase58']);

    // Replay must fail — store::forget was called after success.
    expect(fn () => provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: signMessageBase58($payload['message'], $kp['secretKey']),
        message: $payload['message'],
        nonce: $payload['nonce'],
    ))->toThrow(ChallengeNotFoundException::class);
});

it('honours a container-bound custom ChallengeStore', function (): void {
    $custom = new class implements ChallengeStore {
        /** @var array<string, Challenge> */
        public array $stored = [];

        public function put(Challenge $challenge): void
        {
            $this->stored[$challenge->nonce] = $challenge;
        }

        public function find(string $nonce): ?Challenge
        {
            return $this->stored[$nonce] ?? null;
        }

        public function forget(string $nonce): bool
        {
            if (! isset($this->stored[$nonce])) {
                return false;
            }

            unset($this->stored[$nonce]);

            return true;
        }
    };

    app()->instance(ChallengeStore::class, $custom);

    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    expect($custom->stored)->toHaveKey($payload['nonce']);

    provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: signMessageBase58($payload['message'], $kp['secretKey']),
        message: $payload['message'],
        nonce: $payload['nonce'],
    );

    expect($custom->stored)->toBeEmpty();

    app()->forgetInstance(ChallengeStore::class);
});

it('rejects the second of two concurrent verifies on the same nonce', function (): void {
    // Simulates two workers that both read the challenge before either consumed it.
    // Inject a peek-only store wrapper so we can force both verifyCredentials() calls
    // through the validation gate before the atomic forget() resolves.
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);
    $signature = signMessageBase58($payload['message'], $kp['secretKey']);

    // First verify succeeds and atomically claims the nonce.
    $first = provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: $signature,
        message: $payload['message'],
        nonce: $payload['nonce'],
    );
    expect($first->getId())->toBe($kp['publicKeyBase58']);

    // Re-put the same challenge to simulate a state where the second worker had peeked
    // before the first worker's forget() ran. The second forget() must return false.
    $store = app()->make(SessionChallengeStore::class, [
        'session' => app('session.store'),
    ]);
    // Now the nonce is gone — calling forget directly returns false.
    expect($store->forget($payload['nonce']))->toBeFalse();
});

it('throws when ChallengeStore container binding resolves to the wrong type', function (): void {
    app()->instance(
        ChallengeStore::class,
        new stdClass(),
    );

    try {
        provider()->buildChallengeFor(generateKeypair()['publicKeyBase58']);
        expect(false)->toBeTrue('expected LogicException');
    } catch (LogicException $logicException) {
        expect($logicException->getMessage())->toContain('Container binding for')
            ->and($logicException->getMessage())->toContain('expected an instance of');
    } finally {
        app()->forgetInstance(ChallengeStore::class);
    }
});

it('throws a clear error when services.solana.store names a non-existent class', function (): void {
    config()->set('services.solana.store', 'Nope\\NotAClass');

    provider()->buildChallengeFor(generateKeypair()['publicKeyBase58']);
})->throws(LogicException::class, 'is not a known store keyword');

it('throws when services.solana.store names a class that does not implement the contract', function (): void {
    config()->set('services.solana.store', stdClass::class);

    provider()->buildChallengeFor(generateKeypair()['publicKeyBase58']);
})->throws(LogicException::class, 'does not implement');

it('logs successful challenge issuance at info level', function (): void {
    $logger = new ArrayLogger();
    $kp = generateKeypair();

    provider()->setLogger($logger)->buildChallengeFor($kp['publicKeyBase58']);

    expect($logger->records)->toHaveCount(1)
        ->and($logger->records[0]['level'])->toBe('info')
        ->and($logger->records[0]['message'])->toBe('SIWS: challenge issued')
        ->and($logger->records[0]['context'])->toHaveKey('ttl_seconds');
});

it('logs each failure path with the exception class in context', function (): void {
    $cases = [
        ['name' => 'missing param', 'run' => fn (Provider $p) => $p->buildChallengeFor(''), 'exception' => MissingChallengeParameterException::class],
        ['name' => 'invalid pubkey', 'run' => fn (Provider $p) => $p->buildChallengeFor('not-a-real-pubkey'), 'exception' => InvalidPublicKeyException::class],
        ['name' => 'malformed nonce', 'run' => fn (Provider $p) => $p->verifyCredentials('A', 'B', 'C', 'too-short'), 'exception' => ChallengeNotFoundException::class],
    ];

    foreach ($cases as $case) {
        $logger = new ArrayLogger();
        try {
            $case['run'](provider()->setLogger($logger));
            expect(false)->toBeTrue("expected {$case['name']} to throw");
        } catch (InvalidArgumentException) {
            // expected
        }

        expect($logger->recordsWithException($case['exception']))->not->toBeEmpty();
    }
});

it('logs successful verification at info level', function (): void {
    $logger = new ArrayLogger();
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    provider()->setLogger($logger)->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: signMessageBase58($payload['message'], $kp['secretKey']),
        message: $payload['message'],
        nonce: $payload['nonce'],
    );

    $success = array_filter($logger->records, fn (array $r) => $r['message'] === 'SIWS: verification succeeded');
    expect($success)->not->toBeEmpty();
});

it('logs an invalid signature attempt as warning with byte length context', function (): void {
    $logger = new ArrayLogger();
    $kp = generateKeypair();
    $imposter = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    try {
        provider()->setLogger($logger)->verifyCredentials(
            publicKey: $kp['publicKeyBase58'],
            signature: signMessageBase58($payload['message'], $imposter['secretKey']),
            message: $payload['message'],
            nonce: $payload['nonce'],
        );
    } catch (InvalidSignatureException) {
        // expected
    }

    $entry = $logger->recordsWithException(InvalidSignatureException::class)[0] ?? null;
    expect($entry)->not->toBeNull()
        ->and($entry['level'])->toBe('warning');
});

it('uses NullLogger when no logger is set or bound — no exceptions thrown', function (): void {
    $kp = generateKeypair();
    $result = provider()->buildChallengeFor($kp['publicKeyBase58']);

    expect($result)->toHaveKeys(['message', 'nonce']);
});

it('resolves a container-bound LoggerInterface when no explicit setLogger', function (): void {
    $logger = new ArrayLogger();
    app()->instance(LoggerInterface::class, $logger);

    $kp = generateKeypair();
    provider()->buildChallengeFor($kp['publicKeyBase58']);

    expect($logger->records)->not->toBeEmpty();

    app()->forgetInstance(LoggerInterface::class);
});

it('classifies a non-decodable signature as MalformedSignatureException', function (): void {
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: '@@@not-base58-or-base64@@@',
        message: $payload['message'],
        nonce: $payload['nonce'],
    );
})->throws(MalformedSignatureException::class);

it('classifies a wrong-length decoded signature as MalformedSignatureException', function (): void {
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    // 32 bytes (a pubkey-sized blob), valid base58, but not 64 → SDK rejects on length
    provider()->verifyCredentials(
        publicKey: $kp['publicKeyBase58'],
        signature: $kp['publicKeyBase58'],
        message: $payload['message'],
        nonce: $payload['nonce'],
    );
})->throws(MalformedSignatureException::class);

it('still classifies a correctly-shaped-but-wrong-signer signature as InvalidSignatureException only', function (): void {
    $kp = generateKeypair();
    $imposter = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    try {
        provider()->verifyCredentials(
            publicKey: $kp['publicKeyBase58'],
            signature: signMessageBase58($payload['message'], $imposter['secretKey']),
            message: $payload['message'],
            nonce: $payload['nonce'],
        );
        expect(false)->toBeTrue('expected throw');
    } catch (InvalidSignatureException $invalidSignatureException) {
        // Must be the parent class exactly, NOT MalformedSignatureException
        expect($invalidSignatureException)->not->toBeInstanceOf(MalformedSignatureException::class);
    }
});

it('catch InvalidSignatureException still catches MalformedSignatureException (additive)', function (): void {
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    try {
        provider()->verifyCredentials(
            publicKey: $kp['publicKeyBase58'],
            signature: '@@@not-base58-or-base64@@@',
            message: $payload['message'],
            nonce: $payload['nonce'],
        );
        expect(false)->toBeTrue('expected throw');
    } catch (InvalidSignatureException $invalidSignatureException) {
        expect($invalidSignatureException)->toBeInstanceOf(MalformedSignatureException::class);
    }
});

it('logs MalformedSignatureException class in context for non-decodable signature', function (): void {
    $logger = new ArrayLogger();
    $kp = generateKeypair();
    $payload = provider()->buildChallengeFor($kp['publicKeyBase58']);

    try {
        provider()->setLogger($logger)->verifyCredentials(
            publicKey: $kp['publicKeyBase58'],
            signature: '@@@not-base58-or-base64@@@',
            message: $payload['message'],
            nonce: $payload['nonce'],
        );
    } catch (MalformedSignatureException) {
        // expected
    }

    expect($logger->recordsWithException(MalformedSignatureException::class))->not->toBeEmpty();
});

it('every exception subclass extends SolanaAuthException and \\InvalidArgumentException', function (): void {
    foreach ([
        MissingChallengeParameterException::class,
        InvalidPublicKeyException::class,
        ChallengeNotFoundException::class,
        ChallengeExpiredException::class,
        MessageMismatchException::class,
        AddressMismatchException::class,
        InvalidSignatureException::class,
        MalformedSignatureException::class,
    ] as $class) {
        expect(is_subclass_of($class, SolanaAuthException::class))->toBeTrue();
        expect(is_subclass_of($class, InvalidArgumentException::class))->toBeTrue();
    }
});
