# Socialite Solana

Laravel Socialite provider for Sign-In With Solana (SIWS / CAIP-122).

This package adds a `solana` driver to [Laravel Socialite](https://laravel.com/docs/socialite). The wallet user signs a SIWS challenge message with their private key; the server verifies the Ed25519 signature and you get back a Socialite `User` keyed by the base58 public key.

- CAIP-122 / Phantom SIWS challenge format (domain, statement, URI, chain ID, nonce, issued-at, expiration-time, resources)
- Ed25519 verification via [`sandermuller/solana-pubkey`](https://github.com/SanderMuller/solana-pubkey)
- Single-use nonce with configurable TTL — failed verifies don't burn the challenge
- Accepts base58 or base64 signatures
- Typed exception hierarchy so callers can map each failure case to its own UX
- Works from controllers, Livewire components, queue jobs, or console code — the HTTP wrappers are thin
- Pluggable challenge storage — session-backed default, cache-backed for API / Sanctum bearer-token flows, or your own implementation
- Optional PSR-3 logger injection for ops dashboards on failed-signature / expiry / malformed-input rates

## Requirements

PHP 8.3+ and Laravel 11, 12, or 13. The `ext-sodium` PHP extension must be enabled.

## Installation

```bash
composer require sandermuller/socialite-solana
```

Register the Socialite extension listener in `app/Providers/AppServiceProvider.php::boot()` (works on Laravel 11/12/13 — those skeletons no longer ship an `EventServiceProvider`):

```php
use Illuminate\Support\Facades\Event;
use SanderMuller\SocialiteSolana\SocialiteSolanaExtendSocialite;
use SocialiteProviders\Manager\SocialiteWasCalled;

public function boot(): void
{
    Event::listen(
        SocialiteWasCalled::class,
        [SocialiteSolanaExtendSocialite::class, 'handle'],
    );
}
```

On older Laravel apps that still have `app/Providers/EventServiceProvider.php`, the listener may instead live in the `$listen` array — the `Event::listen()` call above works on all supported versions.

## Configuration

Add the `solana` block to `config/services.php`:

```php
'solana' => [
    // Required by socialiteproviders/manager but unused by this driver.
    'client_id' => env('SOLANA_CLIENT_ID', 'unused'),
    'client_secret' => env('SOLANA_CLIENT_SECRET', 'unused'),
    'redirect' => env('SOLANA_REDIRECT_URI', '/auth/solana/callback'),

    // Domain shown in the SIWS message. Defaults to APP_URL host.
    'domain' => env('SOLANA_SIWS_DOMAIN'),

    // Canonical URI of the resource being signed in to. Defaults to APP_URL.
    'uri' => env('SOLANA_SIWS_URI'),

    // Human-readable statement (optional).
    'statement' => env('SOLANA_SIWS_STATEMENT', 'Sign in to authenticate.'),

    // Solana cluster: mainnet | devnet | testnet | localnet.
    'chain' => env('SOLANA_SIWS_CHAIN', 'mainnet'),

    // Challenge lifetime in seconds (minimum 60). Default 180 matches typical
    // SIWS reference implementations.
    'ttl' => (int) env('SOLANA_SIWS_TTL', 180),

    // Optional CAIP-122 resource URIs (list of strings).
    'resources' => [],

    // Where the issued challenge lives between buildChallengeFor() and
    // verifyCredentials(). Values: 'session' (default), 'cache', or an FQCN
    // implementing SanderMuller\SocialiteSolana\Contracts\ChallengeStore.
    'store' => env('SOLANA_CHALLENGE_STORE', 'session'),
],
```

## Usage

The Solana flow is not a redirect-based OAuth flow. The wallet returns a signed message synchronously, so the provider exposes both HTTP wrappers and framework-agnostic methods:

| Method | Signature | When to use |
|---|---|---|
| `challenge()` | `Socialite::driver('solana')->challenge(): JsonResponse` | Controller routes; reads `publicKey` from the request, returns JSON. |
| `user()` | `Socialite::driver('solana')->user(): User` | Controller routes; reads `publicKey`, `signature`, `message`, `nonce` from the request. |
| `buildChallengeFor(string $publicKey)` | returns `array{message: string, nonce: string}` | Livewire, queue, console — no HTTP request needed. |
| `verifyCredentials(string $publicKey, string $signature, string $message, string $nonce)` | returns `User` | Livewire, queue, console — no HTTP request needed. |

Calling `redirect()` throws `BadMethodCallException` — there's nothing to redirect to. Calling `scopes()` with non-empty input also throws; OAuth scopes are not applicable.

### Controller routes

```php
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use SanderMuller\SocialiteSolana\Exceptions\SolanaAuthException;

Route::post('/auth/solana/challenge', function () {
    return Socialite::driver('solana')->challenge();
})->middleware('web');

Route::post('/auth/solana/callback', function () {
    try {
        $solanaUser = Socialite::driver('solana')->user();
    } catch (SolanaAuthException $e) {
        return response()->json(['error' => $e->getMessage()], 422);
    }

    $user = \App\Models\User::firstOrCreate(
        ['solana_public_key' => $solanaUser->getId()],
        ['password' => Hash::make(Str::random(32))],
    );

    Auth::login($user, remember: true);

    return response()->json(['redirect' => '/home']);
})->middleware('web');
```

### Livewire component

```php
use Laravel\Socialite\Facades\Socialite;
use Livewire\Component;
use SanderMuller\SocialiteSolana\Exceptions\SolanaAuthException;

class SolanaLogin extends Component
{
    public string $walletAddress = '';

    /**
     * Issue a SIWS challenge. The JS layer should `$wire.set('walletAddress', pubkey)`
     * before calling this so the component already knows the address when verify() fires.
     */
    public function requestSignInChallenge(string $publicKey): array
    {
        return Socialite::driver('solana')->buildChallengeFor($publicKey);
    }

    public function signIn(string $signature, string $message, string $nonce): void
    {
        try {
            $solanaUser = Socialite::driver('solana')->verifyCredentials(
                $this->walletAddress, $signature, $message, $nonce,
            );
        } catch (SolanaAuthException $e) {
            $this->addError('solana', $e->getMessage());
            return;
        }

        // ... resolve user, log in, redirect
    }
}
```

On the JS side, a small `signMessageBase58()` helper wraps the wallet adapter call so consumers don't repeat `bs58.encode(signed.signature)` at every site:

```js
import bs58 from 'https://esm.sh/bs58@5.0.0';

async function signMessageBase58(wallet, message) {
    const encoded = new TextEncoder().encode(message);
    const signed = await wallet.signMessage(encoded, 'utf8');
    return bs58.encode(signed.signature);
}

await wallet.connect();
$wire.set('walletAddress', wallet.publicKey.toBase58());

const { message, nonce } = await $wire.call('requestSignInChallenge', wallet.publicKey.toBase58());
const signature = await signMessageBase58(wallet, message);
await $wire.call('signIn', signature, message, nonce);
```

For UX, sharing a single error surface between sync (server validation) and async (wallet/network) errors keeps the component simple:

```blade
<div x-data="{ error: null }">
    <div x-show="error || $wire.__instance.errors?.solana" class="alert">
        <span x-text="error"></span>
        @error('solana') {{ $message }} @enderror
    </div>
</div>
```

### Granular error handling

Every authentication failure throws a specific subclass of `SanderMuller\SocialiteSolana\Exceptions\SolanaAuthException`, which itself extends `\InvalidArgumentException`. Catch the base class for a uniform 422, or the subclasses for per-case UX and rate-limit buckets:

```php
use SanderMuller\SocialiteSolana\Exceptions\AddressMismatchException;
use SanderMuller\SocialiteSolana\Exceptions\ChallengeExpiredException;
use SanderMuller\SocialiteSolana\Exceptions\ChallengeNotFoundException;
use SanderMuller\SocialiteSolana\Exceptions\InvalidPublicKeyException;
use SanderMuller\SocialiteSolana\Exceptions\InvalidSignatureException;
use SanderMuller\SocialiteSolana\Exceptions\MalformedSignatureException;
use SanderMuller\SocialiteSolana\Exceptions\MessageMismatchException;
use SanderMuller\SocialiteSolana\Exceptions\MissingChallengeParameterException;

try {
    $solanaUser = Socialite::driver('solana')->user();
} catch (MissingChallengeParameterException) {
    return back()->withErrors(['wallet' => 'Wallet response was incomplete. Try again.']);
} catch (ChallengeExpiredException | ChallengeNotFoundException) {
    return back()->withErrors(['wallet' => 'Sign-in window expired. Click sign in to retry.']);
} catch (InvalidPublicKeyException) {
    return back()->withErrors(['wallet' => 'That wallet address is not a valid Solana public key.']);
} catch (MessageMismatchException | AddressMismatchException) {
    abort(400, 'Tampered request.'); // Wallet signed something the server did not issue — usually a bug, occasionally an attack.
} catch (MalformedSignatureException) {
    // Wallet returned a signature that's not 64 raw bytes — extension bug or wrong wallet. Catch BEFORE InvalidSignatureException.
    return back()->withErrors(['wallet' => 'Your wallet did not return a valid signature. Try a different wallet or reconnect.']);
} catch (InvalidSignatureException) {
    return back()->withErrors(['wallet' => 'Signature did not match. The user may have switched wallets mid-flow. Please try again.']);
}
```

### Challenge storage

By default, the issued challenge lives in the Laravel session, so the browser's session cookie binds it to one device. For headless flows (Sanctum bearer tokens, native mobile, API clients) where no session exists, switch to the cache-backed store:

```php
// config/services.php
'solana' => [
    // ...
    'store' => 'cache',
],
```

The cache store treats the 32-character nonce (~160 bits of entropy) as the unguessable handle, exactly the way short-lived bearer tokens work. Callers must keep the nonce secret between issue and verify.

For full control, implement `SanderMuller\SocialiteSolana\Contracts\ChallengeStore` and bind it in the container — the package prefers a container binding over the config string:

```php
use SanderMuller\SocialiteSolana\Contracts\ChallengeStore;

$this->app->singleton(ChallengeStore::class, MyRedisStore::class);
```

The interface is three methods:

```php
interface ChallengeStore
{
    public function put(Challenge $challenge): void;
    public function find(string $nonce): ?Challenge;
    public function forget(string $nonce): void;
}
```

### Logging

The Provider accepts a PSR-3 `LoggerInterface` so you can ship SIWS auth events to your observability stack — useful for dashboards on failed-signature count, expiry rate, malformed-pubkey rate, and the like.

Resolution order:

1. An instance passed via `setLogger()` wins.
2. Otherwise a container-bound `Psr\Log\LoggerInterface` is used.
3. Otherwise `NullLogger`.

The **recommended pattern is a scoped `setLogger()` call inside a small helper**, not a global container binding. The Socialite manager memoizes drivers, so calling `setLogger()` on `Socialite::driver('solana')` once per request is idempotent across `challenge()` / `user()` / `buildChallengeFor()` / `verifyCredentials()` invocations:

```php
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use SanderMuller\SocialiteSolana\Provider;

private function solanaProvider(): Provider
{
    /** @var Provider $provider */
    $provider = Socialite::driver('solana');

    $provider->setLogger(Log::channel('security'));

    return $provider;
}

// Use it like:
$user = $this->solanaProvider()->user();
```

> [!WARNING]
> Binding `Psr\Log\LoggerInterface` globally in the container works, but it swaps the default logger for **every** package that resolves that contract — including Laravel internals — which is a wide blast radius for one provider's worth of observability. Prefer the scoped helper pattern above unless you genuinely want the routing to apply package-wide.

```php
// Avoid unless you actually want the routing to be app-wide:
$this->app->bind(\Psr\Log\LoggerInterface::class, fn () => Log::channel('security'));
```

Each failure throws **and** logs a `warning` with the exception class in `context.exception` plus relevant non-PII details (signature byte length, expiry delta, missing-param flags). Successful challenge issuance and signature verification log at `info`.

| Event | Level | Notable context |
|---|---|---|
| Challenge issued | `info` | `ttl_seconds` |
| Verification succeeded | `info` | — |
| Missing param on challenge / verify | `warning` | `exception`, `*_empty` flags |
| Invalid public key | `warning` | `exception`, `input_length` |
| Malformed / unknown nonce | `warning` | `exception`, `nonce_length`, `reason` |
| Message mismatch | `warning` | `exception`, `stored_length`, `received_length` |
| Address mismatch | `warning` | `exception` |
| Challenge expired | `warning` | `exception`, `expired_seconds_ago` |
| Malformed signature (undecodable or wrong length) | `warning` | `exception` = `MalformedSignatureException`, `signature_byte_length` or `input_length` |
| Invalid signature (verify returned false) | `warning` | `exception` = `InvalidSignatureException` |
| Nonce race lost | `warning` | `exception`, `reason: concurrent_consumption` |

No public keys, signatures, or message contents are logged.

### Frontend (Phantom wallet)

The wallet connects first so the server knows which address to embed in the SIWS message:

```js
import bs58 from 'https://esm.sh/bs58@5.0.0';

const provider = window.solana;
await provider.connect();
const publicKey = provider.publicKey.toBase58();

const challenge = await fetch('/auth/solana/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': csrf },
    credentials: 'same-origin',
    body: JSON.stringify({ publicKey }),
}).then(r => r.json());

const signed = await provider.signMessage(
    new TextEncoder().encode(challenge.message),
    'utf8',
);

const result = await fetch('/auth/solana/callback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': csrf },
    credentials: 'same-origin',
    body: JSON.stringify({
        publicKey,
        signature: bs58.encode(signed.signature),
        message: challenge.message,
        nonce: challenge.nonce,
    }),
});
```

A full Blade example lives in `resources/views/auth/solana-login.blade.php`.

### What the SIWS message looks like

```
example.com wants you to sign in with your Solana account:
Fh7s4WkPgVZBkU3xCqAd9kQp...

Sign in to authenticate.

URI: https://example.com
Version: 1
Chain ID: mainnet
Nonce: 9b2c1f4a...
Issued At: 2026-05-11T12:30:00Z
Expiration Time: 2026-05-11T12:40:00Z
```

## Threat model

What the package defends against, and what it doesn't.

**Defends against:**

- **Forged signatures** — Ed25519 verify with the SDK's length-checked binary signature path.
- **Replay across sessions (session store)** — when using the default `SessionChallengeStore`, the challenge is keyed by the Laravel session cookie; an attacker without the victim's session cannot consume their challenge.
- **Replay of a redeemed nonce** — nonce is consumed atomically by the store's `forget()`, which returns `true` only for the caller that actually removed it. Concurrent verifiers on the same valid bundle resolve to exactly one success; the losers get `ChallengeNotFoundException`.
- **Expired challenges** — `Expiration Time` is enforced server-side; `ttl` config has a 60-second floor.
- **Address swap** — `publicKey` in the request must match the address the server embedded in the issued message.
- **Tampered message** — server compares the received message against the stored message with `hash_equals` before signature verify.
- **Malformed nonce** — input nonce must match the 32-char alphanumeric format the package issues; bogus values short-circuit to `ChallengeNotFoundException`.
- **Nonce burn on failed verify** — failed signature verifies do NOT consume the nonce, so wallet retries and double-submits survive bad input.

**Does NOT defend against:**

- **Wallet-side phishing** — if the user signs the message on an attacker's domain, the package on your domain is not involved. Educate users; consider showing the domain field prominently in the wallet prompt.
- **Compromised session storage** — the challenge lives in the Laravel session. If the session driver is compromised (XSS leaking the cookie, shared session store breach), an attacker can race a valid signature into your endpoint within the TTL window.
- **Wallet identity over time** — the package authenticates that whoever signed the message controls the wallet right now. It does not say anything about whether the same human still controls that wallet a week later. Treat the wallet address like any other long-lived identity claim and re-authenticate when the action warrants it.
- **Bundle interception with the cache store** — `CacheChallengeStore` removes the session-cookie binding, so the 32-character nonce is the only handle. If an attacker can read the full `(publicKey, signature, message, nonce)` bundle off the wire before the legitimate client redeems it, they can redeem it from any client within the TTL. The signature itself stays valid only against the address embedded in the message — they cannot impersonate a different wallet — but they can race the legitimate caller for the one-time consumption. This is the conventional bearer-token threat model. Use the cache store only on TLS-terminated transports, and prefer the session store whenever a session cookie is available.

## Testing

```bash
composer test
```

This runs the Pest suite under Orchestra Testbench. Covers the full SIWS round-trip, every exception subclass, signature/message/address tampering, nonce format validation, nonce reuse, expiry, and base58 vs base64 signature decoding.

## Contributing

Issues and pull requests welcome at <https://github.com/SanderMuller/socialite-solana>.

Quality gates on every PR: Pint, PHPStan (level max, strict rules, type-coverage 100%), Rector, full Pest suite.

## Credits

- [Sander Muller](https://github.com/SanderMuller)
- [Claude Opus 4.7](https://claude.com/claude-code)

## License

MIT
