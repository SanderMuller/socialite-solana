<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana;

use BadMethodCallException;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\User;
use LogicException;
use Override;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use SanderMuller\SocialiteSolana\Contracts\ChallengeStore;
use SanderMuller\SocialiteSolana\Exceptions\AddressMismatchException;
use SanderMuller\SocialiteSolana\Exceptions\ChallengeExpiredException;
use SanderMuller\SocialiteSolana\Exceptions\ChallengeNotFoundException;
use SanderMuller\SocialiteSolana\Exceptions\InvalidPublicKeyException;
use SanderMuller\SocialiteSolana\Exceptions\InvalidSignatureException;
use SanderMuller\SocialiteSolana\Exceptions\MalformedSignatureException;
use SanderMuller\SocialiteSolana\Exceptions\MessageMismatchException;
use SanderMuller\SocialiteSolana\Exceptions\MissingChallengeParameterException;
use SanderMuller\SocialiteSolana\Stores\CacheChallengeStore;
use SanderMuller\SocialiteSolana\Stores\SessionChallengeStore;
use SanderMuller\SolanaPubkey\Base58;
use SanderMuller\SolanaPubkey\Exceptions\InvalidBase58Exception;
use SanderMuller\SolanaPubkey\Exceptions\InvalidSignatureException as SdkInvalidSignatureException;
use SanderMuller\SolanaPubkey\PublicKey;
use SocialiteProviders\Manager\ConfigTrait;
use Throwable;

final class Provider extends AbstractProvider
{
    use ConfigTrait;

    public const string IDENTIFIER = 'SOLANA';

    private const string NONCE_PATTERN = '/^[A-Za-z0-9]{32}$/';

    /**
     * Disables Socialite's OAuth `state` parameter, which is irrelevant to SIWS.
     * Challenge storage is delegated to ChallengeStore — by default that's a
     * session-backed store, but a cache-backed store ships for headless flows.
     */
    protected $stateless = true;

    private ?LoggerInterface $logger = null;

    /**
     * Inject a PSR-3 logger to capture per-exception SIWS auth events. Without
     * this, the package falls back to a container-bound `LoggerInterface` if
     * present, otherwise NullLogger. Useful for ops dashboards on failed-sig
     * count, expiry rate, malformed-pubkey rate, etc.
     */
    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    /**
     * @return list<string>
     */
    public static function additionalConfigKeys(): array
    {
        return ['domain', 'uri', 'statement', 'chain', 'ttl', 'resources', 'store'];
    }

    #[Override]
    public function redirect(): RedirectResponse
    {
        throw new BadMethodCallException(
            'Solana sign-in does not use HTTP redirects. Call challenge() to obtain the SIWS message.',
        );
    }

    /**
     * Build a SIWS challenge for the given wallet address. Framework-agnostic — does
     * not read from the HTTP request. Useful for Livewire, queue jobs, or console code.
     *
     * @return array{message: string, nonce: string}
     */
    public function buildChallengeFor(string $publicKey): array
    {
        if ($publicKey === '') {
            $this->logger()->warning('SIWS: challenge requested without publicKey', [
                'exception' => MissingChallengeParameterException::class,
            ]);
            throw new MissingChallengeParameterException('publicKey is required to build the SIWS message.');
        }

        $this->parsePublicKey($publicKey);

        $cfg = $this->solanaConfig();
        $appUrl = $this->appUrl();
        $domain = $this->stringFromConfig($cfg, 'domain', '');
        if ($domain === '') {
            $host = parse_url($appUrl, PHP_URL_HOST);
            // No $this->request fallback — buildChallengeFor() is called from
            // Livewire / queue / console where the resolved request has no
            // meaningful host. Set services.solana.domain explicitly in prod.
            $domain = is_string($host) && $host !== '' ? $host : 'localhost';
        }

        $nonce = Str::random(32);
        $issuedAt = Carbon::now();
        $ttl = max(60, $this->intFromConfig($cfg, 'ttl', 180));
        $expiresAt = $issuedAt->copy()->addSeconds($ttl);
        $expiresAtTimestamp = $expiresAt->getTimestamp();

        $message = (new SignInMessage(
            domain: $domain,
            address: $publicKey,
            statement: $this->nullableStringFromConfig($cfg, 'statement'),
            uri: $this->stringFromConfig($cfg, 'uri', $appUrl),
            version: '1',
            chainId: $this->stringFromConfig($cfg, 'chain', 'mainnet'),
            nonce: $nonce,
            issuedAt: $issuedAt->toIso8601ZuluString(),
            expirationTime: $expiresAt->toIso8601ZuluString(),
            resources: $this->resourcesFromConfig($cfg),
        ))->toString();

        $this->challengeStore()->put(new Challenge(
            nonce: $nonce,
            message: $message,
            address: $publicKey,
            expiresAt: $expiresAtTimestamp,
        ));

        $this->logger()->info('SIWS: challenge issued', [
            'ttl_seconds' => $ttl,
        ]);

        return ['message' => $message, 'nonce' => $nonce];
    }

    /**
     * Verify a SIWS signature and return the authenticated user. Framework-agnostic —
     * does not read from the HTTP request.
     */
    public function verifyCredentials(
        string $publicKey,
        string $signature,
        string $message,
        string $nonce,
    ): User {
        if ($publicKey === '' || $signature === '' || $message === '' || $nonce === '') {
            $this->logger()->warning('SIWS: verify called with missing parameters', [
                'exception' => MissingChallengeParameterException::class,
                'publicKey_empty' => $publicKey === '',
                'signature_empty' => $signature === '',
                'message_empty' => $message === '',
                'nonce_empty' => $nonce === '',
            ]);
            throw new MissingChallengeParameterException(
                'Missing required parameters: publicKey, signature, message, or nonce.',
            );
        }

        if (preg_match(self::NONCE_PATTERN, $nonce) !== 1) {
            $this->logger()->warning('SIWS: malformed nonce', [
                'exception' => ChallengeNotFoundException::class,
                'nonce_length' => strlen($nonce),
                'reason' => 'format_mismatch',
            ]);
            throw new ChallengeNotFoundException('Authentication challenge expired or invalid.');
        }

        $store = $this->challengeStore();
        $challenge = $store->find($nonce);

        if (! $challenge instanceof Challenge) {
            $this->logger()->warning('SIWS: challenge not found for nonce', [
                'exception' => ChallengeNotFoundException::class,
                'reason' => 'store_miss',
            ]);
            throw new ChallengeNotFoundException('Authentication challenge expired or invalid.');
        }

        if (! hash_equals($challenge->message, $message)) {
            $this->logger()->warning('SIWS: signed message does not match stored challenge', [
                'exception' => MessageMismatchException::class,
                'stored_length' => strlen($challenge->message),
                'received_length' => strlen($message),
            ]);
            throw new MessageMismatchException('Signed message does not match expected message.');
        }

        if (! hash_equals($challenge->address, $publicKey)) {
            $this->logger()->warning('SIWS: signer address does not match challenge address', [
                'exception' => AddressMismatchException::class,
            ]);
            throw new AddressMismatchException('Signer address does not match challenge address.');
        }

        $now = Carbon::now()->getTimestamp();
        if ($challenge->hasExpired($now)) {
            $this->logger()->warning('SIWS: challenge expired before verification', [
                'exception' => ChallengeExpiredException::class,
                'expired_seconds_ago' => $now - $challenge->expiresAt,
            ]);
            throw new ChallengeExpiredException('Authentication challenge has expired.');
        }

        $parsed = $this->parsePublicKey($publicKey);
        $signatureBytes = $this->decodeSignature($signature);

        try {
            $isValid = $parsed->verify($message, $signatureBytes);
        } catch (SdkInvalidSignatureException $sdkInvalidSignatureException) {
            $this->logger()->warning('SIWS: signature length rejected by SDK', [
                'exception' => MalformedSignatureException::class,
                'signature_byte_length' => strlen($signatureBytes),
                'sdk_message' => $sdkInvalidSignatureException->getMessage(),
            ]);
            throw new MalformedSignatureException(
                $sdkInvalidSignatureException->getMessage(),
                $sdkInvalidSignatureException->getCode(),
                previous: $sdkInvalidSignatureException,
            );
        }

        if (! $isValid) {
            $this->logger()->warning('SIWS: signature did not verify against public key', [
                'exception' => InvalidSignatureException::class,
            ]);
            throw new InvalidSignatureException('Invalid signature.');
        }

        // Atomic claim: only one of N concurrent verifiers can be the one
        // that actually removes the nonce. Losers get false and bail out.
        if (! $store->forget($nonce)) {
            $this->logger()->warning('SIWS: nonce already consumed (race)', [
                'exception' => ChallengeNotFoundException::class,
                'reason' => 'concurrent_consumption',
            ]);
            throw new ChallengeNotFoundException('Authentication challenge has already been consumed.');
        }

        $this->logger()->info('SIWS: verification succeeded', []);

        return $this->mapUserToObject([
            'publicKey' => $publicKey,
            'publicKey_parsed' => $parsed,
            'message' => $message,
            'signature' => $signature,
            'nonce' => $nonce,
        ]);
    }

    /**
     * HTTP wrapper around buildChallengeFor(). Reads `publicKey` from the
     * request and returns the challenge as a JsonResponse. Use this from
     * controller routes; use buildChallengeFor() directly from Livewire,
     * queue jobs, or any other non-HTTP context.
     */
    public function challenge(): JsonResponse
    {
        return response()->json($this->buildChallengeFor($this->stringInput('publicKey')));
    }

    /**
     * HTTP wrapper around verifyCredentials(). Reads `publicKey`, `signature`,
     * `message`, and `nonce` from the request. Use this from controller routes;
     * use verifyCredentials() directly from any non-HTTP context.
     */
    #[Override]
    public function user(): User
    {
        return $this->verifyCredentials(
            publicKey: $this->stringInput('publicKey'),
            signature: $this->stringInput('signature'),
            message: $this->stringInput('message'),
            nonce: $this->stringInput('nonce'),
        );
    }

    /**
     * Resolve the ChallengeStore. A container binding for ChallengeStore::class
     * takes precedence; otherwise the `services.solana.store` config value is
     * consulted (`session` default, `cache`, or a fully-qualified class name).
     */
    /**
     * Resolve the logger. Setter-supplied instance wins; otherwise check the
     * container for a bound LoggerInterface; otherwise NullLogger.
     */
    private function logger(): LoggerInterface
    {
        if ($this->logger instanceof LoggerInterface) {
            return $this->logger;
        }

        $container = app();
        if ($container->bound(LoggerInterface::class)) {
            $resolved = $container->make(LoggerInterface::class);
            if ($resolved instanceof LoggerInterface) {
                return $this->logger = $resolved;
            }
        }

        return $this->logger = new NullLogger();
    }

    private function challengeStore(): ChallengeStore
    {
        $container = app();

        if ($container->bound(ChallengeStore::class)) {
            $resolved = $container->make(ChallengeStore::class);
            if (! $resolved instanceof ChallengeStore) {
                throw new LogicException(
                    'Container binding for ' . ChallengeStore::class . ' resolved to ' . get_debug_type($resolved)
                    . '; expected an instance of ' . ChallengeStore::class . '.',
                );
            }

            return $resolved;
        }

        $choice = $this->stringFromConfig($this->solanaConfig(), 'store', 'session');

        return match ($choice) {
            'session' => $this->buildSessionStore(),
            'cache' => $this->buildCacheStore(),
            default => $this->resolveStoreClass($choice),
        };
    }

    private function buildSessionStore(): SessionChallengeStore
    {
        $session = app('session.store');

        if (! $session instanceof Session) {
            throw new LogicException('Unable to resolve the Laravel session driver for SessionChallengeStore.');
        }

        return new SessionChallengeStore($session);
    }

    private function buildCacheStore(): CacheChallengeStore
    {
        $cache = app('cache.store');

        if (! $cache instanceof Repository) {
            throw new LogicException('Unable to resolve the Laravel cache repository for CacheChallengeStore.');
        }

        return new CacheChallengeStore($cache);
    }

    private function resolveStoreClass(string $class): ChallengeStore
    {
        if (! class_exists($class)) {
            throw new LogicException(
                "Configured services.solana.store '{$class}' is not a known store keyword (session|cache) and does not name an existing class.",
            );
        }

        $resolved = app()->make($class);

        if (! $resolved instanceof ChallengeStore) {
            throw new LogicException(
                "Configured services.solana.store '{$class}' does not implement " . ChallengeStore::class . '.',
            );
        }

        return $resolved;
    }

    /**
     * @param array<array-key, mixed> $user
     */
    #[Override]
    protected function mapUserToObject(array $user): User
    {
        if (! isset($user['publicKey']) || ! is_string($user['publicKey']) || $user['publicKey'] === '') {
            throw new InvalidPublicKeyException(
                'mapUserToObject() was called without a valid publicKey. This is an internal misuse.',
            );
        }

        $publicKey = $user['publicKey'];

        return (new User())
            ->setRaw($user)
            ->map([
                'id' => $publicKey,
                'nickname' => null,
                'name' => null,
                'email' => null,
                'avatar' => null,
            ]);
    }

    private function parsePublicKey(string $value): PublicKey
    {
        try {
            return PublicKey::from($value);
        } catch (Throwable $throwable) {
            $this->logger()->warning('SIWS: invalid public key', [
                'exception' => InvalidPublicKeyException::class,
                'input_length' => strlen($value),
                'sdk_message' => $throwable->getMessage(),
            ]);
            throw new InvalidPublicKeyException(
                'Invalid Solana public key: ' . $throwable->getMessage(),
                $throwable->getCode(),
                previous: $throwable,
            );
        }
    }

    private function decodeSignature(string $value): string
    {
        try {
            return Base58::decode($value);
        } catch (InvalidBase58Exception) {
            // fall through to base64
        }

        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            $this->logger()->warning('SIWS: signature is neither base58 nor base64', [
                'exception' => MalformedSignatureException::class,
                'input_length' => strlen($value),
            ]);
            throw new MalformedSignatureException('Signature must be base58 or base64 encoded.');
        }

        return $decoded;
    }

    /**
     * @return array<string, mixed>
     */
    private function solanaConfig(): array
    {
        $cfg = [];
        foreach (Config::array('services.solana', []) as $key => $value) {
            if (is_string($key)) {
                $cfg[$key] = $value;
            }
        }

        return $cfg;
    }

    private function appUrl(): string
    {
        $url = config('app.url', 'http://localhost');

        return is_string($url) ? $url : 'http://localhost';
    }

    private function stringInput(string $key): string
    {
        $value = $this->request->input($key);

        return is_string($value) ? $value : '';
    }

    /**
     * @param array<string, mixed> $cfg
     */
    private function stringFromConfig(array $cfg, string $key, string $default): string
    {
        $value = $cfg[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : $default;
    }

    /**
     * @param array<string, mixed> $cfg
     */
    private function nullableStringFromConfig(array $cfg, string $key): ?string
    {
        $value = $cfg[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @param array<string, mixed> $cfg
     */
    private function intFromConfig(array $cfg, string $key, int $default): int
    {
        $value = $cfg[$key] ?? null;

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && is_numeric($value)) {
            return (int) $value;
        }

        return $default;
    }

    /**
     * @param array<string, mixed> $cfg
     * @return list<string>
     */
    private function resourcesFromConfig(array $cfg): array
    {
        $value = $cfg['resources'] ?? null;

        if (! is_array($value)) {
            return [];
        }

        $resources = [];
        foreach ($value as $resource) {
            if (is_string($resource) && $resource !== '') {
                $resources[] = $resource;
            }
        }

        return $resources;
    }

    #[Override]
    protected function getAuthUrl(mixed $state): string
    {
        return $this->redirectUrl;
    }

    #[Override]
    protected function getTokenUrl(): string
    {
        return '';
    }

    /**
     * @return array<string, mixed>
     */
    #[Override]
    protected function getUserByToken(mixed $token): array
    {
        throw new BadMethodCallException('getUserByToken is not supported by the Solana provider.');
    }

    /**
     * @return array<string, mixed>
     */
    #[Override]
    protected function getTokenFields(mixed $code): array
    {
        return [];
    }

    /**
     * Socialite's manager calls scopes([]) during driver instantiation, so this can
     * not unconditionally throw. Reject only non-empty input so callers that
     * deliberately try to set scopes get a clear error instead of a silent no-op.
     *
     * @param array<array-key, mixed>|string $scopes
     */
    #[Override]
    public function scopes(mixed $scopes): self
    {
        if (is_string($scopes) && $scopes !== '') {
            throw new BadMethodCallException('OAuth scopes are not supported by the Solana provider.');
        }

        if (is_array($scopes) && $scopes !== []) {
            throw new BadMethodCallException('OAuth scopes are not supported by the Solana provider.');
        }

        return $this;
    }
}
