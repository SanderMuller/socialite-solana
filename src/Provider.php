<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana;

use BadMethodCallException;
use Collectiq\SolanaPhpSdk\Exceptions\InputValidationException;
use Collectiq\SolanaPhpSdk\PublicKey;
use Collectiq\SolanaPhpSdk\Util\Buffer;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Laravel\Socialite\Contracts\User as UserContract;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\User;
use Override;
use SocialiteProviders\Manager\ConfigTrait;
use Throwable;

final class Provider extends AbstractProvider
{
    use ConfigTrait;

    public const string IDENTIFIER = 'SOLANA';

    private const string SESSION_KEY_PREFIX = 'solana_auth_challenge:';

    protected $stateless = true;

    /**
     * @return list<string>
     */
    public static function additionalConfigKeys(): array
    {
        return ['domain', 'uri', 'statement', 'chain', 'ttl', 'resources'];
    }

    #[Override]
    public function redirect(): RedirectResponse
    {
        throw new BadMethodCallException(
            'Solana sign-in does not use HTTP redirects. Call challenge() to obtain the SIWS message.',
        );
    }

    public function challenge(): JsonResponse
    {
        $address = $this->stringInput('publicKey');

        if ($address === '') {
            throw new InvalidArgumentException('publicKey is required to build the SIWS message.');
        }

        $this->parsePublicKey($address);

        $cfg = $this->solanaConfig();
        $appUrl = $this->appUrl();
        $domain = $this->stringFromConfig($cfg, 'domain', '');
        if ($domain === '') {
            $host = parse_url($appUrl, PHP_URL_HOST);
            $domain = is_string($host) && $host !== '' ? $host : $this->request->getHost();
        }

        $nonce = Str::random(32);
        $issuedAt = Carbon::now();
        $ttl = max(60, $this->intFromConfig($cfg, 'ttl', 600));
        $expiresAt = $issuedAt->copy()->addSeconds($ttl);

        $message = (new SignInMessage(
            domain: $domain,
            address: $address,
            statement: $this->nullableStringFromConfig($cfg, 'statement'),
            uri: $this->stringFromConfig($cfg, 'uri', $appUrl),
            version: '1',
            chainId: $this->stringFromConfig($cfg, 'chain', 'mainnet'),
            nonce: $nonce,
            issuedAt: $issuedAt->toIso8601ZuluString(),
            expirationTime: $expiresAt->toIso8601ZuluString(),
            resources: $this->resourcesFromConfig($cfg),
        ))->toString();

        Session::put(self::SESSION_KEY_PREFIX . $nonce, [
            'message' => $message,
            'address' => $address,
            'expires_at' => $expiresAt->timestamp,
        ]);

        return response()->json([
            'message' => $message,
            'nonce' => $nonce,
        ]);
    }

    #[Override]
    public function user(): UserContract
    {
        $publicKey = $this->stringInput('publicKey');
        $signature = $this->stringInput('signature');
        $signedMessage = $this->stringInput('message');
        $nonce = $this->stringInput('nonce');

        if ($publicKey === '' || $signature === '' || $signedMessage === '' || $nonce === '') {
            throw new InvalidArgumentException('Missing required parameters: publicKey, signature, message, or nonce.');
        }

        $sessionKey = self::SESSION_KEY_PREFIX . $nonce;
        $challenge = Session::get($sessionKey);

        if (! is_array($challenge)
            || ! isset($challenge['message'], $challenge['address'], $challenge['expires_at'])
            || ! is_string($challenge['message'])
            || ! is_string($challenge['address'])
            || ! is_int($challenge['expires_at'])
        ) {
            throw new InvalidArgumentException('Authentication challenge expired or invalid.');
        }

        if (! hash_equals($challenge['message'], $signedMessage)) {
            throw new InvalidArgumentException('Signed message does not match expected message.');
        }

        if (! hash_equals($challenge['address'], $publicKey)) {
            throw new InvalidArgumentException('Signer address does not match challenge address.');
        }

        if (Carbon::now()->timestamp > $challenge['expires_at']) {
            throw new InvalidArgumentException('Authentication challenge has expired.');
        }

        $pubkey = $this->parsePublicKey($publicKey);
        $signatureBytes = $this->decodeSignature($signature);

        try {
            $isValid = $pubkey->verify($signedMessage, $signatureBytes);
        } catch (InputValidationException $inputValidationException) {
            throw new InvalidArgumentException(
                $inputValidationException->getMessage(),
                $inputValidationException->getCode(),
                previous: $inputValidationException,
            );
        }

        if (! $isValid) {
            throw new InvalidArgumentException('Invalid signature.');
        }

        Session::forget($sessionKey);

        return $this->mapUserToObject([
            'publicKey' => $publicKey,
            'message' => $signedMessage,
            'signature' => $signature,
            'nonce' => $nonce,
        ]);
    }

    /**
     * @param array<array-key, mixed> $user
     */
    #[Override]
    protected function mapUserToObject(array $user): UserContract
    {
        $publicKey = isset($user['publicKey']) && is_string($user['publicKey'])
            ? $user['publicKey']
            : '';

        return (new User())
            ->setRaw($user)
            ->map([
                'id' => $publicKey,
                'nickname' => $publicKey,
                'name' => $publicKey,
                'email' => null,
                'avatar' => null,
            ]);
    }

    private function parsePublicKey(string $value): PublicKey
    {
        try {
            return PublicKey::from($value);
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException(
                'Invalid Solana public key: ' . $throwable->getMessage(),
                $throwable->getCode(),
                previous: $throwable,
            );
        }
    }

    private function decodeSignature(string $value): string
    {
        try {
            return Buffer::fromBase58($value)->toBinaryString();
        } catch (Throwable) {
            // fall through to base64
        }

        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            throw new InvalidArgumentException('Signature must be base58 or base64 encoded.');
        }

        return $decoded;
    }

    /**
     * @return array<string, mixed>
     */
    private function solanaConfig(): array
    {
        $raw = config('services.solana');

        if (! is_array($raw)) {
            return [];
        }

        $cfg = [];
        foreach ($raw as $key => $value) {
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
     * @param array<array-key, mixed>|string $scopes
     */
    #[Override]
    public function scopes(mixed $scopes): self
    {
        return $this;
    }
}
