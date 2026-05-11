<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana;

use Stringable;

/**
 * Sign-In With Solana message per Phantom SIWS / CAIP-122 spec.
 *
 * @see https://docs.phantom.app/solana/sign-in-with-solana
 * @see https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md
 */
final readonly class SignInMessage implements Stringable
{
    /**
     * @param list<string> $resources
     */
    public function __construct(
        public string $domain,
        public string $address,
        public ?string $statement,
        public string $uri,
        public string $version,
        public string $chainId,
        public string $nonce,
        public string $issuedAt,
        public ?string $expirationTime = null,
        public ?string $notBefore = null,
        public ?string $requestId = null,
        public array $resources = [],
    ) {}

    public function toString(): string
    {
        $lines = [
            "{$this->domain} wants you to sign in with your Solana account:",
            $this->address,
        ];

        if ($this->statement !== null && $this->statement !== '') {
            $lines[] = '';
            $lines[] = $this->statement;
        }

        $lines[] = '';
        $lines[] = "URI: {$this->uri}";
        $lines[] = "Version: {$this->version}";
        $lines[] = "Chain ID: {$this->chainId}";
        $lines[] = "Nonce: {$this->nonce}";
        $lines[] = "Issued At: {$this->issuedAt}";

        if ($this->expirationTime !== null) {
            $lines[] = "Expiration Time: {$this->expirationTime}";
        }

        if ($this->notBefore !== null) {
            $lines[] = "Not Before: {$this->notBefore}";
        }

        if ($this->requestId !== null) {
            $lines[] = "Request ID: {$this->requestId}";
        }

        if ($this->resources !== []) {
            $lines[] = 'Resources:';
            foreach ($this->resources as $resource) {
                $lines[] = "- {$resource}";
            }
        }

        return implode("\n", $lines);
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}
