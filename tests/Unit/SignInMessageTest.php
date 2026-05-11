<?php declare(strict_types=1);

use SanderMuller\SocialiteSolana\SignInMessage;

it('renders required SIWS fields', function (): void {
    $message = new SignInMessage(
        domain: 'example.test',
        address: 'Fh7s4WkPgVZBkU3xCqAd9kQp1234567890abcdefghij',
        statement: 'Sign in to TestApp.',
        uri: 'https://example.test',
        version: '1',
        chainId: 'mainnet',
        nonce: 'abc123',
        issuedAt: '2026-05-11T12:00:00Z',
    );

    $rendered = $message->toString();

    expect($rendered)
        ->toContain('example.test wants you to sign in with your Solana account:')
        ->toContain('Fh7s4WkPgVZBkU3xCqAd9kQp1234567890abcdefghij')
        ->toContain('Sign in to TestApp.')
        ->toContain('URI: https://example.test')
        ->toContain('Version: 1')
        ->toContain('Chain ID: mainnet')
        ->toContain('Nonce: abc123')
        ->toContain('Issued At: 2026-05-11T12:00:00Z');
});

it('omits optional fields when null', function (): void {
    $rendered = (new SignInMessage(
        domain: 'example.test',
        address: 'addr',
        statement: null,
        uri: 'https://example.test',
        version: '1',
        chainId: 'mainnet',
        nonce: 'n',
        issuedAt: 'i',
    ))->toString();

    expect($rendered)
        ->not->toContain('Expiration Time:')
        ->not->toContain('Not Before:')
        ->not->toContain('Request ID:')
        ->not->toContain('Resources:');
});

it('renders resources as bullet list', function (): void {
    $rendered = (new SignInMessage(
        domain: 'example.test',
        address: 'addr',
        statement: null,
        uri: 'https://example.test',
        version: '1',
        chainId: 'mainnet',
        nonce: 'n',
        issuedAt: 'i',
        resources: ['https://example.test/tos', 'https://example.test/privacy'],
    ))->toString();

    expect($rendered)
        ->toContain("Resources:\n- https://example.test/tos\n- https://example.test/privacy");
});

it('casts to string', function (): void {
    $message = new SignInMessage(
        domain: 'example.test',
        address: 'addr',
        statement: null,
        uri: 'https://example.test',
        version: '1',
        chainId: 'mainnet',
        nonce: 'n',
        issuedAt: 'i',
    );

    expect((string) $message)->toBe($message->toString());
});
