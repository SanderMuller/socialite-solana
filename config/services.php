<?php declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Example Socialite Solana configuration
|--------------------------------------------------------------------------
|
| Merge this block into your application's config/services.php. All keys
| are optional — sensible defaults are applied at runtime.
|
*/

return [
    'solana' => [
        'redirect' => env('SOLANA_REDIRECT_URI', '/auth/solana/callback'),

        // Domain shown in the SIWS message. Defaults to APP_URL host.
        'domain' => env('SOLANA_SIWS_DOMAIN'),

        // Canonical URI of the resource being signed in to. Defaults to APP_URL.
        'uri' => env('SOLANA_SIWS_URI'),

        // Human-readable statement included in the SIWS message (optional).
        'statement' => env('SOLANA_SIWS_STATEMENT', 'Sign in to authenticate. This action will not trigger a blockchain transaction or cost any gas.'),

        // Solana cluster: mainnet | devnet | testnet | localnet.
        'chain' => env('SOLANA_SIWS_CHAIN', 'mainnet'),

        // Challenge lifetime in seconds.
        'ttl' => (int) env('SOLANA_SIWS_TTL', 600),

        // Optional list<string> of CAIP-122 resources.
        'resources' => [],
    ],
];
