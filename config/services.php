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
        // Required by socialiteproviders/manager but unused by this driver.
        'client_id' => env('SOLANA_CLIENT_ID', 'unused'),
        'client_secret' => env('SOLANA_CLIENT_SECRET', 'unused'),
        'redirect' => env('SOLANA_REDIRECT_URI', '/auth/solana/callback'),

        // Domain shown in the SIWS message. Defaults to APP_URL host.
        'domain' => env('SOLANA_SIWS_DOMAIN'),

        // Canonical URI of the resource being signed in to. Defaults to APP_URL.
        'uri' => env('SOLANA_SIWS_URI'),

        // Human-readable statement included in the SIWS message (optional).
        'statement' => env('SOLANA_SIWS_STATEMENT', 'Sign in to authenticate. This action will not trigger a blockchain transaction or cost any gas.'),

        // Solana cluster: mainnet | devnet | testnet | localnet.
        'chain' => env('SOLANA_SIWS_CHAIN', 'mainnet'),

        // Challenge lifetime in seconds (minimum 60). Most wallets resolve a sign
        // prompt in under 30s; SIWS reference implementations recommend 60-300s.
        'ttl' => (int) env('SOLANA_SIWS_TTL', 180),

        // Optional list<string> of CAIP-122 resources.
        'resources' => [],

        // Challenge storage backend: 'session' (default), 'cache', or a
        // fully-qualified class name implementing
        // SanderMuller\SocialiteSolana\Contracts\ChallengeStore. To inject a
        // fully-customized store, bind the contract in the container instead.
        'store' => env('SOLANA_CHALLENGE_STORE', 'session'),
    ],
];
