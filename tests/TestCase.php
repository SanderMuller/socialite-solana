<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana\Tests;

use Laravel\Socialite\SocialiteServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use SanderMuller\SocialiteSolana\SocialiteSolanaExtendSocialite;
use SocialiteProviders\Manager\ServiceProvider as SocialiteProvidersServiceProvider;
use SocialiteProviders\Manager\SocialiteWasCalled;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            SocialiteServiceProvider::class,
            SocialiteProvidersServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.url', 'https://example.test');
        $app['config']->set('app.name', 'TestApp');

        $app['config']->set('services.solana', [
            'client_id' => 'solana',
            'client_secret' => 'solana',
            'redirect' => '/auth/solana/callback',
            'domain' => 'example.test',
            'uri' => 'https://example.test',
            'statement' => 'Sign in to TestApp.',
            'chain' => 'mainnet',
            'ttl' => 600,
            'resources' => [],
        ]);

        $app['events']->listen(
            SocialiteWasCalled::class,
            [SocialiteSolanaExtendSocialite::class, 'handle'],
        );
    }
}
