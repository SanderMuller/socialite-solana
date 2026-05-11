<?php declare(strict_types=1);

use Laravel\Socialite\Facades\Socialite;
use SanderMuller\SocialiteSolana\Provider;

it('registers the solana driver with Socialite', function (): void {
    $driver = Socialite::driver('solana');

    expect($driver)->toBeInstanceOf(Provider::class);
});
