<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana;

use SocialiteProviders\Manager\SocialiteWasCalled;

final class SocialiteSolanaExtendSocialite
{
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        $socialiteWasCalled->extendSocialite('solana', Provider::class);
    }
}
