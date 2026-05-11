<?php declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Example routes for Socialite Solana
|--------------------------------------------------------------------------
|
| These routes demonstrate the SIWS sign-in flow. Copy them into your own
| application's routes/web.php and adapt the User model to your project.
|
*/

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;

Route::view('/auth/solana', 'auth.solana-login')->middleware('web');

// 1. Frontend connects wallet, then POSTs its public key to receive the SIWS challenge.
Route::post('/auth/solana/challenge', function () {
    return Socialite::driver('solana')->challenge();
})->middleware('web');

// 2. Frontend POSTs publicKey + nonce + message + signature once the wallet signs.
Route::post('/auth/solana/callback', function (Request $request) {
    try {
        $solanaUser = Socialite::driver('solana')->user();

        $userModel = config('auth.providers.users.model', App\Models\User::class);

        $user = $userModel::firstOrCreate(
            ['solana_public_key' => $solanaUser->getId()],
            [
                'name' => $solanaUser->getName(),
                'email' => null,
                'password' => Hash::make(Str::random(32)),
            ],
        );

        Auth::login($user, true);

        return response()->json(['redirect' => '/home']);
    } catch (InvalidArgumentException $e) {
        Log::warning('Solana auth rejected: ' . $e->getMessage());

        return response()->json(['error' => $e->getMessage()], 422);
    } catch (Throwable $e) {
        Log::error('Solana auth failed: ' . $e->getMessage());

        return response()->json(['error' => 'Authentication failed.'], 500);
    }
})->middleware('web');
