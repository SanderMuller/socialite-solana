<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Sign in with Solana</title>
</head>
<body>
<button id="solana-login" type="button" disabled>Connect wallet</button>
<pre id="status"></pre>

<script type="module">
    import bs58 from 'https://esm.sh/bs58@5.0.0';

    /**
     * Wraps wallet-adapter signMessage and returns the signature as a base58
     * string. Drop this helper into your own JS to avoid re-encoding boilerplate
     * at every callsite.
     */
    async function signMessageBase58(walletProvider, message) {
        const encoded = new TextEncoder().encode(message);
        const signed = await walletProvider.signMessage(encoded, 'utf8');

        return bs58.encode(signed.signature);
    }

    const button = document.getElementById('solana-login');
    const status = document.getElementById('status');
    const csrf = document.querySelector('meta[name="csrf-token"]').content;

    const wallet = window.solana;

    if (!wallet?.isPhantom) {
        status.textContent = 'Phantom wallet not detected. Install: https://phantom.app';
    } else {
        button.disabled = false;
    }

    const post = (url, body) => fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-CSRF-TOKEN': csrf,
        },
        credentials: 'same-origin',
        body: JSON.stringify(body),
    });

    button.addEventListener('click', async () => {
        button.disabled = true;
        status.textContent = 'Connecting wallet...';

        try {
            await wallet.connect();
            const publicKey = wallet.publicKey.toBase58();

            status.textContent = 'Requesting challenge...';
            const challengeRes = await post('/auth/solana/challenge', { publicKey });
            if (!challengeRes.ok) {
                throw new Error('Failed to obtain challenge.');
            }
            const { message, nonce } = await challengeRes.json();

            status.textContent = 'Awaiting signature in wallet...';
            const signature = await signMessageBase58(wallet, message);

            const result = await post('/auth/solana/callback', {
                publicKey,
                signature,
                message,
                nonce,
            });

            if (!result.ok) {
                const err = await result.json().catch(() => ({ error: result.statusText }));
                throw new Error(err.error ?? 'Authentication failed');
            }

            const { redirect } = await result.json();
            window.location.href = redirect ?? '/';
        } catch (err) {
            status.textContent = 'Error: ' + err.message;
            button.disabled = false;
        }
    });
</script>
</body>
</html>
