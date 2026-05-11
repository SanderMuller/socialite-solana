<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana\Exceptions;

/**
 * Thrown when the submitted signature cannot be decoded or has the wrong byte
 * length — i.e. the wallet did not produce a valid 64-byte Ed25519 signature
 * blob in the first place. This is the "malformed input" case, distinct from
 * a correctly-shaped signature that simply fails verification.
 *
 * Extends {@see InvalidSignatureException} so consumers that catch the parent
 * keep their existing behavior; only consumers that want to split UX (e.g.
 * "try a different wallet" vs "user switched wallets mid-flow") need to add
 * a specific catch block for this subclass.
 */
final class MalformedSignatureException extends InvalidSignatureException {}
