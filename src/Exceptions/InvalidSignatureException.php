<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana\Exceptions;

/**
 * Thrown when the signature is malformed (wrong length, invalid encoding)
 * or fails Ed25519 verification against the public key and message.
 */
final class InvalidSignatureException extends SolanaAuthException {}
