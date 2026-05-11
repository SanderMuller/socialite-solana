<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana\Exceptions;

/**
 * Thrown when an Ed25519 signature, parsed and length-valid, fails to verify
 * against the public key and signed message.
 *
 * The "malformed" sub-case (signature can't be decoded as base58/base64, or
 * decoded but wrong byte length) is reported via the {@see MalformedSignatureException}
 * subclass so consumers that want to split UX can do so; consumers that catch
 * this class continue to catch both cases.
 */
class InvalidSignatureException extends SolanaAuthException {}
