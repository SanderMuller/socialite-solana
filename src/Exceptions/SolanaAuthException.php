<?php declare(strict_types=1);

namespace SanderMuller\SocialiteSolana\Exceptions;

use InvalidArgumentException;

/**
 * Base class for every Sign-In With Solana authentication failure.
 *
 * Extends \InvalidArgumentException so callers can keep a single broad catch
 * if they don't need to distinguish between cases.
 */
abstract class SolanaAuthException extends InvalidArgumentException {}
