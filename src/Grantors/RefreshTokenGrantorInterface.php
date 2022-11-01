<?php

namespace Francerz\OAuth2\AuthServer\Grantors;

use Francerz\OAuth2\AuthServer\Finders\ClientFinderInterface;
use Francerz\OAuth2\AuthServer\Finders\ResourceOwnerFinderInterface;
use Francerz\OAuth2\AuthServer\Issuers\AccessTokenIssuerInterface;
use Francerz\OAuth2\AuthServer\Issuers\RefreshTokenIssuerInterface;
use Francerz\OAuth2\AuthServer\RefreshToken;

/**
 * This interface MUST be implemented when authorization server supports
 * Refresh token issuing and granting.
 */
interface RefreshTokenGrantorInterface extends
    TokenGrantorInterface,
    ClientFinderInterface,
    ResourceOwnerFinderInterface,
    AccessTokenIssuerInterface,
    RefreshTokenIssuerInterface
{
    public function findRefreshToken(string $refreshToken): ?RefreshToken;
}
