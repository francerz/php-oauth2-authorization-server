<?php

namespace Francerz\OAuth2\AuthServer\Grantors;

use Francerz\OAuth2\AuthServer\Finders\ClientFinderInterface;
use Francerz\OAuth2\AuthServer\Finders\ResourceOwnerFinderInterface;
use Francerz\OAuth2\AuthServer\Issuers\AccessTokenIssuerInterface;
use Francerz\OAuth2\AuthServer\Issuers\RefreshTokenIssuerInterface;
use Francerz\OAuth2\AuthServer\RefreshToken;

interface RefreshTokenGrantorInterface extends
    ClientFinderInterface,
    ResourceOwnerFinderInterface,
    AccessTokenIssuerInterface
{
    public function findRefreshToken(string $refreshToken): RefreshToken;
}
