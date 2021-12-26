<?php

namespace Francerz\OAuth2\AuthServer\Issuers;

use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\RefreshToken;
use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;

interface RefreshTokenIssuerInterface
{
    public function acquireRefreshToken(ClientInterface $client, ResourceOwnerInterface $owner): ?RefreshToken;
    public function issueRefreshToken(
        ClientInterface $client,
        ResourceOwnerInterface $owner,
        string $scope
    ): RefreshToken;
    public function saveRefreshToken(RefreshToken $refreshToken);
}
