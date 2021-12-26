<?php

namespace Francerz\OAuth2\AuthServer\Issuers;

use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;

interface AccessTokenIssuerInterface
{
    public function issueAccessToken(
        ClientInterface $client,
        ResourceOwnerInterface $owner,
        string $scope
    ): AccessToken;
}
