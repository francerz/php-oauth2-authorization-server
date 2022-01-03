<?php

namespace Francerz\OAuth2\AuthServer\Grantors;

use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\Finders\ClientFinderInterface;

interface ClientCredentialsGrantorInterface extends
    TokenGrantorInterface,
    ClientFinderInterface
{
    public function issueClientAccessToken(ClientInterface $client, string $scope): AccessToken;
}
