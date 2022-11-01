<?php

namespace Francerz\OAuth2\AuthServer\Grantors;

use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\Finders\ClientFinderInterface;

/**
 * This interface MUST be implemented in authorization server when supporting
 * Client Credentials flow, providing a client scope access token.
 */
interface ClientCredentialsGrantorInterface extends
    TokenGrantorInterface,
    ClientFinderInterface
{
    public function issueClientAccessToken(ClientInterface $client, string $scope): AccessToken;
}
