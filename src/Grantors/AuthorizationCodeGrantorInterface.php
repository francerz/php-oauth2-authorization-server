<?php

namespace Francerz\OAuth2\AuthServer\Grantors;

use Francerz\OAuth2\AuthServer\AuthorizationCode;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\Finders\ClientFinderInterface;
use Francerz\OAuth2\AuthServer\Finders\ResourceOwnerFinderInterface;
use Francerz\OAuth2\AuthServer\Issuers\AccessTokenIssuerInterface;
use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;
use Psr\Http\Message\UriInterface;

interface AuthorizationCodeGrantorInterface extends
    AuthorizeGrantorInterface,
    TokenGrantorInterface,
    ClientFinderInterface,
    ResourceOwnerFinderInterface,
    AccessTokenIssuerInterface
{
    public function issueAuthorizationCode(
        ClientInterface $client,
        ResourceOwnerInterface $owner,
        string $scope,
        UriInterface $redirectUri,
        ?string $codeChallenge,
        $codeChallengeMethod
    ): AuthorizationCode;
    public function findAuthorizationCode(string $code): AuthorizationCode;
    public function saveAuthorizationCodeRedeemTime(AuthorizationCode $authCode);
}
