<?php

namespace Francerz\OAuth2\AuthServer\GrantTypes;

use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthServer\AuthorizationCode;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\RefreshToken;
use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;
use Psr\Http\Message\UriInterface;

interface GeneralInterface
{
    // authorize: implicit
    // token: code, owner
    public function issueAccessToken(
        ClientInterface $client,
        ResourceOwnerInterface $owner,
        string $scope
    ): AccessToken;

    // token: client
    public function issueClientAccessToken(ClientInterface $client, string $scope): AccessToken;

    // authorize: code
    public function issueAuthorizationCode(
        ClientInterface $client,
        ResourceOwnerInterface $owner,
        string $scope,
        UriInterface $redirectUri
    ): AuthorizationCode;

    // token: code
    public function findAuthorizationCode(string $code): AuthorizationCode;

    // token: code
    public function updateAuthorizationCodeRedeemTime(AuthorizationCode $authCode);

    // ALL
    // authorize: code, implicit
    // token: code, owner, client
    public function findClient(string $client_id): ClientInterface;

    public function issueRefreshToken(
        ClientInterface $client,
        ResourceOwnerInterface $owner,
        string $scope
    ): RefreshToken;
    // token: refresh_token
    public function findRefreshToken(string $refreshToken): RefreshToken;

    // token: code, refresh_token
    public function findResourceOwner(string $ownerId): ResourceOwnerInterface;

    // authorize: code, implicit
    public function getResourceOwner(): ?ResourceOwnerInterface;
}
