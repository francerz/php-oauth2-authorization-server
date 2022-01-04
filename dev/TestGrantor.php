<?php

namespace Francerz\OAuth2\AuthServer\Dev;

use Francerz\Http\Uri;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthServer\AuthorizationCode;
use Francerz\OAuth2\AuthServer\Client;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\Grantors\AuthorizationCodeGrantorInterface;
use Francerz\OAuth2\AuthServer\Grantors\ClientCredentialsGrantorInterface;
use Francerz\OAuth2\AuthServer\Grantors\ImplicitGrantorInterface;
use Francerz\OAuth2\AuthServer\Grantors\OwnerCredentialsGrantorInterface;
use Francerz\OAuth2\AuthServer\Grantors\RefreshTokenGrantorInterface;
use Francerz\OAuth2\AuthServer\Issuers\RefreshTokenIssuerInterface;
use Francerz\OAuth2\AuthServer\RefreshToken;
use Francerz\OAuth2\AuthServer\ResourceOwner;
use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;
use Francerz\OAuth2\CodeChallengeMethodsEnum;
use Francerz\OAuth2\PKCEHelper;
use Psr\Http\Message\UriInterface;

class TestGrantor implements
    AuthorizationCodeGrantorInterface,
    ImplicitGrantorInterface,
    OwnerCredentialsGrantorInterface,
    ClientCredentialsGrantorInterface,
    RefreshTokenGrantorInterface,
    RefreshTokenIssuerInterface
{
    private $ownerId = '12345';
    private $clientId = 'abcdefghij';
    private $clientRedirectUri = 'https://example.com/oauth2/callback';
    private $clientSecret = 'a1B2c3D4e5';
    private $authCode = 'zyxwvutsrq';
    private $scope = 'scope1 scope2';

    public function setAuthorizationCode(string $authCode)
    {
        $this->authCode = $authCode;
    }
    public function setClientId(string $clientId)
    {
        $this->clientId = $clientId;
    }
    public function getClientId()
    {
        return $this->clientId;
    }
    public function setClientSecret(string $clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }
    public function getClientSecret()
    {
        return $this->clientSecret;
    }
    public function setClientRedirectUri(string $redirectUri)
    {
        $this->clientRedirectUri = $redirectUri;
    }

    public function findClient(string $client_id): ClientInterface
    {
        $client = new Client($client_id, $this->clientSecret, true);
        $client->setRedirectUri($this->clientRedirectUri);
        return $client;
    }

    public function getCurrentResourceOwner(): ?ResourceOwnerInterface
    {
        return new ResourceOwner($this->ownerId);
    }

    public function findResourceOwner(string $ownerId): ?ResourceOwnerInterface
    {
        return new ResourceOwner($ownerId);
    }

    public function acquireResourceOwner(string $user): ?ResourceOwnerInterface
    {
        return new ResourceOwner($this->ownerId);
    }

    public function verifyResourceOwnerPassword(ResourceOwnerInterface $owner, string $password): bool
    {
        return true;
    }

    public function issueAuthorizationCode(
        ClientInterface $client,
        ResourceOwnerInterface $owner,
        string $scope,
        UriInterface $redirectUri,
        ?string $codeChallenge,
        $codeChallengeMethod
    ): AuthorizationCode {
        return new AuthorizationCode(
            $this->authCode,
            $client->getClientId(),
            $owner->getOwnerId(),
            $scope,
            $redirectUri,
            $codeChallenge,
            $codeChallengeMethod
        );
    }

    public function findAuthorizationCode(string $code): AuthorizationCode
    {
        return new AuthorizationCode(
            $code,
            $this->clientId,
            $this->ownerId,
            $this->scope,
            'https://example.com/oauth2/callback',
            PKCEHelper::urlEncode('a0b1c2d3e4f5g6h7i8j9', CodeChallengeMethodsEnum::SHA256),
            CodeChallengeMethodsEnum::SHA256
        );
    }

    public function saveAuthorizationCodeRedeemTime(AuthorizationCode $authCode)
    {
    }

    public function issueAccessToken(
        ClientInterface $client,
        ResourceOwnerInterface $owner,
        string $scope
    ): AccessToken {
        return new AccessToken('abcdefghijklmnopqrstuvwxyz');
    }

    public function issueClientAccessToken(ClientInterface $client, string $scope): AccessToken
    {
        return new AccessToken('zyxwvutsrqponmlkjihgfedcba');
    }

    public function findRefreshToken(string $refreshToken): RefreshToken
    {
        return new RefreshToken($refreshToken, $this->clientId, $this->ownerId, $this->scope);
    }

    public function acquireRefreshToken(ClientInterface $client, ResourceOwnerInterface $owner): ?RefreshToken
    {
        return new RefreshToken('abcdefghij', $client->getClientId(), $owner->getOwnerId(), $this->scope);
    }

    public function issueRefreshToken(
        ClientInterface $client,
        ResourceOwnerInterface $owner,
        string $scope
    ): RefreshToken {
        $this->clientId = $client->getClientId();
        $this->ownerId = $owner->getOwnerId();
        $this->scope = $scope;

        return new RefreshToken('abcdefghijklmnopqrstuvwxyz', $client->getClientId(), $owner->getOwnerId(), $scope);
    }

    public function saveRefreshToken(RefreshToken $refreshToken)
    {
    }
}
