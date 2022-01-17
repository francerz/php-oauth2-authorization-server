<?php

namespace Francerz\OAuth2\AuthServer;

use DateTimeImmutable;
use Fig\Http\Message\StatusCodeInterface;
use Francerz\Http\Utils\Headers\BasicAuthorizationHeader;
use Francerz\Http\Utils\HttpHelper;
use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\Exceptions\TokenInvalidClientException;
use Francerz\OAuth2\AuthServer\Exceptions\TokenInvalidGrantException;
use Francerz\OAuth2\AuthServer\Exceptions\TokenInvalidRequestException;
use Francerz\OAuth2\AuthServer\Exceptions\TokenInvalidScopeException;
use Francerz\OAuth2\AuthServer\Exceptions\TokenUnauthorizedClientException;
use Francerz\OAuth2\AuthServer\Exceptions\TokenUnsupportedGrantTypeException;
use Francerz\OAuth2\AuthServer\Finders\ClientFinderInterface;
use Francerz\OAuth2\AuthServer\Grantors\AuthorizationCodeGrantorInterface;
use Francerz\OAuth2\AuthServer\Grantors\ClientCredentialsGrantorInterface;
use Francerz\OAuth2\AuthServer\Grantors\OwnerCredentialsGrantorInterface;
use Francerz\OAuth2\AuthServer\Grantors\RefreshTokenGrantorInterface;
use Francerz\OAuth2\AuthServer\Issuers\RefreshTokenIssuerInterface;
use Francerz\OAuth2\ClientTypesEnum;
use Francerz\OAuth2\CodeChallengeMethodsEnum;
use Francerz\OAuth2\GrantTypesEnum;
use Francerz\OAuth2\OAuth2Error;
use Francerz\OAuth2\PKCEHelper;
use Francerz\OAuth2\ScopeHelper;
use Francerz\OAuth2\TokenErrorEnum;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Throwable;

class TokenEndpointHandler
{
    private $codeGrantor;
    private $ownerGrantor;
    private $clientGrantor;
    private $refreshTokenGrantor;

    private $responseFactory;

    private $grantType;
    private $clientId;
    private $clientSecret;
    private $code;
    private $redirectUri;
    private $username;
    private $password;
    private $scope;
    private $refreshToken;

    private $codeVerifier;

    public function __construct(ResponseFactoryInterface $responseFactory)
    {
        $this->responseFactory = $responseFactory;
    }

    public function initFromRequest(ServerRequestInterface $request)
    {
        $post = $request->getParsedBody();
        $this->setGrantType($post['grant_type'] ?? null);
        $this->setCode($post['code'] ?? null);
        $this->setRedirectUri($post['redirect_uri'] ?? null);
        $this->setClientId($post['client_id'] ?? null);
        $this->setUsername($post['username'] ?? null);
        $this->setPassword($post['password'] ?? null);
        $this->setScope($post['scope'] ?? null);
        $this->setRefreshToken($post['refresh_token'] ?? null);
        $this->setCodeVerifier($post['code_verifier'] ?? null);

        self::fetchClientCredentials($request, $clientId, $clientSecret);
        if (isset($clientId)) {
            $this->setClientId($clientId);
            $this->setClientSecret($clientSecret);
        }
    }

    private static function fetchClientCredentials(
        ServerRequestInterface $request,
        ?string &$clientId = '',
        ?string &$clientSecret = ''
    ) {
        $auths = HttpHelper::getAuthorizationHeaders($request);
        if (isset($auths)) {
            $auth = reset($auths);
            if (isset($auth) && $auth instanceof BasicAuthorizationHeader) {
                $clientId = $auth->getUser();
                $clientSecret = $auth->getPassword();
                return;
            }
        }

        $params = $request->getParsedBody();
        if (is_object($params)) {
            $params = (array)$params;
        }
        if (!is_array($params)) {
            return;
        }
        if (array_key_exists('client_id', $params)) {
            $clientId = $params['client_id'];
        }
        if (array_key_exists('client_secret', $params)) {
            $clientSecret = $params['client_secret'];
        }
    }

    private static function issueRefreshToken(
        RefreshTokenIssuerInterface $issuer,
        ClientInterface $client,
        ResourceOwnerInterface $owner,
        string $scope
    ): RefreshToken {
        $refreshToken = $issuer->acquireRefreshToken($client, $owner);
        if (is_null($refreshToken)) {
            return $issuer->issueRefreshToken($client, $owner, $scope);
        }

        $rtScope = ScopeHelper::toArray($refreshToken->getScope());
        $newScope = ScopeHelper::merge($rtScope, $scope);
        if (count($rtScope) === count($newScope)) {
            return $refreshToken;
        }

        $refreshToken->setScope(ScopeHelper::toString($newScope));
        $issuer->saveRefreshToken($refreshToken);
        return $refreshToken;
    }

    private function buildAccessTokenResponse(AccessToken $accessToken): ResponseInterface
    {
        $response = $this->responseFactory
            ->createResponse(StatusCodeInterface::STATUS_OK)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache')
            ->withHeader('Content-Type', 'application/json; charset=utf-8');
        $response->getBody()->write(json_encode($accessToken));
        return $response;
    }

    private function fetchClient(ClientFinderInterface $finder): ClientInterface
    {
        if (empty($this->clientId)) {
            throw new TokenInvalidRequestException('Missing client_id identifier.');
        }

        $client = $finder->findClient($this->clientId);
        if (!isset($client)) {
            throw new TokenInvalidClientException("Cannot found client with client_id '{$this->clientId}'.");
        }

        if ($client->getClientType() == ClientTypesEnum::TYPE_CONFIDENTIAL) {
            if (empty($this->clientSecret)) {
                throw new TokenInvalidClientException("Missing required 'client_secret'.");
            }
            if ($client->getClientSecret() !== $this->clientSecret) {
                throw new TokenInvalidClientException("Given 'client_secret' mismatch with real 'client_secret'.");
            }
        }

        return $client;
    }

    public function setCodeGrantor(AuthorizationCodeGrantorInterface $grantor)
    {
        $this->codeGrantor = $grantor;
    }

    public function setOwnerGrantor(OwnerCredentialsGrantorInterface $grantor)
    {
        $this->ownerGrantor = $grantor;
    }

    public function setClientGrantor(ClientCredentialsGrantorInterface $grantor)
    {
        $this->clientGrantor = $grantor;
    }

    public function setRefreshTokenGrantor(RefreshTokenGrantorInterface $grantor)
    {
        $this->refreshTokenGrantor = $grantor;
    }

    /**
     * @param GrantTypesEnum|string|null $grantType
     */
    public function setGrantType($grantType)
    {
        $this->grantType = $grantType;
    }

    public function setClientId(?string $clientId)
    {
        $this->clientId = $clientId;
    }

    public function setClientSecret(?string $clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    public function setCode(?string $code)
    {
        $this->code = $code;
    }

    /**
     * @param UriInterface|string|null $redirectUri
     */
    public function setRedirectUri($redirectUri)
    {
        if ($redirectUri instanceof UriInterface) {
            $redirectUri = (string)$redirectUri;
        }
        $this->redirectUri = $redirectUri;
    }

    public function setUsername(?string $username)
    {
        $this->username = $username;
    }

    public function setPassword(?string $password)
    {
        $this->password = $password;
    }

    /**
     * @param string|string[]|null $scope
     */
    public function setScope($scope)
    {
        $this->scope = ScopeHelper::toString($scope);
    }

    public function setRefreshToken(?string $refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }

    public function setCodeVerifier(?string $codeVerifier)
    {
        $this->codeVerifier = $codeVerifier;
    }

    public function handle(): ResponseInterface
    {
        if (!isset($this->grantType)) {
            throw new TokenInvalidRequestException('Missing grant_type attribute.');
        }
        switch ($this->grantType) {
            case GrantTypesEnum::AUTHORIZATION_CODE:
                if (!isset($this->codeGrantor)) {
                    throw new TokenUnsupportedGrantTypeException($this->grantType);
                }
                return $this->handleCodeRequest();
            case GrantTypesEnum::PASSWORD:
                if (!isset($this->ownerGrantor)) {
                    throw new TokenUnsupportedGrantTypeException($this->grantType);
                }
                return $this->handlePasswordRequest();
            case GrantTypesEnum::CLIENT_CREDENTIALS:
                if (!isset($this->clientGrantor)) {
                    throw new TokenUnsupportedGrantTypeException($this->grantType);
                }
                return $this->handleClientCredentialsRequest();
            case GrantTypesEnum::REFRESH_TOKEN:
                if (!isset($this->refreshTokenGrantor)) {
                    throw new TokenUnsupportedGrantTypeException($this->grantType);
                }
                return $this->handleRefreshTokenRequest();
            default:
                throw new TokenUnsupportedGrantTypeException($this->grantType);
        }
    }

    private function isValidCodeChallenge(AuthorizationCode $authCode): bool
    {
        $codeChallenge = $authCode->getCodeChallenge();
        $codeVerifier = $this->codeVerifier;
        if (is_null($codeChallenge)) {
            return true;
        }
        if (is_null($codeVerifier)) {
            return false;
        }
        if ($authCode->getCodeChallengeMethod() == CodeChallengeMethodsEnum::SHA256) {
            $codeVerifier = PKCEHelper::urlEncode($codeVerifier, CodeChallengeMethodsEnum::SHA256);
        }
        return $codeVerifier === $codeChallenge;
    }

    private function handleCodeRequest(): ResponseInterface
    {
        $client = $this->fetchClient($this->codeGrantor);

        if (!isset($this->code)) {
            throw new TokenInvalidRequestException("Missing required 'code' attribute.");
        }
        $authCode = $this->codeGrantor->findAuthorizationCode($this->code);
        if ($authCode->getClientId() != $client->getClientId()) {
            throw new TokenInvalidGrantException("This Authorization code was issued to another client.");
        }
        if (!empty($authCode->getRedirectUri()) && $authCode->getRedirectUri() !== $this->redirectUri) {
            throw new TokenInvalidGrantException('Redirect uri not matching with code redirect_uri.');
        }
        if ($authCode->isUsed()) {
            throw new TokenInvalidGrantException('Authorization code is already used.');
        }
        if ($authCode->isExpired()) {
            throw new TokenInvalidGrantException('Authorization code expired.');
        }
        if (!$this->isValidCodeChallenge($authCode)) {
            throw new TokenInvalidGrantException('Mismatch PKCE code_verifier with code_challenge');
        }

        $owner = $this->codeGrantor->findResourceOwner($authCode->getOwnerId());
        if (!isset($owner)) {
            throw new TokenInvalidGrantException('Internal error: Cannot find Code\'s resource owner.');
        }
        $authCode->setRedeemTime(new DateTimeImmutable());
        $this->codeGrantor->saveAuthorizationCodeRedeemTime($authCode);

        $accessToken = $this->codeGrantor->issueOwnerAccessToken($client, $owner, $authCode->getScope());
        if ($this->codeGrantor instanceof RefreshTokenIssuerInterface) {
            $refreshToken = static::issueRefreshToken($this->codeGrantor, $client, $owner, $authCode->getScope());
            $accessToken->setRefreshToken((string)$refreshToken);
        }
        return $this->buildAccessTokenResponse($accessToken);
    }

    private function handlePasswordRequest(): ResponseInterface
    {
        $client = $this->fetchClient($this->ownerGrantor);

        $owner = $this->ownerGrantor->acquireResourceOwner($this->username);
        if (!isset($owner)) {
            throw new TokenInvalidGrantException('Invalid resource owner username.');
        }
        if (!$this->ownerGrantor->verifyResourceOwnerPassword($owner, $this->password)) {
            throw new TokenInvalidGrantException('Incorrect resource owner credentials.');
        }
        $accessToken = $this->ownerGrantor->issueOwnerAccessToken($client, $owner, $this->scope);
        if ($this->ownerGrantor instanceof RefreshTokenIssuerInterface) {
            $refreshToken = static::issueRefreshToken($this->ownerGrantor, $client, $owner, $this->scope);
            $accessToken->setRefreshToken((string)$refreshToken);
        }
        return $this->buildAccessTokenResponse($accessToken);
    }

    private function handleClientCredentialsRequest(): ResponseInterface
    {
        $client = $this->fetchClient($this->clientGrantor);
        $accessToken = $this->clientGrantor->issueClientAccessToken($client, $this->scope ?? '');
        return $this->buildAccessTokenResponse($accessToken);
    }

    private function handleRefreshTokenRequest(): ResponseInterface
    {
        $client = $this->fetchClient($this->refreshTokenGrantor);

        if (!isset($this->refreshToken)) {
            throw new TokenInvalidRequestException('Missing required refresh_token attribute.');
        }
        $refreshToken = $this->refreshTokenGrantor->findRefreshToken($this->refreshToken);
        if (!isset($refreshToken)) {
            throw new TokenInvalidGrantException('Invalid refresh_token.');
        }
        if ($refreshToken->getClientId() !== $client->getClientId()) {
            throw new TokenInvalidGrantException('Refresh token not matches with client credentials.');
        }
        $resourceOwner = $this->refreshTokenGrantor->findResourceOwner($refreshToken->getOwnerId());
        if (!isset($resourceOwner)) {
            throw new TokenInvalidGrantException('Internal error: Cannot find resource owner of this refresh token.');
        }
        $accessToken = $this->refreshTokenGrantor->issueOwnerAccessToken($client, $resourceOwner, $refreshToken->getScope());
        return $this->buildAccessTokenResponse($accessToken);
    }

    public function catch(Throwable $ex): ResponseInterface
    {
        $error = $this->catchExceptionError($ex);
        $status = StatusCodeInterface::STATUS_BAD_REQUEST;
        switch ($error->getError()) {
            case TokenErrorEnum::INVALID_CLIENT:
                $status = StatusCodeInterface::STATUS_UNAUTHORIZED;
                break;
            case 'server_error':
                $status = StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR;
                break;
        }
        $response = $this->responseFactory->createResponse($status);
        $response->getBody()->write(json_encode($error));
        if ($status === StatusCodeInterface::STATUS_UNAUTHORIZED) {
            $response = $response->withHeader('WWW-Authenticate', 'Basic');
        }
        return $response;
    }

    private function catchExceptionError(Throwable $ex)
    {
        if ($ex instanceof TokenInvalidClientException) {
            return new OAuth2Error(TokenErrorEnum::INVALID_CLIENT, $ex->getMessage());
        }
        if ($ex instanceof TokenInvalidGrantException) {
            return new OAuth2Error(TokenErrorEnum::INVALID_GRANT, $ex->getMessage());
        }
        if ($ex instanceof TokenInvalidRequestException) {
            return new OAuth2Error(TokenErrorEnum::INVALID_REQUEST, $ex->getMessage());
        }
        if ($ex instanceof TokenInvalidScopeException) {
            return new OAuth2Error(TokenErrorEnum::INVALID_SCOPE, $ex->getMessage());
        }
        if ($ex instanceof TokenUnauthorizedClientException) {
            return new OAuth2Error(TokenErrorEnum::UNAUTHORIZED_CLIENT, $ex->getMessage());
        }
        if ($ex instanceof TokenUnsupportedGrantTypeException) {
            return new OAuth2Error(TokenErrorEnum::UNSUPPORTED_GRANT_TYPE, $ex->getMessage());
        }
        return new OAuth2Error('server_error', $ex->getMessage());
    }
}
