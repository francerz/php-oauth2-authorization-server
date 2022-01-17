<?php

namespace Francerz\OAuth2\AuthServer;

use Fig\Http\Message\StatusCodeInterface;
use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\AuthorizeErrorEnum;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeAccessDeniedException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeInvalidRequestException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeInvalidScopeException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeServerErrorException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeTemporarilyUnavailableException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeUnauthorizedClientException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeUnsupportedResponseTypeException;
use Francerz\OAuth2\AuthServer\Grantors\AuthorizationCodeGrantorInterface;
use Francerz\OAuth2\AuthServer\Grantors\ImplicitGrantorInterface;
use Francerz\OAuth2\CodeChallengeMethodsEnum;
use Francerz\OAuth2\OAuth2Error;
use Francerz\OAuth2\ResponseTypesEnum;
use Francerz\OAuth2\ScopeHelper;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Message\UriFactoryInterface;
use Throwable;

class AuthorizeGrantHandler
{
    private $codeGrantor;
    private $implicitGrantor;

    private $responseFactory;
    private $uriFactory;

    /** @var string */
    private $clientId;

    /** @var string */
    private $responseType;

    /** @var UriInterface */
    private $redirectUri;

    /** @var string */
    private $scope;

    /** @var string */
    private $state;

    /** @var string|null */
    private $codeChallenge;
    private $codeChallengeMethod;

    public function __construct(
        ResponseFactoryInterface $responseFactory,
        UriFactoryInterface $uriFactory
    ) {
        $this->responseFactory = $responseFactory;
        $this->uriFactory = $uriFactory;
    }

    public function setCodeGrantor(AuthorizationCodeGrantorInterface $grantor)
    {
        $this->codeGrantor = $grantor;
    }

    public function setImplicitGrantor(ImplicitGrantorInterface $grantor)
    {
        $this->implicitGrantor = $grantor;
    }

    #region Setters and Getters
    /**
     * @param string $clientId
     * @return void
     */
    public function setClientId($clientId)
    {
        if (is_null($clientId)) {
            return;
        }
        $this->clientId = $clientId;
    }

    /**
     * @param ResponseTypesEnum|string|null $responseType
     * @return void
     */
    public function setResponseType($responseType)
    {
        $this->responseType = $responseType;
    }

    /**
     * @param UriInterface|string|null $redirectUri
     * @return void
     */
    public function setRedirectUri($redirectUri)
    {
        if (is_string($redirectUri)) {
            $redirectUri = $this->uriFactory->createUri($redirectUri);
        }
        $this->redirectUri = $redirectUri;
    }

    /**
     * @param string|string[]|null $scope
     * @return void
     */
    public function setScope($scope)
    {
        $this->scope = ScopeHelper::toString($scope);
    }

    /**
     * @param string|null $state
     * @return void
     */
    public function setState($state)
    {
        $this->state = $state;
    }

    /**
     * @param string|null $codeChallenge
     * @return void
     */
    public function setCodeChallenge(?string $codeChallenge)
    {
        $this->codeChallenge = $codeChallenge;
    }

    /**
     * @param string|null $codeChallengeMethod
     * @return void
     */
    public function setCodeChallengeMethod($codeChallengeMethod)
    {
        if (is_null($codeChallengeMethod)) {
            $codeChallengeMethod = CodeChallengeMethodsEnum::PLAIN;
        }
        $this->codeChallengeMethod = CodeChallengeMethodsEnum::coerce($codeChallengeMethod);
    }
    #endregion

    public function initFromRequest(ServerRequestInterface $request)
    {
        $body = $request->getParsedBody();
        $this->initFromParamsArray($body);
    }

    public function initFromParamsArray($params)
    {
        if (!is_array($params)) {
            return;
        }
        $this->setClientId($params['client_id'] ?? null);
        $this->setResponseType($params['response_type'] ?? null);
        $this->setRedirectUri($params['redirect_uri'] ?? null);
        $this->setScope($params['scope'] ?? null);
        $this->setState($params['state'] ?? null);
        $this->setCodeChallenge($params['code_challenge'] ?? null);
        $this->setCodeChallengeMethod($params['code_challenge_method'] ?? null);
    }

    public function handle(bool $approved): ResponseInterface
    {
        if (!isset($this->clientId)) {
            throw new AuthorizeInvalidRequestException("Missing 'client_id' attribute.");
        }
        if (!isset($this->responseType)) {
            throw new AuthorizeInvalidRequestException("Missing 'response_type' attribute.");
        }
        if (!$approved) {
            throw new AuthorizeAccessDeniedException('Resource Owner explicity denied authorization.');
        }

        switch ($this->responseType) {
            case ResponseTypesEnum::AUTHORIZATION_CODE:
                if (!isset($this->codeGrantor)) {
                    throw new AuthorizeUnsupportedResponseTypeException($this->responseType);
                }
                return $this->handleAuthorizationCodeRequest();
            case ResponseTypesEnum::TOKEN:
                if (!isset($this->implicitGrantor)) {
                    throw new AuthorizeUnsupportedResponseTypeException($this->responseType);
                }
                return $this->handleImplicitRequest();
            default:
                throw new AuthorizeUnsupportedResponseTypeException($this->responseType);
        }
    }

    private function handleAuthorizationCodeRequest(): ResponseInterface
    {
        $client = $this->codeGrantor->findClient($this->clientId);
        if (!isset($client)) {
            throw new AuthorizeInvalidRequestException("Invalid client_id.");
        }
        $owner = $this->codeGrantor->getCurrentResourceOwner();
        if (!isset($owner)) {
            throw new AuthorizeServerErrorException("Failed retrieving resource owner profile.");
        }
        $code = $this->codeGrantor->issueAuthorizationCode(
            $client,
            $owner,
            $this->scope,
            $this->redirectUri,
            $this->codeChallenge,
            $this->codeChallengeMethod
        );

        $uriParams = ['code' => (string)$code];
        if (isset($this->state)) {
            $uriParams['state'] = $this->state;
        }
        $redirectUri = UriHelper::withQueryParams($this->redirectUri, $uriParams);

        return $this->responseFactory
            ->createResponse(StatusCodeInterface::STATUS_FOUND)
            ->withHeader('Location', (string)$redirectUri);
    }

    private function handleImplicitRequest(): ResponseInterface
    {
        $client = $this->implicitGrantor->findClient($this->clientId);
        if (!isset($client)) {
            throw new AuthorizeInvalidRequestException('Invalid client_id.');
        }
        $owner = $this->implicitGrantor->getCurrentResourceOwner();
        if (!isset($owner)) {
            throw new AuthorizeServerErrorException('Failed retrieving resource owner profile.');
        }

        $accessToken = $this->implicitGrantor->issueOwnerAccessToken($client, $owner, $this->scope);

        $uriParams = [
            'access_token' => $accessToken->getAccessToken(),
            'token_type' => $accessToken->getTokenType(),
            'expires_in' => $accessToken->getExpiresIn(),
            'scope' => $this->scope
        ];
        if (isset($this->state)) {
            $uriParams['state'] = $this->state;
        }
        $redirectUri = UriHelper::withFragmentParams($this->redirectUri, $uriParams);

        return $this->responseFactory
            ->createResponse(StatusCodeInterface::STATUS_FOUND)
            ->withHeader('Location', (string)$redirectUri);
    }

    public function catch(Throwable $ex)
    {
        if (is_null($this->redirectUri)) {
            $error = $this->catchExceptionError(new AuthorizeInvalidRequestException(
                "Missing required 'redirect_uri' attribute."
            ));
            $response = $this->responseFactory->createResponse(StatusCodeInterface::STATUS_BAD_REQUEST);
            $response->getBody()->write($error->getErrorDescription());
            return $response;
        }
        switch ($this->responseType) {
            case ResponseTypesEnum::AUTHORIZATION_CODE:
                $error = $this->catchExceptionError($ex);
                $redirectUri = UriHelper::withQueryParams($this->redirectUri, $error->toAssoc());
                if (isset($this->state)) {
                    $redirectUri = UriHelper::withQueryParam($redirectUri, 'state', $this->state);
                }
                return $this->responseFactory
                    ->createResponse(StatusCodeInterface::STATUS_FOUND)
                    ->withHeader('Location', (string)$redirectUri);
            case ResponseTypesEnum::TOKEN:
                $error = $this->catchExceptionError($ex);
                $redirectUri = UriHelper::withFragmentParams($this->redirectUri, $error->toAssoc());
                if (isset($this->state)) {
                    $redirectUri = UriHelper::withFragmentParam($redirectUri, 'state', $this->state);
                }
                return $this->responseFactory
                    ->createResponse(StatusCodeInterface::STATUS_FOUND)
                    ->withHeader('Location', (string)$redirectUri);
            default:
                $error = $this->catchExceptionError(new AuthorizeInvalidRequestException(
                    "Unknown response_type '{$this->responseType}'."
                ));
                $response = $this->responseFactory->createResponse(StatusCodeInterface::STATUS_BAD_REQUEST);
                $response->getBody()->write($error->getErrorDescription());
                return $response;
        }
    }

    private function catchExceptionError(Throwable $ex)
    {
        if ($ex instanceof AuthorizeAccessDeniedException) {
            return new OAuth2Error(AuthorizeErrorEnum::ACCESS_DENIED, $ex->getMessage());
        }
        if ($ex instanceof AuthorizeInvalidRequestException) {
            return new OAuth2Error(AuthorizeErrorEnum::INVALID_REQUEST, $ex->getMessage());
        }
        if ($ex instanceof AuthorizeInvalidScopeException) {
            return new OAuth2Error(AuthorizeErrorEnum::INVALID_SCOPE, $ex->getMessage());
        }
        if ($ex instanceof AuthorizeTemporarilyUnavailableException) {
            return new OAuth2Error(AuthorizeErrorEnum::TEMPORARILY_UNAVAILABLE, $ex->getMessage());
        }
        if ($ex instanceof AuthorizeUnauthorizedClientException) {
            return new OAuth2Error(AuthorizeErrorEnum::UNAUTHORIZED_CLIENT, $ex->getMessage());
        }
        if ($ex instanceof AuthorizeUnsupportedResponseTypeException) {
            return new OAuth2Error(AuthorizeErrorEnum::UNSUPPORTED_RESPONSE_TYPE, $ex->getMessage());
        }
        return new OAuth2Error(AuthorizeErrorEnum::SERVER_ERROR, $ex->getMessage());
    }
}
