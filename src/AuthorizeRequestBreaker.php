<?php

namespace Francerz\OAuth2\AuthServer;

use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeInvalidRequestException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeUnsupportedResponseTypeException;
use Francerz\OAuth2\AuthServer\Grantors\AuthorizationCodeGrantorInterface;
use Francerz\OAuth2\AuthServer\Grantors\ImplicitGrantorInterface;
use Francerz\OAuth2\ResponseTypesEnum;
use Iterator;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizeRequestBreaker implements Iterator
{
    private $request;
    private $codeGrantor;
    private $implicitGrantor;

    /** @var string[] */
    private $params;
    /** @var string|null */
    private $responseType;
    /** @var string|null */
    private $clientId;
    /** @var string|null */
    private $redirectUri;
    /** @var string|null */
    private $scope;
    /** @var string|null */
    private $state;

    public function __construct(
        ServerRequestInterface $request,
        ?AuthorizationCodeGrantorInterface $codeGrantor = null,
        ?ImplicitGrantorInterface $implicitGrantor = null
    ) {
        $this->request = $request;
        $this->codeGrantor = $codeGrantor;
        $this->implicitGrantor = $implicitGrantor;

        $uriParams = UriHelper::getQueryParams($request->getUri());
        $this->responseType = $uriParams['response_type'] ?? null;
        $this->clientId = $uriParams['client_id'] ?? null;
        $this->redirectUri = $uriParams['redirect_uri'] ?? null;
        $this->scope = $uriParams['scope'] ?? null;
        $this->state = $uriParams['state'] ?? null;
        $this->params = array_intersect_key($uriParams, array_flip([
            'response_type', 'client_id', 'redirect_uri', 'scope', 'state',
            'code_challenge', 'code_challenge_method'
        ]));
    }

    public function getRequest()
    {
        return $this->request;
    }

    public function getResponseType()
    {
        return $this->responseType;
    }

    public function getClientId()
    {
        return $this->clientId;
    }

    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    public function getScope()
    {
        return $this->scope;
    }

    public function getState()
    {
        return $this->state;
    }

    public function fetchRedirectUri()
    {
        $redirectUri = $this->getRedirectUri();
        if (isset($redirectUri)) {
            return $redirectUri;
        }
        $client = $this->fetchClient();
        if (is_null($client)) {
            return null;
        }
        $redirectUri = $client->getRedirectUri();
        if (is_null($redirectUri)) {
            return null;
        }
        return $redirectUri;
    }

    public function fetchClient()
    {
        $clientId = $this->getClientId();
        if (is_null($clientId)) {
            return null;
        }
        return $this->codeGrantor->findClient($clientId);
    }

    public function validate()
    {
        $responseType = $this->getResponseType();
        if (!isset($responseType)) {
            throw new AuthorizeInvalidRequestException("Missing required 'response_type' attribute.");
        }
        $clientId = $this->getClientId();
        if (is_null($clientId)) {
            throw new AuthorizeInvalidRequestException("Missing requried 'client_id' attibute.");
        }
        $client = $this->codeGrantor->findClient($clientId);
        if (is_null($client)) {
            throw new AuthorizeInvalidRequestException("Invalid 'client_id'.");
        }

        switch ($responseType) {
            case ResponseTypesEnum::AUTHORIZATION_CODE:
                if (!$this->codeGrantor instanceof AuthorizationCodeGrantorInterface) {
                    throw new AuthorizeUnsupportedResponseTypeException($responseType);
                }
                return true;
            case ResponseTypesEnum::TOKEN:
                if (!$this->implicitGrantor instanceof ImplicitGrantorInterface) {
                    throw new AuthorizeUnsupportedResponseTypeException($responseType);
                }
                return $this->validateTokenResponseType($client);
            default:
                throw new AuthorizeUnsupportedResponseTypeException($responseType);
        }
    }

    private function validateTokenResponseType(ClientInterface $client)
    {
        $redirectUri = $this->getRedirectUri();
        if (is_null($redirectUri)) {
            throw new AuthorizeInvalidRequestException("Missing required 'redirect_uri' attribute.");
        }
        $clientRedirectUri = $client->getRedirectUri();
        if (isset($clientRedirectUri) && $redirectUri !== $clientRedirectUri) {
            throw new AuthorizeInvalidRequestException("Mismatch 'redirect_uri'.");
        }
        return true;
    }

    public function getParams()
    {
        return $this->params;
    }

    public function current()
    {
        return current($this->params);
    }
    public function key()
    {
        return key($this->params);
    }
    public function next(): void
    {
        next($this->params);
    }
    public function rewind(): void
    {
        reset($this->params);
    }
    public function valid(): bool
    {
        return key($this->params) !== null;
    }
}
