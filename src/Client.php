<?php

namespace Francerz\OAuth2\AuthServer;

use Francerz\OAuth2\ClientTypesEnum;

class Client implements ClientInterface
{
    /** @var string */
    private $clientId;

    /** @var string */
    private $clientSecret;

    /** @var string */
    private $clientType;

    /** @var string */
    private $redirectUri;

    private $params = array();

    public function __construct(
        string $clientId,
        ?string $clientSecret = null,
        $clientType = ClientTypesEnum::TYPE_PUBLIC
    ) {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->clientType = $clientType;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getClientSecret(): ?string
    {
        return $this->clientSecret;
    }

    public function getClientType(): string
    {
        return $this->clientType;
    }

    public function setRedirectUri(?string $redirect_uri)
    {
        $this->redirectUri = $redirect_uri;
    }

    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    /**
     * @deprecated v0.3.0 Use getClientType() method instead.
     * @return boolean
     */
    public function isConfidential(): bool
    {
        return $this->clientType === ClientTypesEnum::TYPE_CONFIDENTIAL;
    }

    public function setParam(string $name, $value)
    {
        $this->params[$name] = $value;
    }

    public function getParam(string $name)
    {
        if (array_key_exists($name, $this->params)) {
            return $this->params[$name];
        }
    }
}
