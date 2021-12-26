<?php

namespace Francerz\OAuth2\AuthServer;

class Client implements ClientInterface
{
    /** @var string */
    private $client_id;

    /** @var string */
    private $client_secret;

    /** @var string */
    private $confidential;

    /** @var string */
    private $redirect_uri;

    private $params = array();

    public function __construct(
        string $client_id,
        ?string $client_secret = null,
        bool $confidential = false
    ) {
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->confidential = $confidential;
    }

    public function getClientId(): string
    {
        return $this->client_id;
    }

    public function getClientSecret(): ?string
    {
        return $this->client_secret;
    }

    public function setRedirectUri(?string $redirect_uri)
    {
        $this->redirect_uri = $redirect_uri;
    }

    public function getRedirectUri(): ?string
    {
        return $this->redirect_uri;
    }

    public function isConfidential(): bool
    {
        return $this->confidential;
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
