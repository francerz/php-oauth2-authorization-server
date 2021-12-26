<?php

namespace Francerz\OAuth2\AuthServer;

class RefreshToken
{
    private $refreshToken;
    private $clientId;
    private $ownerId;
    private $scope;

    public function __construct(string $refreshToken, string $clientId, string $ownerId, string $scope = '')
    {
        $this->refreshToken = $refreshToken;
        $this->clientId = $clientId;
        $this->ownerId = $ownerId;
        $this->scope = $scope;
    }

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(string $refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function setClientId(string $clientId)
    {
        $this->clientId = $clientId;
    }

    public function getOwnerId(): string
    {
        return $this->ownerId;
    }

    public function setOwnerId(string $ownerId)
    {
        $this->ownerId = $ownerId;
    }

    public function getScope(): string
    {
        return $this->scope;
    }

    public function setScope(string $scope)
    {
        $this->scope = $scope;
    }

    public function __toString()
    {
        return $this->refreshToken;
    }
}
