<?php

namespace Francerz\OAuth2\AuthServer;

use Psr\Http\Message\UriInterface;

class AuthCode implements AuthCodeInterface
{
    private $clientId;
    private $ownerId;
    private $code;
    private $scope;
    private $lifetime;
    private $createTime;
    private $redeemTime;
    private $redirectUri;

    private $params = array();

    public function __construct(
        string $code,
        string $clientId,
        string $ownerId,
        ?string $scope,
        ?UriInterface $redirectUri = null,
        int $lifetime = 600,
        ?int $createTime = null,
        ?int $redeemTime = null
    ) {
        $this->clientId = $clientId;
        $this->ownerId = $ownerId;
        $this->code = $code;
        $this->scope = isset($scope) ? $scope : '';
        $this->redirectUri = $redirectUri;
        $this->lifetime = $lifetime;
        $this->createTime = isset($createTime) ? $createTime : time();
        $this->redeemTime = $redeemTime;
    }

    public function withClientId(string $client_id): AuthCodeInterface
    {
        $new = clone $this;
        $new->clientId = $client_id;
        return $new;
    }
    
    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function withOwnerId(string $owner_id): AuthCodeInterface
    {
        $new = clone $this;
        $new->ownerId = $owner_id;
        return $new;
    }

    public function getOwnerId(): string
    {
        return $this->ownerId;
    }

    public function withCode(string $code): AuthCodeInterface
    {
        $new = clone $this;
        $new->code = $code;
        return $new;
    }
    
    public function getCode(): string
    {
        return $this->code;
    }

    public function withScope(string $scope): AuthCodeInterface
    {
        $new = clone $this;
        $new->scope = $scope;
        return $new;
    }

    public function getScope() : string
    {
        return $this->scope;
    }

    public function withLifetime(int $lifetime): AuthCodeInterface
    {
        $new = clone $this;
        $new->lifetime = $lifetime;
        return $new;
    }

    public function getLifetime(): int
    {
        return $this->lifetime;
    }

    public function getCreateTime() : int
    {
        return $this->createTime;
    }

    public function withRedeemTime(int $epoch): AuthCodeInterface
    {
        $new = clone $this;
        $new->redeemTime = $epoch;
        return $new;
    }

    public function getRedeemTime(): ?int
    {
        return $this->redeemTime;
    }

    public function withRedirectUri(UriInterface $uri): AuthCodeInterface
    {
        $new = clone $this;
        $new->redirectUri = $uri;
        return $new;
    }

    public function getRedirectUri(): ?UriInterface
    {
        return $this->redirectUri;
    }

    public function getExpireTime(): int
    {
        return $this->createTime + $this->lifetime;
    }

    public function isUsed(): bool
    {
        return !empty($this->redeemTime);
    }

    public function isExpiredAt(int $epoch): bool
    {
        return $this->getExpireTime() < $epoch;
    }

    public function isExpired(int $s = 5): bool
    {
        return $this->isExpiredAt(time() - $s);
    }

    public function withParam(string $name, $value) : AuthCodeInterface
    {
        $new = clone $this;
        $new->params[$name] = $value;
        return $new;
    }
    public function getParam(string $name)
    {
        if (array_key_exists($name, $this->params)) {
            return $this->params[$name];
        }
    }
}