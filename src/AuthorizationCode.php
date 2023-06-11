<?php

namespace Francerz\OAuth2\AuthServer;

use DateTime;
use DateTimeImmutable;
use DateTimeInterface;
use Francerz\OAuth2\CodeChallengeMethodsEnum;

class AuthorizationCode
{
    private $clientId;
    private $ownerId;
    private $code;
    private $scope;
    private $lifetime;
    private $createTime;
    private $expireTime;
    private $redeemTime;
    private $redirectUri;
    private $codeChallenge;
    private $codeChallengeMethod;

    private $params = array();

    /**
     * @param string $code
     * @param string $clientId
     * @param string $ownerId
     * @param string|null $scope
     * @param string|null $redirectUri
     * @param string|null $codeChallenge
     * @param string $codeChallengeMethod
     * @param integer $lifetime
     * @param DateTimeInterface|int|null $createTime
     * @param DateTimeInterface|int|null $redeemTime
     */
    public function __construct(
        string $code,
        string $clientId,
        string $ownerId,
        ?string $scope = null,
        ?string $redirectUri = null,
        ?string $codeChallenge = null,
        $codeChallengeMethod = null,
        int $lifetime = 600,
        $createTime = null,
        $redeemTime = null
    ) {
        $this->clientId = $clientId;
        $this->ownerId = $ownerId;
        $this->code = $code;
        $this->scope = isset($scope) ? $scope : '';
        $this->redirectUri = $redirectUri;
        $this->lifetime = $lifetime;

        $this->createTime = static::parseDateTimeImmutable($createTime, true);
        $this->expireTime = $this->createTime->modify("+{$lifetime} seconds");
        $this->redeemTime = static::parseDateTimeImmutable($redeemTime);

        $this->codeChallenge = $codeChallenge;
        $this->setCodeChallengeMethod($codeChallengeMethod);
    }

    private static function parseDateTimeImmutable($dateTime, $parseNull = false)
    {
        if ($dateTime instanceof DateTimeImmutable) {
            return $dateTime;
        }
        if (is_null($dateTime)) {
            return $parseNull ? new DateTimeImmutable() : null;
        }
        if (is_string($dateTime)) {
            return new DateTimeImmutable($dateTime);
        }
        if (is_numeric($dateTime)) {
            return new DateTimeImmutable("@{$dateTime}");
        }
        if ($dateTime instanceof DateTime) {
            return DateTimeImmutable::createFromMutable($dateTime);
        }
        return null;
    }

    public function setClientId(string $client_id)
    {
        $this->clientId = $client_id;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function setOwnerId(string $owner_id)
    {
        $this->ownerId = $owner_id;
    }

    public function getOwnerId(): string
    {
        return $this->ownerId;
    }

    public function setCode(string $code)
    {
        $this->code = $code;
    }

    public function getCode(): string
    {
        return $this->code;
    }

    public function setScope(string $scope)
    {
        $this->scope = $scope;
    }

    public function getScope(): string
    {
        return $this->scope;
    }

    public function setLifetime(int $lifetime)
    {
        $this->lifetime = $lifetime;
        $this->expireTime = $this->createTime->modify("+{$this->lifetime} seconds");
    }

    public function getLifetime(): int
    {
        return $this->lifetime;
    }

    public function setCreateTime($time)
    {
        $this->createTime = static::parseDateTimeImmutable($time);
        $this->expireTime = $this->createTime->modify("+{$this->lifetime} seconds");
    }

    public function getCreateTime(): DateTimeImmutable
    {
        return $this->createTime;
    }

    /**
     * Sets the Redeem time of this Authorization Code.
     *
     * @param DateTimeInterface|string|int $time
     * @return void
     */
    public function setRedeemTime($time)
    {
        $this->redeemTime = static::parseDateTimeImmutable($time);
    }

    public function getRedeemTime(): ?DateTimeImmutable
    {
        return $this->redeemTime;
    }

    public function setRedirectUri(?string $uri)
    {
        $this->redirectUri = $uri;
    }

    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    public function getExpireTime(): DateTimeImmutable
    {
        return $this->expireTime;
    }

    public function isUsed(): bool
    {
        return !empty($this->redeemTime);
    }

    public function isExpiredAt($time): bool
    {
        $time = static::parseDateTimeImmutable($time);
        return $this->getExpireTime() < $time;
    }

    /**
     * Checks if current authorization code is expired due to long inactivity
     * within the given seconds.
     *
     * @param integer $s The seconds ahead to be compared. By default is 5 seconds.
     * @return boolean
     */
    public function isExpired(int $s = 5): bool
    {
        $time = new DateTime();
        $time = $time->modify("+{$s} seconds");
        return $this->isExpiredAt($time);
    }

    public function setCodeChallenge(?string $codeChallenge)
    {
        $this->codeChallenge = $codeChallenge;
    }
    public function getCodeChallenge()
    {
        return $this->codeChallenge;
    }

    public function setCodeChallengeMethod($codeChallengeMethod)
    {
        if (is_null($codeChallengeMethod)) {
            $codeChallengeMethod = CodeChallengeMethodsEnum::PLAIN;
        }
        $this->codeChallengeMethod = CodeChallengeMethodsEnum::coerce($codeChallengeMethod);
    }

    public function getCodeChallengeMethod()
    {
        return $this->codeChallengeMethod;
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
        return null;
    }

    public function __toString()
    {
        return $this->code;
    }
}
