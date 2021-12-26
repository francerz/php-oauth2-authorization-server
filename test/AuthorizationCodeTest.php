<?php

namespace Francerz\OAuth2\AuthServer\Tests;

use DateInterval;
use DateTimeImmutable;
use Francerz\Http\HttpFactory;
use Francerz\Http\Utils\HttpFactoryManager;
use Francerz\OAuth2\AuthServer\AuthCode;
use Francerz\OAuth2\AuthServer\AuthorizationCode;
use PHPUnit\Framework\TestCase;

class AuthorizationCodeTest extends TestCase
{
    private $httpFactory;

    public function __construct()
    {
        parent::__construct();
        $this->httpFactory = new HttpFactoryManager(new HttpFactory());
    }
    public function testInstantation()
    {
        $uriFactory = $this->httpFactory->getUriFactory();
        $authCode = new AuthorizationCode(
            'A1lfLISBC4BK',  // code
            'abcdef',        // client_id
            'user:123',      // owner_id
            'scope1 scope2', // scope
            $uriFactory->createUri('https://client.com/oauth2/callback'),
            100,             // lifetime
            0,               // create time
            null             // redeem time
        );

        $this->assertInstanceOf(AuthorizationCode::class, $authCode);
        $this->assertEquals('A1lfLISBC4BK', $authCode->getCode());
        $this->assertEquals('abcdef', $authCode->getClientId());
        $this->assertEquals('user:123', $authCode->getOwnerId());
        $this->assertEquals('scope1 scope2', $authCode->getScope());
        $this->assertEquals('https://client.com/oauth2/callback', (string) $authCode->getRedirectUri());
        $this->assertEquals(100, $authCode->getLifetime());
        $this->assertEquals(new DateTimeImmutable('@0'), $authCode->getCreateTime());
        $this->assertEquals(null, $authCode->getRedeemTime());

        return $authCode;
    }

    /**
     * @depends testInstantation
     *
     * @return void
     */
    public function testExpirationChecks(AuthorizationCode $authCode)
    {
        $createTime = $authCode->getCreateTime();
        $lifetime = $authCode->getLifetime();

        $expireTime = $createTime->add(DateInterval::createFromDateString("{$lifetime} seconds"));

        $this->assertEquals($expireTime, $authCode->getExpireTime());

        $this->assertFalse($authCode->isExpiredAt($expireTime->sub(DateInterval::createFromDateString('1 seconds'))));
        $this->assertFalse($authCode->isExpiredAt($expireTime));
        $this->assertTrue($authCode->isExpiredAt($expireTime->add(DateInterval::createFromDateString("1 seconds"))));
    }

    /**
     * @depends testInstantation
     *
     * @param AuthCode $authCode
     * @return void
     */
    public function testRedeeming(AuthorizationCode $authCode)
    {
        $this->assertNull($authCode->getRedeemTime());
        $this->assertFalse($authCode->isUsed());

        $authCode->setRedeemTime(time());
        $this->assertNotNull($authCode->getRedeemTime());
        $this->assertTrue($authCode->isUsed());
    }
}
