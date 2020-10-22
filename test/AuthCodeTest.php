<?php

use Francerz\Http\HttpFactory;
use Francerz\Http\Tools\HttpFactoryManager;
use Francerz\OAuth2\AuthServer\AuthCode;
use PHPUnit\Framework\TestCase;

class AuthCodeTest extends TestCase
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
        $authCode = new AuthCode(
            'A1lfLISBC4BK', // code
            'abcdef',       // client_id
            'user:123',     // owner_id
            'scope1 scope2',// scope
            $uriFactory->createUri('https://client.com/oauth2/callback'),
            100,            // lifetime
            0,              // create time
            null            // redeem time
        );

        $this->assertInstanceOf(AuthCode::class, $authCode);
        $this->assertEquals('A1lfLISBC4BK', $authCode->getCode());
        $this->assertEquals('abcdef', $authCode->getClientId());
        $this->assertEquals('user:123', $authCode->getOwnerId());
        $this->assertEquals('scope1 scope2', $authCode->getScope());
        $this->assertEquals('https://client.com/oauth2/callback', (string) $authCode->getRedirectUri());
        $this->assertEquals(100, $authCode->getLifetime());
        $this->assertEquals(0, $authCode->getCreateTime());
        $this->assertEquals(null, $authCode->getRedeemTime());

        return $authCode;
    }

    /**
     * @depends testInstantation
     *
     * @return void
     */
    public function testExpirationChecks(AuthCode $authCode)
    {
        $createTime = $authCode->getCreateTime();
        $lifetime = $authCode->getLifetime();

        $expireTime = $createTime + $lifetime;

        $this->assertEquals($expireTime, $authCode->getExpireTime());

        $this->assertFalse($authCode->isExpiredAt($expireTime - 1));
        $this->assertFalse($authCode->isExpiredAt($expireTime));
        $this->assertTrue($authCode->isExpiredAt($expireTime + 1));
    }

    /**
     * @depends testInstantation
     *
     * @param AuthCode $authCode
     * @return void
     */
    public function testRedeeming(AuthCode $authCode)
    {
        $this->assertNull($authCode->getRedeemTime());

        $authCode2 = $authCode->withRedeemTime(time());

        $this->assertNull($authCode->getRedeemTime());
        $this->assertNotNull($authCode2->getRedeemTime());

        $this->assertFalse($authCode->isUsed());
        $this->assertTrue($authCode2->isUsed());
    }
}