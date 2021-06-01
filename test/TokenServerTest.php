<?php

use Francerz\Http\HttpFactory;
use Francerz\Http\Utils\Constants\MediaTypes;
use Francerz\Http\Utils\Constants\Methods;
use Francerz\Http\Utils\Headers\BasicAuthorizationHeader;
use Francerz\Http\Utils\HttpFactoryManager;
use Francerz\Http\Utils\HttpHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthServer\AuthCode;
use Francerz\OAuth2\AuthServer\AuthCodeInterface;
use Francerz\OAuth2\AuthServer\Client;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\RefreshToken;
use Francerz\OAuth2\AuthServer\RefreshTokenInterface;
use Francerz\OAuth2\AuthServer\ResourceOwner;
use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;
use Francerz\OAuth2\AuthServer\TokenServer;
use Francerz\OAuth2\TokenRequestGrantTypes;
use PHPUnit\Framework\TestCase;

class TokenServerTest extends TestCase
{
    private $httpFactory;

    private $client_id = '0123456789abcdef';
    private $client_secret = '4j8zc7h8kalipt69mqd1id9q';
    private $access_token = 'doh8ny4a9h5r72ng52iizjxj';
    private $refresh_token = 'xcag6ykryl8ocr1hrac6q4k2qlf3zm1a';

    public function __construct()
    {
        parent::__construct();
        $this->httpFactory = new HttpFactoryManager(new HttpFactory());
    }

    public function createTokenServer() : TokenServer
    {
        $testClass = $this;
        $tokenServer = new TokenServer($this->httpFactory);

        $tokenServer->setFindClientHandler(function(string $client_id) : ?ClientInterface {
            return new Client($client_id);
        });
        $tokenServer->setFindResourceOwnerHandler(function(string $owner_id): ResourceOwnerInterface {
            return new ResourceOwner($owner_id);
        });
        $tokenServer->setCreateAccessTokenHandler(function(
            ClientInterface $client,
            ResourceOwnerInterface $owner,
            string $scope
        ) use ($testClass) : AccessToken {
            return new AccessToken(
                $testClass->access_token,
                'Bearer',
                3600,
                $testClass->refresh_token,
                null,
                'scope1 scope2'
            );
        });
        
        // Authorization Code grant type
        $tokenServer->setFindAuthorizationCodeHandler(function(string $code) use ($testClass) : AuthCodeInterface {
            $uriFactory = $testClass->httpFactory->getUriFactory();
            return new AuthCode(
                $code,                  // code
                $testClass->client_id,  // client_id
                'user:123',             // owner_id
                'scope1 scope2',        // scope
                $uriFactory->createUri('https://example.com/oauth2/callback')
            );
        });
        $tokenServer->setUpdateAuthorizationCodeRedeemTimeHandler(function(AuthCodeInterface $authCode) {
            
        });

        // Refresh Token grant type
        $tokenServer->setFindRefreshTokenHandler(function(string $refresh_token) use ($testClass) : RefreshTokenInterface {
            return new RefreshToken(
                $refresh_token,
                $testClass->client_id,
                'user:123',
                'scope1 scope2'
            );
        });

        return $tokenServer;
    }

    public function createTokenRequestWithCode(string $code)
    {
        $uriFactory = $this->httpFactory->getUriFactory();
        $requestFactory = $this->httpFactory->getRequestFactory();
        $http = new HttpHelper($this->httpFactory);

        $uri = $uriFactory->createUri('https://oauth2.server.com/token');

        $request = $requestFactory
            ->createRequest(Methods::POST, $uri)
            ->withHeader('Authorization', new BasicAuthorizationHeader(
                $this->client_id, $this->client_secret
            ));
        $request = $http->withContent(
            $request,
            MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED,
            array(
                'grant_type' => TokenRequestGrantTypes::AUTHORIZATION_CODE,
                'code' => $code
            ));
        
        return $request;
    }

    public function createTokenRequestWithRefreshToken(string $refresh_token)
    {
        $uriFactory = $this->httpFactory->getUriFactory();
        $requestFactory = $this->httpFactory->getRequestFactory();
        $http = new HttpHelper($this->httpFactory);

        $uri = $uriFactory->createUri('https://oauth2.server.com/token');

        $request = $requestFactory
            ->createRequest(Methods::POST, $uri)
            ->withHeader('Authorization', new BasicAuthorizationHeader(
                $this->client_id, $this->client_secret
            ));
        $request = $http->withContent(
            $request,
            MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED,
            array(
                'grant_type' => TokenRequestGrantTypes::REFRESH_TOKEN,
                'refresh_token' => $refresh_token
            ));

        return $request;
    }

    public function testFetchAccessTokenWithCode()
    {
        $tokenServer = $this->createTokenServer();
        $request = $this->createTokenRequestWithCode('A1lfLISBC4BK');

        $response = $tokenServer->handle($request);

        $this->assertTrue(HttpHelper::isSuccess($response));
        $this->assertEquals(MediaTypes::APPLICATION_JSON, $response->getHeaderLine('Content-Type'));
        $this->assertEquals('no-store', $response->getHeaderLine('Cache-Control'));
        $this->assertEquals('no-cache', $response->getHeaderLine('Pragma'));
        
        $accessToken = AccessToken::fromHttpMessage($response);

        $this->assertEquals($this->access_token, $accessToken->getAccessToken());
        $this->assertEquals('Bearer', $accessToken->getTokenType());
        $this->assertEquals(3600, $accessToken->getExpiresIn());
        $this->assertEquals($this->refresh_token, $accessToken->getRefreshToken());
    }

    public function testFetchAccessTokenWithRefreshToken()
    {
        $tokenServer = $this->createTokenServer();
        $request = $this->createTokenRequestWithRefreshToken($this->refresh_token);

        $response = $tokenServer->handle($request);

        $this->assertTrue(HttpHelper::isSuccess($response));
        $this->assertEquals(MediaTypes::APPLICATION_JSON, $response->getHeaderLine('Content-Type'));
        $this->assertEquals('no-store', $response->getHeaderLine('Cache-Control'));
        $this->assertEquals('no-cache', $response->getHeaderLine('Pragma'));
        
        $accessToken = AccessToken::fromHttpMessage($response);

        $this->assertEquals($this->access_token, $accessToken->getAccessToken());
        $this->assertEquals('Bearer', $accessToken->getTokenType());
        $this->assertEquals(3600, $accessToken->getExpiresIn());
        $this->assertEquals($this->refresh_token, $accessToken->getRefreshToken());
    }
}