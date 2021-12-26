<?php

namespace Francerz\OAuth2\AuthServer\Tests;

use Exception;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Francerz\Http\HttpFactory;
use Francerz\Http\ServerRequest;
use Francerz\Http\Uri;
use Francerz\Http\Utils\Constants\MediaTypes;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthServer\Dev\TestGrantor;
use Francerz\OAuth2\AuthServer\Exceptions\OAuth2FlowException;
use Francerz\OAuth2\AuthServer\Exceptions\TokenInvalidClientException;
use Francerz\OAuth2\AuthServer\Exceptions\TokenInvalidGrantException;
use Francerz\OAuth2\AuthServer\Exceptions\TokenInvalidRequestException;
use Francerz\OAuth2\AuthServer\Exceptions\TokenInvalidScopeException;
use Francerz\OAuth2\AuthServer\Exceptions\TokenUnauthorizedClientException;
use Francerz\OAuth2\AuthServer\Exceptions\TokenUnsupportedGrantTypeException;
use Francerz\OAuth2\AuthServer\TokenEndpointHandler;
use Francerz\OAuth2\GrantTypesEnum;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class TokenEndpointTest extends TestCase
{
    private $clientAuthorization = 'Basic YWJjZGVmZ2hpajphMUIyYzNENGU1';

    private function createAuthorizationCodeRequest()
    {
        $request = new ServerRequest(
            new Uri("https://oauth2.server.com/token"),
            RequestMethodInterface::METHOD_POST
        );
        $request = $request
            ->withHeader('Content-Type', MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED)
            ->withHeader('Authorization', $this->clientAuthorization)
            ->withParsedBody([
                'grant_type' => GrantTypesEnum::AUTHORIZATION_CODE,
                'code' => 'zyxwvutsrqp',
                'redirect_uri' => 'https://example.com/oauth2/callback'
            ]);
        return $request;
    }
    public function testGrantTypeAuthorizationCode()
    {
        $request = $this->createAuthorizationCodeRequest();
        $httpFactory = new HttpFactory();
        $handler = new TokenEndpointHandler($request, $httpFactory);
        $handler->setCodeGrantor(new TestGrantor());
        $response = $handler->handle();
        $this->assertStringContainsString('access_token', (string)$response->getBody());
        AccessToken::fromMessage($response);
    }

    private function createOwnerPasswordRequest()
    {
        $request = new ServerRequest(
            new Uri('https://oauth2.server.com/token'),
            RequestMethodInterface::METHOD_POST
        );
        $request = $request
            ->withHeader('Content-Type', MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED)
            ->withHeader('Authorization', $this->clientAuthorization)
            ->withParsedBody([
                'grant_type' => GrantTypesEnum::PASSWORD,
                'username' => 'user',
                'password' => 'password'
            ]);
        return $request;
    }

    public function testGrantTypePassword()
    {
        $request = $this->createOwnerPasswordRequest();
        $httpFactory = new HttpFactory();
        $handler = new TokenEndpointHandler($request, $httpFactory);
        $handler->setOwnerGrantor(new TestGrantor());
        $response = $handler->handle();
        $this->assertStringContainsString('access_token', (string)$response->getBody());
        AccessToken::fromMessage($response);
    }

    private function createClientCredentialsRequest()
    {
        $request = new ServerRequest(
            new Uri('https://oauth2.server.com/token'),
            RequestMethodInterface::METHOD_POST
        );
        $request = $request
            ->withHeader('Content-Type', MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED)
            ->withHeader('Authorization', $this->clientAuthorization)
            ->withParsedBody([
                'grant_type' => GrantTypesEnum::CLIENT_CREDENTIALS
            ]);
        return $request;
    }

    public function testGrantTypeClientCredentials()
    {
        $request = $this->createClientCredentialsRequest();
        $httpFactory = new HttpFactory();
        $handler = new TokenEndpointHandler($request, $httpFactory);
        $handler->setClientGrantor(new TestGrantor());
        $response = $handler->handle();
        $this->assertStringContainsString('access_token', (string)$response->getBody());
        AccessToken::fromMessage($response);
    }

    private function createRefreshTokenRequest()
    {
        $request = new ServerRequest(
            new Uri('https://oauth2.server.com/token'),
            RequestMethodInterface::METHOD_POST
        );
        $request = $request
            ->withHeader('Content-Type', MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED)
            ->withHeader('Authorization', $this->clientAuthorization)
            ->withParsedBody([
                'grant_type' => GrantTypesEnum::REFRESH_TOKEN,
                'refresh_token' => 'abcdefghij',
                'scope' => 'scope1 scope3'
            ]);
        return $request;
    }

    public function testGrantTypeRefreshToken()
    {
        $request = $this->createRefreshTokenRequest();
        $httpFactory = new HttpFactory();
        $handler = new TokenEndpointHandler($request, $httpFactory);
        $handler->setRefreshTokenGrantor(new TestGrantor());
        $response = $handler->handle();
        $this->assertStringContainsString('access_token', (string)$response->getBody());
        AccessToken::fromMessage($response);
    }

    public function testInvalidGrants()
    {
        $uri = new Uri('https://oauth2.server.com/token');
        $request = new ServerRequest($uri, RequestMethodInterface::METHOD_POST);
        $httpFactory = new HttpFactory();
        $handler = new TokenEndpointHandler($request, $httpFactory);

        $this->expectException(OAuth2FlowException::class);
        $handler->handle();
    }

    public function testCatch()
    {
        $uri = new Uri('https://oauth2.server.com/token');
        $request = new ServerRequest($uri);
        $httpFactory = new HttpFactory();
        $handler = new TokenEndpointHandler($request, $httpFactory);

        $ex = new TokenUnsupportedGrantTypeException();
        $response = $handler->catch($ex);
        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertStringContainsString('"error":"unsupported_grant_type"', (string)$response->getBody());

        $response = $handler->catch(new TokenInvalidClientException());
        $this->assertStringContainsString('"error":"invalid_client"', (string)$response->getBody());
        $this->assertEquals(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        $this->assertTrue($response->hasHeader('WWW-Authenticate'));

        $response = $handler->catch(new TokenInvalidGrantException());
        $this->assertStringContainsString('"error":"invalid_grant"', (string)$response->getBody());

        $response = $handler->catch(new TokenInvalidRequestException());
        $this->assertStringContainsString('"error":"invalid_request"', (string)$response->getBody());

        $response = $handler->catch(new TokenInvalidScopeException());
        $this->assertStringContainsString('"error":"invalid_scope"', (string)$response->getBody());

        $response = $handler->catch(new TokenUnauthorizedClientException());
        $this->assertStringContainsString('"error":"unauthorized_client"', (string)$response->getBody());

        $response = $handler->catch(new Exception());
        $this->assertStringContainsString('"error":"server_error', (string)$response->getBody());
        $this->assertEquals(StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR, $response->getStatusCode());
    }
}
