<?php

namespace Francerz\OAuth2\AuthServer\Tests;

use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Francerz\Http\HttpFactory;
use Francerz\Http\ServerRequest;
use Francerz\Http\Uri;
use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\AuthServer\AuthorizeGrantHandler;
use Francerz\OAuth2\AuthServer\AuthorizeRequestBreaker;
use Francerz\OAuth2\AuthServer\Dev\TestGrantor;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeAccessDeniedException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeInvalidRequestException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeInvalidScopeException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeServerErrorException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeTemporarilyUnavailableException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeUnauthorizedClientException;
use Francerz\OAuth2\AuthServer\Exceptions\AuthorizeUnsupportedResponseTypeException;
use Francerz\OAuth2\ResponseTypesEnum;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class AuthorizeEndpointTest extends TestCase
{
    private function createAuthorizationCodeRequest()
    {
        $uri = new Uri("https://oauth2.server.com/authorize");
        $uri = UriHelper::withQueryParams($uri, [
            'response_type' => ResponseTypesEnum::AUTHORIZATION_CODE,
            'client_id' => '0123456789abcdef',
            'scope' => 'scope1 scope2',
            'state' => '9kl3fjhk',
            'redirect_uri' => 'https://example.com/oauth2/callback'
        ]);
        $request = new ServerRequest($uri);
        return $request;
    }

    public function testAuthorizationCodeRequestBreaker()
    {
        $request = $this->createAuthorizationCodeRequest();
        $grantor = new TestGrantor();
        $breaker = new AuthorizeRequestBreaker($request, $grantor);

        $this->assertEquals(ResponseTypesEnum::AUTHORIZATION_CODE, $breaker->getResponseType());
        $this->assertEquals('0123456789abcdef', $breaker->getClientId());
        $this->assertEquals('https://example.com/oauth2/callback', $breaker->getRedirectUri());
        $this->assertEquals('scope1 scope2', $breaker->getScope());
        $this->assertEquals('9kl3fjhk', $breaker->getState());
        $this->assertTrue($breaker->validate());

        $this->assertTrue($breaker->valid());
        $this->assertEquals('response_type', $breaker->key());
        $this->assertEquals(ResponseTypesEnum::AUTHORIZATION_CODE, $breaker->current());
        $breaker->next();
        $this->assertEquals('client_id', $breaker->key());
        $this->assertEquals('0123456789abcdef', $breaker->current());
        $breaker->next();
        $this->assertEquals('scope', $breaker->key());
        $this->assertEquals('scope1 scope2', $breaker->current());
        $breaker->next();
        $this->assertEquals('state', $breaker->key());
        $this->assertEquals('9kl3fjhk', $breaker->current());
        $breaker->next();
        $this->assertEquals('redirect_uri', $breaker->key());
        $this->assertEquals('https://example.com/oauth2/callback', $breaker->current());
        $breaker->next();
        $this->assertFalse($breaker->valid());
        $breaker->rewind();

        return $breaker;
    }

    private function createRequestFromBreaker(AuthorizeRequestBreaker $breaker)
    {
        $uri = new Uri('https://oauth2.server.com/authorize_handler');
        $request = new ServerRequest($uri, RequestMethodInterface::METHOD_POST);
        return $request->withParsedBody($breaker->getParams());
    }

    /**
     * @depends testAuthorizationCodeRequestBreaker
     */
    public function testAuthorizationCodeRequestGrant(AuthorizeRequestBreaker $breaker)
    {
        $httpFactory = new HttpFactory();
        $request = $this->createRequestFromBreaker($breaker);
        $handler = new AuthorizeGrantHandler($httpFactory, $httpFactory);
        $handler->initFromRequest($request);

        $grantor = new TestGrantor();
        $grantor->setAuthorizationCode('A1b2C3d4E5f6');
        $handler->setCodeGrantor($grantor);

        $response = $handler->handle(true);
        $this->assertNotEmpty($response->getHeaderLine('Location'));

        $uri = new Uri($response->getHeaderLine('Location'));
        $uriParams = UriHelper::getQueryParams($uri);
        $this->assertArrayHasKey('code', $uriParams);
        $this->assertEquals('A1b2C3d4E5f6', $uriParams['code']);
        $this->assertArrayHasKey('state', $uriParams);
        $this->assertEquals('9kl3fjhk', $uriParams['state']);
    }

    public function createTokenRequest()
    {
        $uri = new Uri("https://oauth2.server.com/authorize");
        $uri = UriHelper::withQueryParams($uri, [
            'response_type' => ResponseTypesEnum::TOKEN,
            'client_id' => '0123456789abcdef',
            'scope' => 'scope1 scope2',
            'state' => '9kl3fjhk',
            'redirect_uri' => 'https://example.com/oauth2/callback'
        ]);
        $request = new ServerRequest($uri);
        return $request;
    }

    public function testTokenRequestBreaker()
    {
        $request = $this->createTokenRequest();
        $grantor = new TestGrantor();
        $grantor->setClientRedirectUri('https://example.com/oauth2/callback');
        $breaker = new AuthorizeRequestBreaker($request, $grantor, $grantor);

        $this->assertEquals(ResponseTypesEnum::TOKEN, $breaker->getResponseType());
        $this->assertEquals('0123456789abcdef', $breaker->getClientId());
        $this->assertEquals('https://example.com/oauth2/callback', $breaker->getRedirectUri());
        $this->assertEquals('scope1 scope2', $breaker->getScope());
        $this->assertEquals('9kl3fjhk', $breaker->getState());
        $this->assertTrue($breaker->validate());

        $this->assertTrue($breaker->valid());
        $this->assertEquals('response_type', $breaker->key());
        $this->assertEquals(ResponseTypesEnum::TOKEN, $breaker->current());
        $breaker->next();
        $this->assertEquals('client_id', $breaker->key());
        $this->assertEquals('0123456789abcdef', $breaker->current());
        $breaker->next();
        $this->assertEquals('scope', $breaker->key());
        $this->assertEquals('scope1 scope2', $breaker->current());
        $breaker->next();
        $this->assertEquals('state', $breaker->key());
        $this->assertEquals('9kl3fjhk', $breaker->current());
        $breaker->next();
        $this->assertEquals('redirect_uri', $breaker->key());
        $this->assertEquals('https://example.com/oauth2/callback', $breaker->current());
        $breaker->next();
        $this->assertFalse($breaker->valid());
        $breaker->rewind();

        return $breaker;
    }

    /**
     * @depends testTokenRequestBreaker
     */
    public function testTokenRequestGrant(AuthorizeRequestBreaker $breaker)
    {
        $httpFactory = new HttpFactory();
        $request = $this->createRequestFromBreaker($breaker);
        $handler = new AuthorizeGrantHandler($httpFactory, $httpFactory);
        $handler->initFromRequest($request);

        $grantor = new TestGrantor();
        $handler->setImplicitGrantor($grantor);

        $response = $handler->handle(true);
        $this->assertNotEmpty($response->getHeaderLine('Location'));

        $uri = new Uri($response->getHeaderLine('Location'));
        $uriParams = UriHelper::getFragmentParams($uri);
        $this->assertArrayHasKey('access_token', $uriParams);
        $this->assertArrayHasKey('token_type', $uriParams);
        $this->assertArrayHasKey('expires_in', $uriParams);
        $this->assertArrayHasKey('scope', $uriParams);
        $this->assertArrayHasKey('state', $uriParams);
        $this->assertEquals('9kl3fjhk', $uriParams['state']);
    }

    public function testInvalidRequest()
    {
        $uri = new Uri('https://oauth2.server.com/authorize');
        $request = new ServerRequest($uri);
        $httpFactory = new HttpFactory();
        $handler = new AuthorizeGrantHandler($httpFactory, $httpFactory);
        $handler->initFromRequest($request);

        $ex = new AuthorizeAccessDeniedException();
        $response = $handler->catch($ex);
        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        $this->assertStringContainsString('redirect_uri', (string)$response->getBody());

        $handler->setRedirectUri('https://example.com/oauth2/callback');
        $response = $handler->catch($ex);
        $this->assertEquals(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        $this->assertStringContainsString('response_type', (string)$response->getBody());

        $handler->setResponseType('any');
        $response = $handler->catch($ex);
        $this->assertEquals(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        $this->assertStringContainsString('response_type', (string)$response->getBody());

        $handler->setResponseType(ResponseTypesEnum::AUTHORIZATION_CODE);
        $response = $handler->catch($ex);
        $this->assertEquals(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        $this->assertStringContainsString('error=access_denied', $response->getHeaderLine('Location'));

        $response = $handler->catch(new AuthorizeInvalidRequestException());
        $this->assertEquals(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        $this->assertStringContainsString('error=invalid_request', $response->getHeaderLine('Location'));

        $response = $handler->catch(new AuthorizeServerErrorException());
        $this->assertEquals(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        $this->assertStringContainsString('error=server_error', $response->getHeaderLine('Location'));

        $response = $handler->catch(new AuthorizeTemporarilyUnavailableException());
        $this->assertEquals(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        $this->assertStringContainsString('error=temporarily_unavailable', $response->getHeaderLine('Location'));

        $response = $handler->catch(new AuthorizeInvalidScopeException());
        $this->assertEquals(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        $this->assertStringContainsString('error=invalid_scope', $response->getHeaderLine('Location'));

        $response = $handler->catch(new AuthorizeUnauthorizedClientException());
        $this->assertEquals(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        $this->assertStringContainsString('error=unauthorized_client', $response->getHeaderLine('Location'));

        $response = $handler->catch(new AuthorizeUnsupportedResponseTypeException());
        $this->assertEquals(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        $this->assertStringContainsString('error=unsupported_response_type', $response->getHeaderLine('Location'));
    }
}
