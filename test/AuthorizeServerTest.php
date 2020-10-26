<?php

use Francerz\Http\HttpFactory;
use Francerz\Http\Utils\Constants\Methods;
use Francerz\Http\Utils\Constants\StatusCodes;
use Francerz\Http\Utils\HttpFactoryManager;
use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\AuthorizeRequestTypes;
use Francerz\OAuth2\AuthServer\AuthorizeServer;
use Francerz\OAuth2\AuthServer\Client;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\ResourceOwner;
use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

class AuthorizeServerTest extends TestCase
{
    private $httpFactory;
    
    public function __construct()
    {
        parent::__construct();
        $this->httpFactory = new HttpFactoryManager(new HttpFactory());
    }

    public function createAuthorizeServer()
    {
        $authorizeServer = new AuthorizeServer($this->httpFactory);

        $authorizeServer->setFindClientHandler(function(string $client_id) : ?ClientInterface {
            return new Client($client_id);
        });
        $authorizeServer->setGetResourceOwnerHandler(function() : ?ResourceOwnerInterface {
            return new ResourceOwner('user:123');
        });
        $authorizeServer->setCreateAuthorizationCodeHandler(function(
            ClientInterface $client,
            ResourceOwnerInterface $owner,
            string $scope,
            UriInterface $redirect_uri
        ) : string {
            return 'A1lfLISBC4BK';
        });

        return $authorizeServer;
    }

    public function createAuthCodeRequest()
    {
        $requestFactory = $this->httpFactory->getRequestFactory();
        $uriFactory = $this->httpFactory->getUriFactory();

        $uri = $uriFactory->createUri('https://auth.server.com/authorize');
        $uri = UriHelper::withQueryParams($uri, array(
            'response_type' => AuthorizeRequestTypes::AUTHORIZATION_CODE,
            'client_id' => '0123456789abcdef',
            'scope' => 'scope1 scope2',
            'state' => '9kl3fjhk',
            'redirect_uri' => 'https://example.com/oauth2/callback'
        ));

        $request = $requestFactory->createRequest(Methods::GET, $uri);

        return $request;
    }

    public function testHandleAuthCodeRequest()
    {
        $server = $this->createAuthorizeServer();
        $request = $this->createAuthCodeRequest();

        $response = $server->handle($request);

        $this->assertEquals(StatusCodes::REDIRECT_FOUND, $response->getStatusCode());
        
        $uriFactory = $this->httpFactory->getUriFactory();
        $locUri = $uriFactory->createUri($response->getHeaderLine('Location'));

        $this->assertEquals('https', $locUri->getScheme());
        $this->assertEquals('example.com', $locUri->getHost());
        $this->assertEquals('/oauth2/callback', $locUri->getPath());
        
        $uriQueryParams = UriHelper::getQueryParams($locUri);

        $this->assertEquals('9kl3fjhk', $uriQueryParams['state']);
        $this->assertEquals('A1lfLISBC4BK', $uriQueryParams['code']);
    }
}