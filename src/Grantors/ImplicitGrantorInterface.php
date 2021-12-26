<?php

namespace Francerz\OAuth2\AuthServer\Grantors;

use Francerz\OAuth2\AuthServer\Finders\ClientFinderInterface;
use Francerz\OAuth2\AuthServer\Issuers\AccessTokenIssuerInterface;

interface ImplicitGrantorInterface extends
    AuthorizeGrantorInterface,
    ClientFinderInterface,
    AccessTokenIssuerInterface
{
}
