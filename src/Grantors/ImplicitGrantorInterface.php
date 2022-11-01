<?php

namespace Francerz\OAuth2\AuthServer\Grantors;

use Francerz\OAuth2\AuthServer\Finders\ClientFinderInterface;
use Francerz\OAuth2\AuthServer\Issuers\AccessTokenIssuerInterface;

/**
 * This interface MUST be implemented if authorization server supports
 * Implicit Grant flow.
 */
interface ImplicitGrantorInterface extends
    AuthorizeGrantorInterface,
    ClientFinderInterface,
    AccessTokenIssuerInterface
{
}
