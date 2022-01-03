<?php

namespace Francerz\OAuth2\AuthServer\Grantors;

use Francerz\OAuth2\AuthServer\Finders\ClientFinderInterface;
use Francerz\OAuth2\AuthServer\Issuers\AccessTokenIssuerInterface;
use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;

interface OwnerCredentialsGrantorInterface extends
    TokenGrantorInterface,
    ClientFinderInterface,
    AccessTokenIssuerInterface
{
    public function acquireResourceOwner(string $username): ?ResourceOwnerInterface;
    public function verifyResourceOwnerPassword(ResourceOwnerInterface $owner, string $password): bool;
}
