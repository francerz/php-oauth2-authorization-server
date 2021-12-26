<?php

namespace Francerz\OAuth2\AuthServer\Grantors;

use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;

/**
 * @internal
 */
interface AuthorizeGrantorInterface
{
    public function getCurrentResourceOwner(): ?ResourceOwnerInterface;
}
