<?php

namespace Francerz\OAuth2\AuthServer\Grantors;

use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;

/**
 * @internal
 */
interface AuthorizeGrantorInterface
{
    /**
     * @return ResourceOwnerInterface|null
     */
    public function getCurrentResourceOwner(): ?ResourceOwnerInterface;
}
