<?php

namespace Francerz\OAuth2\AuthServer\Finders;

use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;

interface ResourceOwnerFinderInterface
{
    public function findResourceOwner(string $ownerId): ?ResourceOwnerInterface;
}
