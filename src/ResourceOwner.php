<?php

namespace Francerz\OAuth2\AuthServer;

class ResourceOwner implements ResourceOwnerInterface
{
    private $ownerId;

    public function __construct(string $ownerId)
    {
        $this->ownerId = $ownerId;
    }

    public function getOwnerId(): string
    {
        return $this->ownerId;
    }
}
