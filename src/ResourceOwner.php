<?php

namespace Francerz\OAuth2\AuthServer;

class ResourceOwner implements ResourceOwnerInterface
{
    private $uniqueId;
    public function __construct(string $uniqueId)
    {
        $this->uniqueId = $uniqueId;
    }

    public function getOwnerId(): string
    {
        return $this->uniqueId;
    }
}