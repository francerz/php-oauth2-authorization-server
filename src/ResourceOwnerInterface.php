<?php

namespace Francerz\OAuth2\AuthServer;

interface ResourceOwnerInterface
{
    public function getOwnerId(): string;
}
