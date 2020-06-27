<?php

declare(strict_types=1);

namespace BNLambert\Phalcon\Auth\Tests\Unit;

use BNLambert\Phalcon\Auth\Traits\DBQuery as DBQueryTait;

class DBQueryTraitTest extends AbstractUnitTest
{
    public function testTestCase(): void
    {
        $authWith = ['email'];
        $credentials = ['email' => 'test@test.com', 'password' => 'test'];
        $flags = [];

        $mock = $this->getMockForTrait(DBQueryTait::class);
        $result = $mock->makeConditions($authWith, $credentials, $flags);

        $this->assertArrayHasKey('conditions', $result);
        $this->assertArrayHasKey('bindParams', $result);
    }
}
