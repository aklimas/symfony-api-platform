<?php
// tests/AuthenticationTest.php

namespace App\Tests;

use ApiPlatform\Symfony\Bundle\Test\ApiTestCase;
use App\Entity\User;
use App\Repository\UserRepository;
use Hautelook\AliceBundle\PhpUnit\ReloadDatabaseTrait;

class AuthenticationTest extends ApiTestCase
{
    use ReloadDatabaseTrait;

    public function testLogin(): void
    {
        $client = self::createClient();
        $container = self::getContainer();

        $user = new User();
        $user->setEmail('admin@programigo.com');
        $user->setPassword(
            $container->get('security.user_password_hasher')->hashPassword($user, 'AppCode2021!')
        );

        $manager = $container->get('doctrine')->getManager();
        $manager->persist($user);
        $manager->flush();

        // retrieve a token
        $response = $client->request('GET', '/auth', [
            'headers' => ['Content-Type' => 'application/json'],
            'json' => [
                'email' => 'admin@programigo.com',
                'password' => 'AppCode2021!',
                'roles' => [
                    'ROLE_USER'
                ]
            ],
        ]);

        $json = $response->toArray();
        $this->assertResponseIsSuccessful();
        $this->assertArrayHasKey('token', $json);

        // test not authorized
        $client->request('GET', '/greeting');
        $this->assertResponseStatusCodeSame(401);

        // test authorized
        $client->request('GET', '/api/users', ['auth_bearer' => $json['token']]);
        $this->assertResponseIsSuccessful();
    }
}
