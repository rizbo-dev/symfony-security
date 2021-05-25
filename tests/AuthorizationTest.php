<?php


namespace App\Tests;


use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class AuthorizationTest extends WebTestCase
{
    
    protected function setUp(): void
    {
        $this->client = static::createClient();
        $this->userRepo = static::$container->get(UserRepository::class);
    }

    /** @test */
    public function an_admin_can_visit_the_admin_dashboard()
    {
        $testUser = $this->userRepo->findOneByEmail('boris.evetovic777@gmail.com');

        $this->client->loginUser($testUser);

        $this->client->request('GET', '/admin/dashboard');

        $this->assertResponseIsSuccessful();
    }

    /** @test */
    public function a_user_cannot_view_another_users_account()
    {
        $testUser = $this->userRepo->findOneByEmail('anon@anon.com');

        $this->client->loginUser($testUser);

        $this->client->request('GET', '/accounts/1');

        $this->assertResponseStatusCodeSame(403);
    }

    /** @test */
    public function an_account_holder_can_view_their_own_account()
    {
        $testUser = $this->userRepo->findOneByEmail('anotheruser@gmail.com');

        $this->client->loginUser($testUser);

        $this->client->request('GET', '/accounts/1');

        $this->assertResponseIsSuccessful();
    }

    /** @test */
    public function an_account_manager_can_view_accounts_which_they_manage()
    {
        $testUser = $this->userRepo->findOneByEmail('accmanager@example.com');

        $this->client->loginUser($testUser);

        $this->client->request('GET', '/accounts/1');

        $this->assertResponseIsSuccessful();
    }

    /** @test */
    public function a_non_admin_can_not_delete_an_account()
    {
        $testUser = $this->userRepo->findOneByEmail('anon@anon.com');

        $this->client->loginUser($testUser);

        $this->client->request('GET', '/accounts/1/delete');

        $this->assertResponseStatusCodeSame(403);
    }

    /** @test */
    public function an_admin_can_delete_an_account()
    {
        $testUser = $this->userRepo->findOneByEmail('boris.evetovic777@gmail.com');

        $this->client->loginUser($testUser);

        $this->client->request('GET', '/accounts/1/delete');

        $this->assertResponseIsSuccessful();
    }
}