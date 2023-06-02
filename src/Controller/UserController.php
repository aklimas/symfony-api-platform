<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    #[Route('/api/current-user', name: 'current_user')]
    public function getCurrentUser(): Response
    {
        $this->denyAccessUnlessGranted("ROLE_USER");
        $user = $this->getUser();
        return $this->json($user);
    }
}
