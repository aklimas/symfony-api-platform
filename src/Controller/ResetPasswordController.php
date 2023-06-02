<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\ChangePasswordFormType;
use App\Form\ResetPasswordRequestFormType;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use SymfonyCasts\Bundle\ResetPassword\Controller\ResetPasswordControllerTrait;
use SymfonyCasts\Bundle\ResetPassword\Exception\ResetPasswordExceptionInterface;
use SymfonyCasts\Bundle\ResetPassword\ResetPasswordHelperInterface;

#[Route('/reset-password')]
class ResetPasswordController extends AbstractController
{
    use ResetPasswordControllerTrait;

    public function __construct(
        private ResetPasswordHelperInterface $resetPasswordHelper,
        private EntityManagerInterface       $entityManager,
        private UserRepository               $userRepository
    )
    {
    }

    /**
     * Display & process form to request a password reset.
     */
    #[Route('', name: 'app_forgot_password_request' ,methods: ['POST'])]
    public function request(Request $request, MailerInterface $mailer)
    {

        $data = json_decode($request->getContent(), true);

        // Pobierz adres e-mail z żądania
        $email = $data['email'];

        // Znajdź użytkownika na podstawie adresu e-mail
        $user = $this->userRepository->findOneBy(['email' => $email]);

        if (!$user) {
            return new JsonResponse(['error' => 'Nieprawidłowy adres e-mail'], 400);
        }

        return $this->processSendingPasswordResetEmail(
            $email,
            $mailer
        );
    }

    /**
     * Confirmation page after a user has requested a password reset.
     */
    #[Route('/check-email', name: 'app_check_email')]
    public function checkEmail(): Response
    {
        if (null === ($resetToken = $this->getTokenObjectFromSession())) {
            $resetToken = $this->resetPasswordHelper->generateFakeResetToken();
        }

        return new JsonResponse('Został wysłany email z linkiem do resetowania hasła');
    }

    /**
     * Validates and process the reset URL that the user clicked in their email.
     */
    #[Route('/reset/{token}', name: 'app_reset_password')]
    public function reset(Request $request, UserPasswordHasherInterface $passwordHasher, MailerInterface $mailer, string $token = null): Response
    {
        if ($token) {
            // We store the token in session and remove it from the URL, to avoid the URL being
            // loaded in a browser and potentially leaking the token to 3rd party JavaScript.
            $this->storeTokenInSession($token);

            return $this->redirectToRoute('app_reset_password');
        }

        $token = $this->getTokenFromSession();
        if (null === $token) {
            throw $this->createNotFoundException('No reset password token found in the URL or in the session.');
        }

        try {
            $user = $this->resetPasswordHelper->validateTokenAndFetchUser($token);
        } catch (ResetPasswordExceptionInterface $e) {
            $this->addFlash('reset_password_error', sprintf(
                '%s - %s',
                ResetPasswordExceptionInterface::MESSAGE_PROBLEM_VALIDATE,
                $e->getReason()
            ));

            return $this->redirectToRoute('app_forgot_password_request');
        }

        // A password reset token should be used only once, remove it.
        $this->resetPasswordHelper->removeResetRequest($token);

        $newPassword = $this->generateRandomString(6);
        // Encode(hash) the plain password, and set it.
        $encodedPassword = $passwordHasher->hashPassword(
            $user,
            $newPassword
        );

        $user->setPassword($encodedPassword);
        $this->entityManager->flush();


        $email = (new TemplatedEmail())
            ->from(new Address('dev@programigo.com', 'Programigo'))
            ->to($user->getEmail())
            ->subject('Nowe hasło')
            ->htmlTemplate('reset_password/emailConfirm.html.twig')
            ->context([
                'newPassword' => $newPassword,
            ]);

        $mailer->send($email);

        // The session is cleaned up after the password has been changed.
        $this->cleanSessionAfterReset();

        return new JsonResponse(true);
    }

    private function processSendingPasswordResetEmail(string $emailFormData, MailerInterface $mailer): RedirectResponse
    {
        $user = $this->entityManager->getRepository(User::class)->findOneBy([
            'email' => $emailFormData,
        ]);

        // Do not reveal whether a user account was found or not.
        if (!$user) {
            return $this->redirectToRoute('app_check_email');
        }

        try {
            $resetToken = $this->resetPasswordHelper->generateResetToken($user);
        } catch (ResetPasswordExceptionInterface $e) {
            // If you want to tell the user why a reset email was not sent, uncomment
            // the lines below and change the redirect to 'app_forgot_password_request'.
            // Caution: This may reveal if a user is registered or not.
            //
            // $this->addFlash('reset_password_error', sprintf(
            //     '%s - %s',
            //     ResetPasswordExceptionInterface::MESSAGE_PROBLEM_HANDLE,
            //     $e->getReason()
            // ));

            return $this->redirectToRoute('app_check_email');
        }

        $email = (new TemplatedEmail())
            ->from(new Address('dev@programigo.com', 'Programigo'))
            ->to($user->getEmail())
            ->subject('Resetowania hasła')
            ->htmlTemplate('reset_password/email.html.twig')
            ->context([
                'resetToken' => $resetToken,
            ]);

        $mailer->send($email);

        // Store the token object in session for retrieval in check-email route.
        $this->setTokenObjectInSession($resetToken);

        return $this->redirectToRoute('app_check_email');
    }

    function generateRandomString($length)
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    #[Route('/new-password', name: 'new_password', methods: ["POST"])]
    public function newPassword(Request $request, UserPasswordHasherInterface $passwordEncoder): Response
    {
        $this->isGranted('ROLE_USER');

        $data = json_decode($request->getContent(), true);

        $newPassword = $data['newPassword'];

        $user = $this->userRepository->find($this->getUser());

        if (!$user) {
            throw $this->createNotFoundException('Użytkownik o podanym ID nie istnieje.');
        }

        $encodedPassword = $passwordEncoder->hashPassword(
            $user,
            $newPassword
        );

        $user->setPassword($encodedPassword);

        // Zapisz zmiany w bazie danych
        $this->userRepository->save($user,true);

        // Zwróć odpowiedź
        return new Response('Hasło zostało zmienione.');
    }

}
