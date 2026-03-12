<?php

namespace App\Controller;

use App\Service\PasswordService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class PasswordController extends AbstractController
{
    public function __construct(
        private readonly PasswordService $passwordService,
    ) {
    }

    #[Route('/', name: 'password_create', methods: ['GET'])]
    public function create(): Response
    {
        return $this->render('password/create.html.twig');
    }

    #[Route('/', name: 'password_create_post', methods: ['POST'])]
    public function createPost(Request $request): Response
    {
        $secret       = $request->request->get('secret', '');
        $linkPassword = $request->request->get('link_password', '') ?: null;
        $duration     = $request->request->get('duration', 'DAYS');

        if (!$this->isCsrfTokenValid('create_password', $request->request->get('_csrf_token'))) {
            $this->addFlash('error', 'Ungültige Anfrage (CSRF).');
            return $this->redirectToRoute('password_create');
        }

        if ($secret === '') {
            $this->addFlash('error', 'Bitte geben Sie ein Passwort ein.');
            return $this->redirectToRoute('password_create');
        }

        $allowedDurations = ['HOURS', 'DAYS', 'WEEKS'];
        if (!in_array($duration, $allowedDurations, true)) {
            $duration = 'DAYS';
        }

        $baseUrl = $request->getSchemeAndHttpHost();
        $link    = $this->passwordService->generate($secret, $linkPassword, $duration, $baseUrl);

        $this->addFlash('generated_link', $link);

        return $this->redirectToRoute('password_create');
    }

    #[Route('/show', name: 'password_show', methods: ['GET'])]
    public function show(Request $request): Response
    {
        $secretKey = $request->query->get('secretKey', '');

        if ($secretKey === '') {
            return $this->render('password/show.html.twig', [
                'valid'            => false,
                'secretKey'        => '',
                'requiresPassword' => false,
            ]);
        }

        $valid = $this->passwordService->isValid($secretKey);

        return $this->render('password/show.html.twig', [
            'valid'            => $valid,
            'secretKey'        => $secretKey,
            'requiresPassword' => $valid && $this->passwordService->requiresLinkPassword($secretKey),
        ]);
    }

    #[Route('/show', name: 'password_show_post', methods: ['POST'])]
    public function showPost(Request $request): Response
    {
        $secretKey    = $request->request->get('secretKey', '');
        $linkPassword = $request->request->get('link_password', '') ?: null;

        if (!$this->isCsrfTokenValid('show_password', $request->request->get('_csrf_token'))) {
            $this->addFlash('error', 'Ungültige Anfrage (CSRF).');
            return $this->redirectToRoute('password_create');
        }

        if ($secretKey === '') {
            $this->addFlash('error', 'Ungültiger Link.');
            return $this->redirectToRoute('password_create');
        }

        $plainText = $this->passwordService->reveal($secretKey, $linkPassword);

        if ($plainText === null) {
            // Could be wrong link password or expired/missing entry
            $this->addFlash('reveal_error', 'Das Passwort konnte nicht entschlüsselt werden. Möglicherweise ist das Linkpasswort falsch oder der Link ist abgelaufen.');
            return $this->redirectToRoute('password_show', ['secretKey' => $secretKey]);
        }

        $this->addFlash('revealed_password', $plainText);

        return $this->redirectToRoute('password_revealed');
    }

    #[Route('/revealed', name: 'password_revealed', methods: ['GET'])]
    public function revealed(): Response
    {
        return $this->render('password/revealed.html.twig');
    }
}
