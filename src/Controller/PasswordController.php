<?php

namespace App\Controller;

use App\Service\PasswordService;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;

class PasswordController extends AbstractController
{
    private const MAX_SECRET_LENGTH        = 50_000;
    private const MAX_LINK_PASSWORD_LENGTH = 1_024;

    public function __construct(
        private readonly PasswordService $passwordService,
        private readonly LoggerInterface $logger,
        #[Autowire(service: 'limiter.password_create')]
        private readonly RateLimiterFactory $createLimiter,
        #[Autowire(service: 'limiter.password_reveal')]
        private readonly RateLimiterFactory $revealLimiter,
        #[Autowire(service: 'limiter.password_reveal_per_uuid')]
        private readonly RateLimiterFactory $revealPerUuidLimiter,
        #[Autowire(service: 'limiter.password_show')]
        private readonly RateLimiterFactory $showLimiter,
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
        if (!$this->createLimiter->create($request->getClientIp())->consume()->isAccepted()) {
            $this->logger->warning('rate_limit.create', ['ip' => $request->getClientIp()]);
            throw new TooManyRequestsHttpException();
        }

        if (!$this->isCsrfTokenValid('create_password', $request->request->get('_csrf_token'))) {
            $this->logger->warning('csrf.create_failed', ['ip' => $request->getClientIp()]);
            $this->addFlash('error', 'Ungültige Anfrage (CSRF).');
            return $this->redirectToRoute('password_create');
        }

        $secret       = $request->request->get('secret', '');
        $linkPassword = $request->request->get('link_password', '') ?: null;
        $duration     = $request->request->get('duration', 'DAYS');

        if ($secret === '') {
            $this->addFlash('error', 'Bitte geben Sie ein Passwort ein.');
            return $this->redirectToRoute('password_create');
        }

        if (strlen($secret) > self::MAX_SECRET_LENGTH) {
            $this->addFlash('error', sprintf('Das Passwort darf maximal %s Zeichen lang sein.', number_format(self::MAX_SECRET_LENGTH)));
            return $this->redirectToRoute('password_create');
        }

        if ($linkPassword !== null && strlen($linkPassword) > self::MAX_LINK_PASSWORD_LENGTH) {
            $this->addFlash('error', sprintf('Das Linkpasswort darf maximal %d Zeichen lang sein.', self::MAX_LINK_PASSWORD_LENGTH));
            return $this->redirectToRoute('password_create');
        }

        if (!in_array($duration, ['HOURS', 'DAYS', 'WEEKS'], strict: true)) {
            $duration = 'DAYS';
        }

        $baseUrl = $request->getSchemeAndHttpHost();
        $link    = $this->passwordService->generate($secret, $linkPassword, $duration, $baseUrl);

        $this->logger->info('password.created', ['has_link_password' => $linkPassword !== null, 'duration' => $duration]);
        $this->addFlash('generated_link', $link);

        return $this->redirectToRoute('password_create');
    }

    #[Route('/show', name: 'password_show', methods: ['GET'])]
    public function show(Request $request): Response
    {
        if (!$this->showLimiter->create($request->getClientIp())->consume()->isAccepted()) {
            throw new TooManyRequestsHttpException();
        }

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
        $ip = $request->getClientIp();

        if (!$this->revealLimiter->create($ip)->consume()->isAccepted()) {
            $this->logger->warning('rate_limit.reveal_ip', ['ip' => $ip]);
            throw new TooManyRequestsHttpException();
        }

        if (!$this->isCsrfTokenValid('show_password', $request->request->get('_csrf_token'))) {
            $this->logger->warning('csrf.reveal_failed', ['ip' => $ip]);
            $this->addFlash('error', 'Ungültige Anfrage (CSRF).');
            return $this->redirectToRoute('password_create');
        }

        $secretKey    = $request->request->get('secretKey', '');
        $linkPassword = $request->request->get('link_password', '') ?: null;

        if ($secretKey === '') {
            $this->addFlash('error', 'Ungültiger Link.');
            return $this->redirectToRoute('password_create');
        }

        // Per-UUID rate limit — blocks distributed brute-force across many IPs
        if (!$this->revealPerUuidLimiter->create($secretKey)->consume()->isAccepted()) {
            $this->logger->warning('rate_limit.reveal_uuid', ['ip' => $ip]);
            throw new TooManyRequestsHttpException();
        }

        $plainText = $this->passwordService->reveal($secretKey, $linkPassword);

        if ($plainText === null) {
            $this->logger->notice('password.reveal_failed', ['ip' => $ip]);
            $this->addFlash('reveal_error', 'Das Passwort konnte nicht entschlüsselt werden. Möglicherweise ist das Linkpasswort falsch oder der Link ist abgelaufen.');
            return $this->redirectToRoute('password_show', ['secretKey' => $secretKey]);
        }

        $this->logger->info('password.revealed');
        $this->addFlash('revealed_password', $plainText);

        return $this->redirectToRoute('password_revealed');
    }

    #[Route('/revealed', name: 'password_revealed', methods: ['GET'])]
    public function revealed(): Response
    {
        return $this->render('password/revealed.html.twig');
    }
}
