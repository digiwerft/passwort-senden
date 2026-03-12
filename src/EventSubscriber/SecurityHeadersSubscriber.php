<?php

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Adds security-relevant HTTP response headers to every request.
 *
 * Referrer-Policy: no-referrer is critical here — the AES key is embedded
 * in the share URL's query string, and without this header it would leak
 * via the Referer header to CDN or any third-party resource.
 */
class SecurityHeadersSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::RESPONSE => 'onKernelResponse'];
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $response = $event->getResponse();
        $request  = $event->getRequest();

        // Prevent MIME-type sniffing
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Forbid framing (clickjacking protection)
        $response->headers->set('X-Frame-Options', 'DENY');

        // Critical: suppress the Referer header so the AES key in the share
        // URL never leaks to CDN servers (Bootstrap JS/CSS on jsdelivr.net).
        $response->headers->set('Referrer-Policy', 'no-referrer');

        // Permissions Policy: disable browser features not needed by this app
        $response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

        // Content Security Policy
        // - script-src/style-src allow jsdelivr.net (Bootstrap CDN) + inline
        //   styles/scripts present in the Twig templates
        // - form-action 'self' prevents forms from submitting to external URLs
        // - frame-ancestors 'none' is a stronger alternative to X-Frame-Options
        $csp = implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]);
        $response->headers->set('Content-Security-Policy', $csp);

        // HTTP Strict Transport Security (only send over HTTPS)
        if ($request->isSecure()) {
            $response->headers->set(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            );
        }
    }
}
