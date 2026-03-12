<?php

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Applies all security-relevant HTTP response headers.
 *
 * Key design decisions:
 * - Referrer-Policy: no-referrer prevents the AES key (embedded in the share
 *   URL query string) from leaking to CDN servers via the Referer header.
 * - Cache-Control: no-store ensures browsers never cache pages that may
 *   contain a revealed secret.
 * - script-src uses 'self' + the pinned CDN origin; no 'unsafe-inline'.
 *   All JavaScript lives in /js/app.js (served as a static file).
 * - style-src allows 'unsafe-inline' for the inline <style> block; inline
 *   styles cannot execute code so this is an acceptable trade-off.
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

        // Never cache — pages may contain revealed secrets or share links
        $response->headers->set('Cache-Control', 'no-store, private');

        // Prevent MIME-type sniffing
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Forbid framing (clickjacking protection)
        $response->headers->set('X-Frame-Options', 'DENY');

        // Critical: suppress the Referer header so the AES key in the share
        // URL never leaks to CDN servers (Bootstrap JS/CSS on jsdelivr.net)
        $response->headers->set('Referrer-Policy', 'no-referrer');

        // Disable browser features not needed by this app
        $response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

        // Block cross-domain policy files (Flash/Java legacy attack surface)
        $response->headers->set('X-Permitted-Cross-Domain-Policies', 'none');

        // Content Security Policy
        // - script-src: 'self' covers /js/app.js; jsdelivr.net covers Bootstrap.
        //   No 'unsafe-inline' — event handlers use addEventListener in app.js.
        // - style-src: 'unsafe-inline' is acceptable here (inline <style> block);
        //   styles cannot execute arbitrary code.
        $csp = implode('; ', [
            "default-src 'self'",
            "script-src 'self' https://cdn.jsdelivr.net",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]);
        $response->headers->set('Content-Security-Policy', $csp);

        // HTTP Strict Transport Security (only meaningful over HTTPS)
        if ($request->isSecure()) {
            $response->headers->set(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            );
        }
    }
}
