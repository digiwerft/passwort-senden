<?php

namespace App\Service;

use App\Entity\PasswordEntry;
use App\Repository\PasswordEntryRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Uid\Uuid;

class PasswordService
{
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly PasswordEntryRepository $passwordEntryRepository,
    ) {
    }

    /**
     * Encrypts the secret with AES-256-GCM, stores it in the DB, and returns the one-time URL.
     *
     * URL format: {base}/show?secretKey={base64url_key}.{uuid}
     * The 32-byte AES key is embedded in the URL; the server never stores it.
     */
    public function generate(
        string $plainText,
        ?string $linkPassword,
        string $duration,
        string $baseUrl
    ): string {
        $key = random_bytes(32);

        $encrypted = $this->encrypt($plainText, $key);

        $linkPasswordHash = null;
        if ($linkPassword !== null && $linkPassword !== '') {
            $linkPasswordHash = password_hash($linkPassword, PASSWORD_ARGON2ID);
        }

        $validity = match ($duration) {
            'HOURS' => new \DateTime('+1 hour'),
            'DAYS'  => new \DateTime('+1 day'),
            'WEEKS' => new \DateTime('+1 week'),
            default => new \DateTime('+1 day'),
        };

        $uuid = Uuid::v4()->toRfc4122();

        $entry = new PasswordEntry();
        $entry->setUuid($uuid);
        $entry->setSecret($encrypted);
        $entry->setLinkPasswordHash($linkPasswordHash);
        $entry->setValidity($validity);

        $this->entityManager->persist($entry);
        $this->entityManager->flush();

        $secretKey = $this->encodeKey($key) . '.' . $uuid;

        return $baseUrl . '/show?secretKey=' . $secretKey;
    }

    /**
     * Checks whether a valid (non-expired, existing) entry exists for this secretKey.
     */
    public function isValid(string $secretKey): bool
    {
        $parsed = $this->parseSecretKey($secretKey);
        if ($parsed === null) {
            return false;
        }

        $entry = $this->passwordEntryRepository->findByUuid($parsed['uuid']);
        if ($entry === null) {
            return false;
        }

        return $entry->getValidity() >= new \DateTime();
    }

    /**
     * Checks whether this secret key requires a link password.
     */
    public function requiresLinkPassword(string $secretKey): bool
    {
        $parsed = $this->parseSecretKey($secretKey);
        if ($parsed === null) {
            return false;
        }

        $entry = $this->passwordEntryRepository->findByUuid($parsed['uuid']);

        return $entry !== null && $entry->getLinkPasswordHash() !== null;
    }

    /**
     * Decrypts and returns the plaintext secret, then deletes the record (one-time use).
     * Returns null if the entry is missing, expired, or the link password is wrong.
     */
    public function reveal(string $secretKey, ?string $linkPassword): ?string
    {
        $parsed = $this->parseSecretKey($secretKey);
        if ($parsed === null) {
            return null;
        }

        $key  = $parsed['key'];
        $uuid = $parsed['uuid'];

        $entry = $this->passwordEntryRepository->findByUuid($uuid);
        if ($entry === null) {
            return null;
        }

        if ($entry->getValidity() < new \DateTime()) {
            $this->entityManager->remove($entry);
            $this->entityManager->flush();
            return null;
        }

        if ($entry->getLinkPasswordHash() !== null) {
            if ($linkPassword === null || $linkPassword === '') {
                return null;
            }
            if (!password_verify($linkPassword, $entry->getLinkPasswordHash())) {
                return null;
            }
        }

        $plainText = $this->decrypt($entry->getSecret(), $key);

        // Always delete after a reveal attempt that passes all checks (one-time use)
        $this->entityManager->remove($entry);
        $this->entityManager->flush();

        return $plainText;
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Encrypts $plaintext with AES-256-GCM (authenticated encryption).
     * Stored format: base64(nonce[12] . tag[16] . ciphertext)
     */
    private function encrypt(string $plaintext, string $key): string
    {
        $nonce = random_bytes(12);
        $tag   = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            '',
            16,
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed.');
        }

        return base64_encode($nonce . $tag . $ciphertext);
    }

    /**
     * Decrypts AES-256-GCM ciphertext. Returns null on any failure (wrong key, corrupted data).
     */
    private function decrypt(string $encoded, string $key): ?string
    {
        $raw = base64_decode($encoded, strict: true);
        if ($raw === false || strlen($raw) < 28) {
            return null;
        }

        $nonce      = substr($raw, 0, 12);
        $tag        = substr($raw, 12, 16);
        $ciphertext = substr($raw, 28);

        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
        );

        return $plaintext === false ? null : $plaintext;
    }

    /**
     * Encodes the 32-byte AES key as URL-safe base64 without padding (43 chars).
     */
    private function encodeKey(string $key): string
    {
        return rtrim(strtr(base64_encode($key), '+/', '-_'), '=');
    }

    /**
     * Parses the secretKey token.
     *
     * Format: {base64url_key}.{uuid}
     *   - base64url_key: 43 URL-safe base64 chars (32 raw bytes, no padding)
     *   - uuid: RFC 4122 UUID v4 string
     *
     * @return array{key: string, uuid: string}|null
     */
    private function parseSecretKey(string $secretKey): ?array
    {
        $dotPos = strpos($secretKey, '.');
        if ($dotPos !== 43) {
            return null;
        }

        $keyBase64url = substr($secretKey, 0, 43);
        $uuidStr      = substr($secretKey, 44);

        if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $uuidStr)) {
            return null;
        }

        $padding = str_repeat('=', (4 - 43 % 4) % 4); // 43 % 4 = 3 → 1 padding char
        $key     = base64_decode(strtr($keyBase64url, '-_', '+/') . $padding, strict: true);

        if ($key === false || strlen($key) !== 32) {
            return null;
        }

        return ['key' => $key, 'uuid' => $uuidStr];
    }
}
