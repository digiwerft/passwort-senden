<?php

namespace App\Service;

use App\Entity\PasswordEntry;
use App\Repository\PasswordEntryRepository;
use Doctrine\ORM\EntityManagerInterface;

class PasswordService
{
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly PasswordEntryRepository $passwordEntryRepository,
    ) {
    }

    /**
     * Encrypts the secret, stores it in the DB, and returns the full one-time URL.
     */
    public function generate(
        string $plainText,
        ?string $linkPassword,
        string $duration,
        string $baseUrl
    ): string {
        // Generate 256-bit (32-byte) AES key
        $key = random_bytes(32);

        // Encrypt secret with AES-256-ECB
        $encrypted = base64_encode(
            openssl_encrypt($plainText, 'AES-256-ECB', $key, OPENSSL_RAW_DATA)
        );

        // Encrypt link password if provided
        $encryptedLinkPwd = null;
        if ($linkPassword !== null && $linkPassword !== '') {
            $encryptedLinkPwd = base64_encode(
                openssl_encrypt($linkPassword, 'AES-256-ECB', $key, OPENSSL_RAW_DATA)
            );
        }

        // Calculate validity
        $validity = match ($duration) {
            'HOURS' => new \DateTime('+1 hour'),
            'DAYS'  => new \DateTime('+1 day'),
            'WEEKS' => new \DateTime('+1 week'),
            default => new \DateTime('+1 day'),
        };

        // Persist entry
        $entry = new PasswordEntry();
        $entry->setSecret($encrypted);
        $entry->setLinkPassword($encryptedLinkPwd);
        $entry->setValidity($validity);

        $this->entityManager->persist($entry);
        $this->entityManager->flush();

        // Build the secret key: base64(aes_key) . epoch_ms
        $keyBase64    = base64_encode($key); // 44 chars ending in ==
        $timestampMs  = $entry->getCreatedStamp()->getTimestamp() * 1000;
        $secretKeyRaw = $keyBase64 . $timestampMs;
        $secretKey    = urlencode($secretKeyRaw);

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

        $entry = $this->passwordEntryRepository->findByCreatedStamp($parsed['createdStamp']);
        if ($entry === null) {
            return false;
        }

        // Check if entry has expired
        if ($entry->getValidity() < new \DateTime()) {
            return false;
        }

        return true;
    }

    /**
     * Decrypts and returns the plaintext secret, then deletes the record.
     * Returns null if the entry is not found, expired, or the link password is wrong.
     */
    public function reveal(string $secretKey, ?string $linkPassword): ?string
    {
        $parsed = $this->parseSecretKey($secretKey);
        if ($parsed === null) {
            return null;
        }

        $key         = $parsed['key'];
        $createdStamp = $parsed['createdStamp'];

        $entry = $this->passwordEntryRepository->findByCreatedStamp($createdStamp);
        if ($entry === null) {
            return null;
        }

        // Check expiry
        if ($entry->getValidity() < new \DateTime()) {
            $this->entityManager->remove($entry);
            $this->entityManager->flush();
            return null;
        }

        // Verify link password if one was set
        if ($entry->getLinkPassword() !== null) {
            if ($linkPassword === null || $linkPassword === '') {
                return null;
            }
            $expectedEncryptedLinkPwd = base64_encode(
                openssl_encrypt($linkPassword, 'AES-256-ECB', $key, OPENSSL_RAW_DATA)
            );
            if (!hash_equals($entry->getLinkPassword(), $expectedEncryptedLinkPwd)) {
                return null;
            }
        }

        // Decrypt the secret
        $plainText = openssl_decrypt(
            base64_decode($entry->getSecret()),
            'AES-256-ECB',
            $key,
            OPENSSL_RAW_DATA
        );

        // Delete the record immediately (one-time use)
        $this->entityManager->remove($entry);
        $this->entityManager->flush();

        return $plainText !== false ? $plainText : null;
    }

    /**
     * Checks whether this secret key entry requires a link password.
     */
    public function requiresLinkPassword(string $secretKey): bool
    {
        $parsed = $this->parseSecretKey($secretKey);
        if ($parsed === null) {
            return false;
        }

        $entry = $this->passwordEntryRepository->findByCreatedStamp($parsed['createdStamp']);
        if ($entry === null) {
            return false;
        }

        return $entry->getLinkPassword() !== null;
    }

    /**
     * Parses the URL-encoded secret key into its components.
     *
     * Format: urlencode(base64(aes_key) . epoch_ms)
     * The base64 key is 44 chars ending in '==' or '=' (always ends with '=').
     * We find the last '=' in the decoded string; everything up to and including
     * it is the base64 key, everything after is the epoch ms timestamp.
     *
     * @return array{key: string, createdStamp: \DateTime}|null
     */
    private function parseSecretKey(string $secretKey): ?array
    {
        // Symfony already URL-decodes query parameters (%2B→+, %2F→/, %3D→=).
        // Calling urldecode() again would corrupt the base64 key by turning + into spaces.
        $decoded = $secretKey;

        $lastEq = strrpos($decoded, '=');
        if ($lastEq === false) {
            return null;
        }

        $keyBase64   = substr($decoded, 0, $lastEq + 1);
        $timestampMs = substr($decoded, $lastEq + 1);

        if (!is_numeric($timestampMs)) {
            return null;
        }

        $key = base64_decode($keyBase64);
        if (strlen($key) !== 32) {
            return null;
        }

        $timestampSeconds = intdiv((int) $timestampMs, 1000);
        $createdStamp     = new \DateTime('@' . $timestampSeconds);
        $createdStamp->setTimezone(new \DateTimeZone('UTC'));

        return ['key' => $key, 'createdStamp' => $createdStamp];
    }
}
