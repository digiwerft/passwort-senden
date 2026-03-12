<?php

namespace App\Entity;

use App\Repository\PasswordEntryRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: PasswordEntryRepository::class)]
#[ORM\Table(name: 'password_entry')]
#[ORM\Index(columns: ['uuid'], name: 'idx_uuid')]
#[ORM\Index(columns: ['validity'], name: 'idx_validity')]
#[ORM\HasLifecycleCallbacks]
class PasswordEntry
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'bigint', options: ['unsigned' => true])]
    private ?int $id = null;

    /**
     * Unique identifier embedded in the share URL. Used to look up entries
     * without exposing any sequential/predictable identifiers.
     */
    #[ORM\Column(name: 'uuid', type: 'string', length: 36, unique: true)]
    private string $uuid = '';

    #[ORM\Column(name: 'created_stamp', type: 'datetime')]
    private ?\DateTime $createdStamp = null;

    #[ORM\Column(name: 'modified_stamp', type: 'datetime', nullable: true)]
    private ?\DateTime $modifiedStamp = null;

    /**
     * AES-256-GCM encrypted secret. Format: base64(nonce[12] . tag[16] . ciphertext).
     */
    #[ORM\Column(type: 'text')]
    private string $secret = '';

    /**
     * Argon2id hash of the optional link password. Stored as a plain hash —
     * the AES key in the URL is never involved in link-password verification.
     */
    #[ORM\Column(name: 'link_password_hash', type: 'text', nullable: true)]
    private ?string $linkPasswordHash = null;

    #[ORM\Column(type: 'datetime')]
    private ?\DateTime $validity = null;

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $this->createdStamp = new \DateTime('now', new \DateTimeZone('UTC'));
    }

    #[ORM\PreUpdate]
    public function onPreUpdate(): void
    {
        $this->modifiedStamp = new \DateTime();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUuid(): string
    {
        return $this->uuid;
    }

    public function setUuid(string $uuid): static
    {
        $this->uuid = $uuid;
        return $this;
    }

    public function getCreatedStamp(): ?\DateTime
    {
        return $this->createdStamp;
    }

    public function getModifiedStamp(): ?\DateTime
    {
        return $this->modifiedStamp;
    }

    public function getSecret(): string
    {
        return $this->secret;
    }

    public function setSecret(string $secret): static
    {
        $this->secret = $secret;
        return $this;
    }

    public function getLinkPasswordHash(): ?string
    {
        return $this->linkPasswordHash;
    }

    public function setLinkPasswordHash(?string $linkPasswordHash): static
    {
        $this->linkPasswordHash = $linkPasswordHash;
        return $this;
    }

    public function getValidity(): ?\DateTime
    {
        return $this->validity;
    }

    public function setValidity(\DateTime $validity): static
    {
        $this->validity = $validity;
        return $this;
    }
}
