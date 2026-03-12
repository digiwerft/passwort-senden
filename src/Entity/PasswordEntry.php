<?php

namespace App\Entity;

use App\Repository\PasswordEntryRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: PasswordEntryRepository::class)]
#[ORM\Table(name: 'password_entry')]
#[ORM\Index(columns: ['created_stamp'], name: 'idx_created_stamp')]
#[ORM\Index(columns: ['validity'], name: 'idx_validity')]
#[ORM\HasLifecycleCallbacks]
class PasswordEntry
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'bigint', options: ['unsigned' => true])]
    private ?int $id = null;

    #[ORM\Column(name: 'created_stamp', type: 'datetime')]
    private ?\DateTime $createdStamp = null;

    #[ORM\Column(name: 'modified_stamp', type: 'datetime', nullable: true)]
    private ?\DateTime $modifiedStamp = null;

    #[ORM\Column(type: 'text')]
    private string $secret = '';

    #[ORM\Column(name: 'link_password', type: 'text', nullable: true)]
    private ?string $linkPassword = null;

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

    public function getCreatedStamp(): ?\DateTime
    {
        return $this->createdStamp;
    }

    public function setCreatedStamp(\DateTime $createdStamp): static
    {
        $this->createdStamp = $createdStamp;
        return $this;
    }

    public function getModifiedStamp(): ?\DateTime
    {
        return $this->modifiedStamp;
    }

    public function setModifiedStamp(?\DateTime $modifiedStamp): static
    {
        $this->modifiedStamp = $modifiedStamp;
        return $this;
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

    public function getLinkPassword(): ?string
    {
        return $this->linkPassword;
    }

    public function setLinkPassword(?string $linkPassword): static
    {
        $this->linkPassword = $linkPassword;
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
