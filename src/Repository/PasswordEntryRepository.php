<?php

namespace App\Repository;

use App\Entity\PasswordEntry;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class PasswordEntryRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, PasswordEntry::class);
    }

    public function findByUuid(string $uuid): ?PasswordEntry
    {
        return $this->findOneBy(['uuid' => $uuid]);
    }

    /**
     * Delete all entries where validity < NOW().
     */
    public function deleteExpired(): int
    {
        return (int) $this->createQueryBuilder('p')
            ->delete()
            ->where('p.validity < :now')
            ->setParameter('now', new \DateTime())
            ->getQuery()
            ->execute();
    }
}
