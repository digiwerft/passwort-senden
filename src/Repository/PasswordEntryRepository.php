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

    /**
     * Find a PasswordEntry by its created_stamp (second precision, UTC).
     */
    public function findByCreatedStamp(\DateTime $createdStamp): ?PasswordEntry
    {
        // Use a native SQL query to avoid Doctrine DateTime timezone conversion issues.
        // The created_stamp is stored as UTC 'Y-m-d H:i:s'; we compare as a plain string.
        $stamp = $createdStamp->format('Y-m-d H:i:s');

        $conn   = $this->getEntityManager()->getConnection();
        $result = $conn->executeQuery(
            'SELECT id FROM password_entry WHERE created_stamp = ?',
            [$stamp]
        )->fetchAssociative();

        if (!$result) {
            return null;
        }

        return $this->find((int) $result['id']);
    }

    /**
     * Delete all entries where validity < NOW().
     */
    public function deleteExpired(): int
    {
        return $this->createQueryBuilder('p')
            ->delete()
            ->where('p.validity < :now')
            ->setParameter('now', new \DateTime())
            ->getQuery()
            ->execute();
    }
}
