<?php

namespace App\Command;

use App\Repository\PasswordEntryRepository;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'app:cleanup-passwords',
    description: 'Deletes all expired password entries from the database.',
)]
class CleanupPasswordsCommand extends Command
{
    public function __construct(
        private readonly PasswordEntryRepository $passwordEntryRepository,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $io->title('Cleaning up expired password entries');

        $deleted = $this->passwordEntryRepository->deleteExpired();

        $io->success(sprintf('Deleted %d expired password entr%s.', $deleted, $deleted === 1 ? 'y' : 'ies'));

        return Command::SUCCESS;
    }
}
