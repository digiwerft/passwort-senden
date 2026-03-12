# Cyber-Securitas — One-Time Secret Sharing

A self-hosted web application for sharing passwords and sensitive information securely via one-time links. Built with Symfony 7.4 by [DIGIWERFT GmbH](https://digiwerft.de).

## How It Works

1. Paste your secret (password, API key, credentials, etc.)
2. Optionally protect the link with an additional password
3. Choose an expiry duration (hours, days, or weeks)
4. Share the generated link — it can only be revealed **once**, then it's gone

The encryption key is embedded in the share URL itself and never stored on the server. Even a full database breach exposes no plaintext secrets.

## Security Features

- **AES-256-GCM** authenticated encryption
- **Zero server-side key storage** — the 32-byte key lives only in the share URL
- **Link passwords** hashed with Argon2id (never stored in plaintext)
- **One-time reveal** — secret is deleted from the database on first access
- **Rate limiting** — per-IP and per-UUID limits to prevent brute-force attacks
- **CSRF protection** on all forms
- **Security headers** — CSP, HSTS, X-Frame-Options, Referrer-Policy: no-referrer
- **No user accounts** — fully anonymous, no tracking

## Requirements

- PHP 8.2+
- MySQL 8.x
- Composer
- Symfony CLI (optional, for local dev)

## Installation

```bash
git clone https://github.com/digiwerft/passwort-senden.git
cd passwort-senden
composer install
cp .env .env.local
```

Edit `.env.local` and set:

```dotenv
APP_ENV=prod
APP_SECRET=your-64-char-hex-secret
DATABASE_URL="mysql://user:password@127.0.0.1:3306/passwort_senden"
```

Create the database schema:

```bash
php bin/console doctrine:database:create
php bin/console doctrine:schema:create
```

## Cleanup

Expired secrets are not automatically deleted on reveal. Run the cleanup command periodically via cron:

```bash
# crontab — run every hour
0 * * * * php /var/www/password-senden/bin/console app:cleanup-passwords
```

## Tech Stack

| Layer       | Technology                  |
|-------------|------------------------------|
| Framework   | Symfony 7.4 (LTS)           |
| ORM         | Doctrine ORM 3.x / DBAL 4.x |
| Database    | MySQL 8.x                   |
| Templates   | Twig + Bootstrap 5.3         |
| PHP         | 8.2+                        |

## License

MIT — see [LICENSE](LICENSE).

---

Built with the assistance of [Claude Code](https://claude.ai/claude-code) by Anthropic.
