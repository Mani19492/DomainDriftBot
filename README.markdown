
# DomainDriftBot

## Overview
DomainDriftBot is a Python-based Telegram bot developed in 2025 for domain reconnaissance and authenticity verification. It scans domains and provides detailed reports, including WHOIS data, DNS records, SSL certificates, and security checks using VirusTotal and Google Safe Browsing APIs.

## Features
- **Domain Scanning**: Comprehensive reconnaissance with WHOIS, DNS, and traceroute data.
- **Authenticity Check**: Verifies domains using VirusTotal and Google Safe Browsing.
- **Error Handling**: Robust fallbacks for API failures.
- **Real-Time Updates**: Dynamic reporting via Telegram.

## Prerequisites
- Python 3.8 or higher
- Required libraries:
  - `python-telegram-bot`
  - `requests`
  - `dns.resolver`
  - `beautifulsoup4`
  - `cachetools`
  - `python-dotenv`
- API Keys:
  - Telegram Bot Token
  - VirusTotal API Key
  - Google Safe Browsing API Key
  - WHOISXMLAPI Key (optional)

## Installation
1. Clone the repository:

```bash
git clone https://github.com/Mani19492/DomainDriftBot.git
```

2. Navigate to the directory:

```bash
cd DomainDriftBot
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env
```

5. Edit `.env` to include your API keys (see `.env.example` for the required format).

6. Run the bot:

```bash
python bot.py
```

## Usage
- Start the bot with `/start`.
- Scan a domain with `/scan <domain>` (e.g., `/scan sytechlabs.com`).

## Files
- `bot.py`: Main bot logic and Telegram integration.
- `recon.py`: Domain reconnaissance functions.
- `.env.example`: Template for environment variables.

## License
This project is licensed under the [MIT License](LICENSE) - see the [LICENSE](LICENSE) file for details.

## Contact
- **YouTube Video**: [Watch here](https://youtu.be/wBUzmk0WUpE)
- **GitHub**: [Mani19492](https://github.com/Mani19492),[kiranmai-sys](https://github.com/kiranmai-sys),[lingalavaishnavi17](https://github.com/lingalavaishnavi17),[Sri-Rani](https://github.com/Sri-Rani)
- **Feedback**: Comment on the YouTube video or open an issue on GitHub.

## Future Plans
- Enhance API integrations.
- Add more reconnaissance features.
- Open to collaboration—reach out with ideas!
