# DomainDriftBot

## Overview
DomainDriftBot is a Python-based Telegram bot I developed in 2025 for domain reconnaissance and authenticity verification. It scans domains, providing detailed reports including WHOIS data, DNS records, SSL certificates, and security checks using VirusTotal and Google Safe Browsing APIs.

## Features
- **Domain Scanning**: Comprehensive reconnaissance with WHOIS, DNS, and traceroute data.
- **Authenticity Check**: Verifies domains using VirusTotal and Google Safe Browsing.
- **Error Handling**: Robust fallbacks for API failures.
- **Real-Time Updates**: Dynamic reporting via Telegram.

## Prerequisites
- Python 3.8+
- Required libraries: `python-telegram-bot`, `requests`, `dns.resolver`, `beautifulsoup4`, `cachetools`, `python-dotenv`
- API Keys:
  - Telegram Bot Token
  - VirusTotal API Key
  - Google Safe Browsing API Key
  - WHOISXMLAPI Key (optional)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/DomainDriftBot.git
   ```
2. Navigate to the directory:
   ```bash
   cd DomainDriftBot
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create a `.env` file with your API keys (see `.env.example`).
5. Run the bot:
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
[MIT License] - Feel free to modify and distribute.

## Contact
- YouTube Video: [Link to your video, e.g., https://youtu.be/wBUzmk0WUpE]
- GitHub: [Mani19492](https://github.com/Mani19492)
- Feedback: Comment on the video or open an issue here!

## Future Plans
- Enhance API integrations.
- Add more reconnaissance features.
- Open to collaboration—let me know!
