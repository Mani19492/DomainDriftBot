DomainDriftBot
A Telegram bot for domain reconnaissance, providing WHOIS, DNS, SSL certificate, and optional VirusTotal threat intelligence data.
Setup

Install Python 3.13:

Download from python.org.
Ensure python and pip are added to your PATH.


Clone or Create the Project:
mkdir C:\Users\spmte\Projects\bot
cd C:\Users\spmte\Projects\bot


Install Dependencies:
python -m pip install -r requirements.txt


Set Up Environment Variables:

Create a .env file in the project directory:TELEGRAM_TOKEN=8240966617:AAE6o_wvrGaZEeA-DpG6t9-WRjzJgoIDxh4
# Optional: VIRUSTOTAL_API_KEY=your_virustotal_api_key




Run the Bot:
python bot.py



Usage

/start: Displays a welcome message.
/login  : Authenticate using 19492 and Mani@2011.
/scan : Perform reconnaissance on a domain (e.g., /scan example.com).
/logout: End the session.

Notes

The bot uses a hardcoded WHOISXMLAPI key for WHOIS lookups.
VirusTotal API key is optional; without it, threat intelligence is unavailable.
Move the project to a local directory (C:\Users\spmte\Projects\bot) to avoid OneDrive sync issues.
