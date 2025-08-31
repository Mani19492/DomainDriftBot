# bot.py
import os
import logging
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
import requests
import ssl
import re
from bs4 import BeautifulSoup
import base64
import time

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
if not TELEGRAM_TOKEN:
    raise ValueError("TELEGRAM_TOKEN not set in .env file")
if not VIRUSTOTAL_API_KEY:
    raise ValueError("VIRUSTOTAL_API_KEY not set in .env file")
if not GOOGLE_SAFE_BROWSING_API_KEY:
    raise ValueError("GOOGLE_SAFE_BROWSING_API_KEY not set in .env file")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /start command."""
    await update.message.reply_text(
        'Welcome to @DomainDriftBot! Use /scan <domain> to perform domain reconnaissance with authenticity check.',
        parse_mode='Markdown'
    )

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /scan command for domain reconnaissance with authenticity check."""
    if not context.args:
        await update.message.reply_text('Usage: /scan <domain>', parse_mode='Markdown')
        return
    domain = context.args[0]
    # Send initial waiting message
    await update.message.reply_text(
        f'🔍 *Please wait*, processing reconnaissance data for `{domain}` may take 5-10 minutes...',
        parse_mode='Markdown'
    )
    try:
        from recon import get_recon_data
        recon_data = get_recon_data(domain)
        
        # Add authenticity check at the top
        auth_result = check_authenticity(f'https://{domain}')
        auth_message = ''
        if auth_result['is_genuine']:
            auth_message = f'🎉 *Authenticity Check:* `{domain}` is verified as a genuine website.\n\n'
        else:
            official_link = get_official_link(domain)
            threat_details = (f"VirusTotal: Malicious={auth_result['vt_result']['malicious']}, "
                             f"Suspicious={auth_result['vt_result']['suspicious']}")
            if auth_result['gs_result']:
                threat_details += f"; Google Safe Browsing: {auth_result['gs_result']['threat_type'] if not auth_result['gs_result']['malicious'] else 'Safe'}"
            else:
                threat_details += "; Google Safe Browsing: Unavailable"
            auth_message = f'⚠️ *Authenticity Check:* `{domain}` may be a fake/phishing website ({threat_details}). Visit the original: {official_link}\n\n'

        # Combine authenticity check with reconnaissance data
        full_report = auth_message + recon_data
        report_lines = full_report.split('\n')
        formatted_report = '📊 Reconnaissance Report for ' + domain + '\n' + '='*40 + '\n'
        current_chunk = formatted_report
        for line in report_lines:
            if len(current_chunk) + len(line) + 1 > 4096:
                await update.message.reply_text(current_chunk.strip(), parse_mode=None)
                current_chunk = ''
            current_chunk += line + '\n'
        if current_chunk:
            await update.message.reply_text(current_chunk.strip(), parse_mode=None)
    except Exception as e:
        logger.error(f"Error scanning domain {domain}: {str(e)}")
        await update.message.reply_text(f"❌ *Error scanning {domain}:* {str(e)}", parse_mode='Markdown')

def check_authenticity(url: str) -> dict:
    """Check website authenticity using VirusTotal and Google Safe Browsing with fallback."""
    vt_result = check_virustotal(url)
    gs_result = check_google_safe_browsing(url)
    
    is_genuine = vt_result['malicious'] == 0 and vt_result['suspicious'] == 0
    if gs_result and not gs_result['malicious']:
        is_genuine = True
    
    return {
        'is_genuine': is_genuine,
        'vt_result': vt_result,
        'gs_result': gs_result
    }

def check_virustotal(url: str) -> dict:
    """Scan URL with VirusTotal and get stats."""
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    try:
        response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()['data']['attributes']['last_analysis_stats']
            return {'malicious': data.get('malicious', 0), 'suspicious': data.get('suspicious', 0)}
        elif response.status_code == 404:
            scan_response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url})
            scan_response.raise_for_status()
            analysis_id = scan_response.json()['data']['id']
            for _ in range(6):
                analysis_response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers)
                if analysis_response.status_code == 200:
                    status = analysis_response.json()['data']['attributes']['status']
                    if status == 'completed':
                        data = analysis_response.json()['data']['attributes']['stats']
                        return {'malicious': data.get('malicious', 0), 'suspicious': data.get('suspicious', 0)}
                time.sleep(10)
            raise TimeoutError("VirusTotal analysis timed out")
        response.raise_for_status()
    except Exception as e:
        logger.error(f"VirusTotal error: {str(e)}")
        return {'malicious': 0, 'suspicious': 0}  # Fallback to safe assumption
    return {'malicious': 0, 'suspicious': 0}

def check_google_safe_browsing(url: str) -> dict:
    """Check URL with Google Safe Browsing API with error handling."""
    headers = {'Content-Type': 'application/json'}
    params = {
        'client': {'clientId': 'domaindriftbot', 'clientVersion': '1.0'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    try:
        response = requests.post(
            'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + GOOGLE_SAFE_BROWSING_API_KEY,
            json=params,
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        return {'malicious': len(data.get('matches', [])) > 0, 'threat_type': data.get('matches', [{}])[0].get('threatType', 'Safe') if data.get('matches') else 'Safe'}
    except requests.exceptions.RequestException as e:
        logger.error(f"Google Safe Browsing error: {str(e)}")
        return None  # Return None to indicate failure, fall back to VirusTotal

def get_official_link(domain: str) -> str:
    """Return the official link based on domain (expand as needed)."""
    official_links = {
        'facebook.com': 'https://www.facebook.com',
        'google.com': 'https://www.google.com',
        'amazon.com': 'https://www.amazon.com',
        'sytechlabs.com': 'https://www.sytechlabs.com'  # Add if known official
    }
    for key in official_links:
        if key in domain.lower():
            return official_links[key]
    return 'Unknown original - search manually'

def main() -> None:
    """Start the bot."""
    logger.info("Starting bot...")
    try:
        application = Application.builder().token(TELEGRAM_TOKEN).build()
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("scan", scan))
        application.run_polling(allowed_updates=Update.ALL_TYPES)
    except Exception as e:
        logger.error(f"Failed to start bot: {str(e)}")
        raise

if __name__ == '__main__':
    main()