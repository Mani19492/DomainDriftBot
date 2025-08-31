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


if __name__ == '__main__':
    main()
