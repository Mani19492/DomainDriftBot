<h1 align="center">DomainDriftBot 🔍</h1>
<h3 align="center">A Python-powered Telegram Bot for Domain Recon & Authenticity Checks</h3>

<p align="center">
  <img src="./__pycache__/DomainDriftBot.jpg" alt="DomainDriftBot Image" width="300">
</p>

<p align="center">
  <img src="https://komarev.com/ghpvc/?username=mani19492&label=Profile%20views&color=0e75b6&style=flat" alt="mani19492" />
  <a href="https://github.com/ryo-ma/github-profile-trophy"><img src="https://github-profile-trophy.vercel.app/?username=mani19492&theme=onedark" alt="mani19492" /></a>
</p>

<p align="center">
  <a href="https://twitter.com/spmteja1" target="_blank"><img src="https://img.shields.io/twitter/follow/spmteja1?logo=twitter&style=for-the-badge" alt="spmteja1" /></a>
</p>

---

## 🚀 What is DomainDriftBot?
Launched in 2025, **DomainDriftBot** is a Telegram bot built for **domain reconnaissance** and **authenticity verification**. It delivers in-depth reports on WHOIS, DNS, SSL certificates, traceroutes, and more, while ensuring safety with VirusTotal and Google Safe Browsing checks. Crafted with passion by a team of cybersecurity enthusiasts, this bot makes domain exploration secure and fun! 🌐

---

## ✨ Features
- **Deep Reconnaissance**: WHOIS, DNS, SSL, subdomains, and traceroute data in one report.
- **Authenticity Checks**: Validates domains using VirusTotal and Google Safe Browsing APIs.
- **Robust Fallbacks**: Handles API failures with multiple WHOIS sources, including `python-whois`.
- **Dynamic Reports**: Real-time, emoji-rich Telegram reports with MarkdownV2 formatting.
- **Engaging Touch**: Random cybersecurity tips for a unique experience! 😎

---

## 🛠 Get Started
### Prerequisites
- Python 3.8 or higher
- Libraries:
  - `python-telegram-bot`
  - `requests`
  - `dnspython`
  - `beautifulsoup4`
  - `cachetools`
  - `python-dotenv`
  - `python-whois`
- API Keys:
  - Telegram Bot Token ([BotFather](https://t.me/BotFather))
  - VirusTotal API Key ([VirusTotal](https://www.virustotal.com/))
  - Google Safe Browsing API Key ([Google Cloud](https://cloud.google.com/))
  - WHOISXMLAPI Key (optional, [WHOISXMLAPI](https://www.whoisxmlapi.com/))

### Installation
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
4. Set up `.env`:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your API keys (see `.env.example` for format).
5. Run the bot:
   ```bash
   python bot.py
   ```

### Usage
- **Start**: Send `/start` for a warm welcome.
- **Scan**: Use `/scan <domain>` (e.g., `/scan sytechlabs.com`) for a detailed report.
- **Output**: Get a full, beautifully formatted report split into chunks if needed.

---

## 📂 Project Structure
- `bot.py`: Core bot logic and Telegram integration.
- `recon.py`: Reconnaissance functions with enhanced WHOIS fallbacks.
- `.env.example`: Template for API keys.
- `requirements.txt`: List of Python dependencies.

---

## 👨‍💻 About the Team
Hi, I'm **S.Poorna Mani Teja**, a Cybersecurity & AI Enthusiast, Frontend Developer, and Student, joined by a talented team of collaborators!

- 🌐 My projects: [spmteja.xyz](https://spmteja.xyz)
- 📫 Reach me: **spmteja09@gmail.com**
- 📄 My journey: [Resume](https://spmteja.xyz/S.%20Poorna%20Mani%20Teja.pdf)
- ⚡ Fun fact: *I built a rover with Mecanum wheels that navigates obstacles autonomously!* 🚀🤖

**Collaborators**:
- [Mani19492](https://github.com/Mani19492)
- [kiranmai-sys](https://github.com/kiranmai-sys)
- [lingalavaishnavi17](https://github.com/lingalavaishnavi17)
- [Sri-Rani](https://github.com/Sri-Rani)

<h3 align="center">Connect with Me:</h3>
<p align="center">
  <a href="https://twitter.com/spmteja1" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/twitter.svg" alt="spmteja1" height="30" width="40" /></a>
  <a href="https://linkedin.com/in/singamsetti-poorna-mani-teja-8a2872287" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/linked-in-alt.svg" alt="singamsetti-poorna-mani-teja-8a2872287" height="30" width="40" /></a>
  <a href="https://www.youtube.com/c/singamsepoornamaniteja" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/youtube.svg" alt="singamsepoornamaniteja" height="30" width="40" /></a>
</p>

---

## 🛠 Languages and Tools
<p align="center">
  <a href="https://www.python.org" target="_blank"><img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/python/python-original.svg" alt="python" width="40" height="40"/></a>
  <a href="https://www.w3.org/html/" target="_blank"><img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/html5/html5-original-wordmark.svg" alt="html5" width="40" height="40"/></a>
  <a href="https://www.w3schools.com/css/" target="_blank"><img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/css3/css3-original-wordmark.svg" alt="css3" width="40" height="40"/></a>
  <a href="https://www.cprogramming.com/" target="_blank"><img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/c/c-original.svg" alt="c" width="40" height="40"/></a>
  <a href="https://git-scm.com/" target="_blank"><img src="https://www.vectorlogo.zone/logos/git-scm/git-scm-icon.svg" alt="git" width="40" height="40"/></a>
  <a href="https://www.mysql.com/" target="_blank"><img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/mysql/mysql-original-wordmark.svg" alt="mysql" width="40" height="40"/></a>
  <a href="https://www.linux.org/" target="_blank"><img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/linux/linux-original.svg" alt="linux" width="40" height="40"/></a>
</p>

---

## 📊 My Stats
<p align="center">
  <img src="https://github-readme-stats.vercel.app/api/top-langs?username=mani19492&show_icons=true&locale=en&layout=compact&theme=radical" alt="mani19492" />
  <img src="https://github-readme-stats.vercel.app/api?username=mani19492&show_icons=true&locale=en&theme=radical" alt="mani19492" />
  <img src="https://github-readme-streak-stats.herokuapp.com/?user=mani19492&theme=radical" alt="mani19492" />
</p>

---

## 🎥 Demo
See DomainDriftBot in action: [YouTube Video](https://youtu.be/wBUzmk0WUpE)

---

## 📜 License
This project is licensed under the [MIT License](LICENSE). See the [LICENSE](LICENSE) file for details.

---

## 🌈 Future Plans
- Enhance API integrations for deeper recon.
- Add advanced features like port scanning and subdomain enumeration.
- Open to collaboration—share your ideas!

---

## 🙌 Get Involved
Love what DomainDriftBot can do? Want to make it even better? Open an issue, submit a PR, or reach out via:
- [YouTube](https://www.youtube.com/c/singamsepoornamaniteja) (drop a comment!)
- [Twitter](https://twitter.com/spmteja1)
- [GitHub Issues](https://github.com/Mani19492/DomainDriftBot/issues)

Let’s secure the web together! 🔐
