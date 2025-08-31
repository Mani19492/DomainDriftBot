# recon.py
import requests
import dns.resolver
import ssl

def get_ip(domain: str) -> str:
    """Resolve domain to IP."""
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        logger.error(f"IP resolution failed for {domain}: {str(e)}")
        return None

def get_whois_data(domain: str) -> str:
    """Fetch WHOIS data with enhanced fallback."""
    if domain in whois_cache:
        return whois_cache[domain]

    result = "WHOIS Data for {domain}:\n"
    try:
        # Try WHOISXML API first
        if WHOISXMLAPI_KEY:
            url = f'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOISXMLAPI_KEY}&domainName={domain}&outputFormat=JSON'
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            data = response.json()
            whois_data = data.get('WhoisRecord', {})
            registrar = whois_data.get('registrarName', 'N/A')
            registrant = whois_data.get('registrant', {}).get('name', 'N/A')
            created = whois_data.get('createdDate', 'N/A')
            expires = whois_data.get('expiresDate', 'N/A')
            name_servers = ', '.join(whois_data.get('nameServers', {}).get('hostNames', ['N/A']))
            status = ', '.join(whois_data.get('status', ['N/A']))
            result += (f"Registrar: {registrar}\n"
                      f"Registrant: {registrant}\n"
                      f"Created: {created}\n"
                      f"Expires: {expires}\n"
                      f"Name Servers: {name_servers}\n"
                      f"Domain Status: {status}")
        else:
            result += "Registrar: N/A\nRegistrant: N/A\nCreated: N/A\nExpires: N/A\nName Servers: N/A\nDomain Status: N/A (WHOISXMLAPI_KEY not set)"
            return result.format(domain=domain)

        whois_cache[domain] = result.format(domain=domain)
        return result.format(domain=domain)
    except requests.exceptions.RequestException as e:
        logger.error(f"WHOISXML API error for {domain}: {str(e)}")
        try:
            # Fallback to who.is
            response = requests.get(f'https://who.is/whois/{domain}', timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            whois_info = soup.find('div', class_='col-md-8 queryResponseBodyStyle')
            if whois_info:
                text = whois_info.get_text()
                registrar_match = re.search(r'Registrar:\s*([^\n]+)', text)
                created_match = re.search(r'Creation Date:\s*([^\n]+)', text)
                expires_match = re.search(r'Expiry Date:\s*([^\n]+)', text)
                ns_match = re.search(r'Name Server:\s*([^\n]+)', text, re.MULTILINE)
                status_match = re.search(r'Status:\s*([^\n]+)', text)
                result += (f"Registrar: {registrar_match.group(1) if registrar_match else 'N/A'}\n"
                          f"Registrant: N/A\n"  # Privacy often hides this
                          f"Created: {created_match.group(1) if created_match else 'N/A'}\n"
                          f"Expires: {expires_match.group(1) if expires_match else 'N/A'}\n"
                          f"Name Servers: {ns_match.group(1) if ns_match else 'N/A'}\n"
                          f"Domain Status: {status_match.group(1) if status_match else 'N/A'} (via who.is)")
            else:
                result += "Registrar: N/A\nRegistrant: N/A\nCreated: N/A\nExpires: N/A\nName Servers: N/A\nDomain Status: N/A (who.is fallback failed)"
        except requests.exceptions.RequestException as e:
            logger.error(f"who.is fallback error for {domain}: {str(e)}")
            try:
                # Fallback to direct WHOIS server
                whois_server = 'whois.iana.org'
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(15)
                s.connect((whois_server, 43))
                s.send((domain + '\r\n').encode())
                response = b''
                while True:
                    data = s.recv(4096)
                    response += data
                    if not data:
                        break
                s.close()
                text = response.decode()
                registrar_match = re.search(r'Registrar:\s*([^\n]+)', text)
                created_match = re.search(r'Creation Date:\s*([^\n]+)', text)
                expires_match = re.search(r'Expiry Date:\s*([^\n]+)', text)
                ns_match = re.search(r'Name Server:\s*([^\n]+)', text, re.MULTILINE)
                status_match = re.search(r'Status:\s*([^\n]+)', text)
                result += (f"Registrar: {registrar_match.group(1) if registrar_match else 'N/A'}\n"
                          f"Registrant: N/A\n"
                          f"Created: {created_match.group(1) if created_match else 'N/A'}\n"
                          f"Expires: {expires_match.group(1) if expires_match else 'N/A'}\n"
                          f"Name Servers: {ns_match.group(1) if ns_match else 'N/A'}\n"
                          f"Domain Status: {status_match.group(1) if status_match else 'N/A'} (direct WHOIS)")
            except Exception as e:
                logger.error(f"Direct WHOIS error for {domain}: {str(e)}")
                result += "Registrar: N/A\nRegistrant: N/A\nCreated: N/A\nExpires: N/A\nName Servers: N/A\nDomain Status: N/A (all fallbacks failed)"
        whois_cache[domain] = result.format(domain=domain)
        return result.format(domain=domain)

def get_dns_data(domain: str) -> str:
    """Fetch DNS records."""
    try:
        records = []
        for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, qtype, raise_on_no_answer=False, lifetime=15)
                for rdata in answers:
                    records.append(f"{qtype}: {rdata.to_text()}")
            except Exception:
                records.append(f"{qtype}: No records found")
        return f"DNS Records for {domain}:\n" + "\n".join(records) if records else f"No DNS records for {domain}"
    except Exception as e:
        logger.error(f"DNS lookup failed for {domain}: {str(e)}")
        return f"DNS lookup failed: {str(e)}"

def get_ssl_data(domain: str) -> str:
    """Fetch SSL certificate details."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return (
                    f"SSL Certificate for {domain}:\n"
                    f"Issuer: {cert.get('issuer', 'N/A')}\n"
                    f"Subject: {cert.get('subject', 'N/A')}\n"
                    f"Expiry: {cert.get('notAfter', 'N/A')}"
                )
    except Exception as e:
        logger.error(f"SSL data unavailable for {domain}: {str(e)}")
        return f"SSL data unavailable: {str(e)}"

def get_virustotal_data(domain: str) -> str:
    """Fetch VirusTotal threat intelligence."""
    if not VIRUSTOTAL_API_KEY:
        return "Threat intelligence unavailable: VirusTotal API key not set."
    try:
        url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()['data']['attributes']
        return (
            f"VirusTotal Data for {domain}:\n"
            f"Reputation: {data.get('reputation', 'N/A')}\n"
            f"Last Analysis: {data.get('last_analysis_date', 'N/A')}\n"
            f"Categories: {', '.join(data.get('categories', {}).values())}"
        )
    except Exception as e:
        logger.error(f"Threat intelligence unavailable for {domain}: {str(e)}")
        return f"Threat intelligence unavailable: {str(e)}"

def get_traceroute(domain: str) -> str:
    """Perform traceroute to the domain's IP."""
    ip = get_ip(domain)
    if not ip:
        return f"Traceroute for {domain}: Unable to resolve IP."
    try:
        result = subprocess.run(['tracert', '-d', '-w', '1000', ip], capture_output=True, text=True, timeout=30)
        return f"Traceroute for {domain} (IP: {ip}):\n{result.stdout[:500]}"
    except Exception as e:
        logger.error(f"Traceroute unavailable for {domain}: {str(e)}")
        return f"Traceroute unavailable: {str(e)}"

def get_domain_status(domain: str) -> str:
    """Check if domain is active via HTTP/HTTPS."""
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{domain}"
            response = requests.get(url, timeout=15, allow_redirects=True)
            return f"Domain Status for {domain}: Active (HTTP {response.status_code})"
        except Exception:
            continue
    return f"Domain Status for {domain}: Inactive or unreachable"

def get_subdomains(domain: str) -> str:
    """Fetch subdomains using crt.sh."""
    if domain in subdomain_cache:
        return subdomain_cache[domain]
    try:
        response = requests.get(f'https://crt.sh/?q=%.{domain}&output=json', timeout=15)
        response.raise_for_status()
        subdomains = set(entry['name_value'].strip() for entry in response.json())
        result = f"Subdomains for {domain}:\n" + "\n".join(subdomains)[:500] if subdomains else "No subdomains found."
        subdomain_cache[domain] = result
        return result
    except Exception as e:
        logger.error(f"Subdomains unavailable for {domain}: {str(e)}")
        return f"Subdomains unavailable: {str(e)}"

def get_open_ports(domain: str) -> str:
    """Scan common ports."""
    ip = get_ip(domain)
    if not ip:
        return f"Open Ports for {domain}: Unable to resolve IP."
    ports = [21, 22, 80, 443, 8080]
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(str(port))
            sock.close()
        except Exception:
            continue
    return f"Open Ports for {domain}:\n" + ", ".join(open_ports) if open_ports else "No open ports found."

def get_reverse_ip_lookup(domain: str) -> str:
    """Find other domains on the same IP."""
    ip = get_ip(domain)
    if not ip:
        return f"Reverse IP Lookup for {domain}: Unable to resolve IP."
    try:
        response = requests.get(f'https://api.hackertarget.com/reverseiplookup/?q={ip}', timeout=15)
        response.raise_for_status()
        domains = response.text.splitlines()
        return f"Reverse IP Lookup for {domain} (IP: {ip}):\n" + "\n".join(domains)[:500] if domains else "No other domains found."
    except Exception as e:
        logger.error(f"Reverse IP Lookup unavailable for {domain}: {str(e)}")
        return f"Reverse IP Lookup unavailable: {str(e)}"
