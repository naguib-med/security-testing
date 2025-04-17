#!/usr/bin/env python3
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
from modules.sql_injection import SQLInjectionScanner

# Site de test de vulnérabilités (exemple)
target = 'http://testphp.vulnweb.com/'  
scanner = SQLInjectionScanner(target)
vulnerabilities = scanner.scan()

print(f'Vulnérabilités d\'injection SQL trouvées: {len(vulnerabilities)}')
for vuln in vulnerabilities:
    print(f'- {vuln["description"]}')
    if 'payload' in vuln:
        print(f'  Payload: {vuln["payload"]}')