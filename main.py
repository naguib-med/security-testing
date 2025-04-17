#!/usr/bin/env python3
"""
Script principal pour l'automatisation des tests de sécurité.
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Importer les modules
from modules.port_scanner import PortScanner
from modules.xss_scanner import XSSScanner
from modules.sql_injection import SQLInjectionScanner
from modules.brute_force import BruteForceScanner
from modules.ssl_checker import SSLChecker

from utils.logger import setup_logger
from utils.reporter import Report
from config.settings import THREADS, REPORTS_DIR

def parse_arguments():
    """Analyse les arguments de ligne de commande."""
    parser = argparse.ArgumentParser(description='Outil d\'automatisation de tests de sécurité')
    parser.add_argument('-t', '--target', help='URL ou adresse IP cible')
    parser.add_argument('-c', '--config', default='config/targets.json', help='Fichier de configuration des cibles')
    parser.add_argument('-o', '--output', help='Fichier de sortie pour le rapport')
    parser.add_argument('-m', '--mode', choices=['all', 'web', 'network'], default='all', help='Mode de scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mode verbeux')
    
    # Arguments spécifiques aux modules
    parser.add_argument('--xss', action='store_true', help='Exécuter uniquement le scanner XSS')
    parser.add_argument('--sqli', action='store_true', help='Exécuter uniquement le scanner d\'injection SQL')
    parser.add_argument('--ports', action='store_true', help='Exécuter uniquement le scanner de ports')
    parser.add_argument('--ssl', action='store_true', help='Exécuter uniquement la vérification SSL')
    parser.add_argument('--brute', action='store_true', help='Exécuter uniquement les tests de force brute')
    
    return parser.parse_args()

def load_targets(config_file):
    """Charge les cibles depuis le fichier de configuration."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Erreur lors du chargement du fichier de configuration: {e}")
        sys.exit(1)

def scan_web_target(target, specific_modules=None):
    """Exécute les scans pour une cible web."""
    results = {"target": target["name"], "url": target["url"], "findings": []}
    
    # Déterminer quels modules exécuter
    modules_to_run = {}
    if specific_modules:
        for module in specific_modules:
            if module in target["scan_options"] and target["scan_options"][module]:
                modules_to_run[module] = True
    else:
        modules_to_run = target["scan_options"]
    
    # Exécuter les modules sélectionnés
    if modules_to_run.get("xss", False):
        logging.info(f"Exécution du scanner XSS sur {target['url']}")
        xss_scanner = XSSScanner(target["url"])
        xss_results = xss_scanner.scan()
        results["findings"].extend(xss_results)
    
    if modules_to_run.get("sqli", False):
        logging.info(f"Exécution du scanner d'injection SQL sur {target['url']}")
        sqli_scanner = SQLInjectionScanner(target["url"])
        sqli_results = sqli_scanner.scan()
        results["findings"].extend(sqli_results)
    
    if modules_to_run.get("ssl", False):
        logging.info(f"Vérification SSL sur {target['url']}")
        ssl_checker = SSLChecker(target["url"])
        ssl_results = ssl_checker.check()
        results["findings"].extend(ssl_results)
    
    if modules_to_run.get("brute_force", False):
        logging.info(f"Exécution des tests de force brute sur {target['url']}")
        bf_scanner = BruteForceScanner(target["url"])
        bf_results = bf_scanner.scan()
        results["findings"].extend(bf_results)
    
    return results

def scan_network_target(target, specific_modules=None):
    """Exécute les scans pour une cible réseau."""
    results = {"target": target["name"], "ip_range": target["ip_range"], "findings": []}
    
    # Déterminer quels modules exécuter
    modules_to_run = {}
    if specific_modules:
        for module in specific_modules:
            if module in target["scan_options"] and target["scan_options"][module]:
                modules_to_run[module] = True
    else:
        modules_to_run = target["scan_options"]
    
    # Exécuter les modules sélectionnés
    if modules_to_run.get("port_scan", False):
        logging.info(f"Exécution du scanner de ports sur {target['ip_range']}")
        port_scanner = PortScanner(target["ip_range"])
        port_results = port_scanner.scan()
        results["findings"].extend(port_results)
    
    return results

def main():
    """Fonction principale."""
    args = parse_arguments()
    
    # Configuration de la journalisation
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logger(log_level)
    
    # Créer le répertoire de rapports s'il n'existe pas
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Déterminer le fichier de sortie
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = args.output or os.path.join(REPORTS_DIR, f"security_report_{timestamp}.pdf")
    
    # Déterminer les modules spécifiques à exécuter
    specific_modules = []
    if args.xss:
        specific_modules.append("xss")
    if args.sqli:
        specific_modules.append("sqli")
    if args.ports:
        specific_modules.append("port_scan")
    if args.ssl:
        specific_modules.append("ssl")
    if args.brute:
        specific_modules.append("brute_force")
    
    # Si une cible spécifique est fournie, la scanner, sinon utiliser le fichier de configuration
    all_results = []
    
    if args.target:
        # Créer une cible ad-hoc
        if "://" in args.target:  # C'est une URL
            target = {
                "name": "Cible spécifiée",
                "url": args.target,
                "scan_options": {
                    "xss": args.xss or (not specific_modules),
                    "sqli": args.sqli or (not specific_modules),
                    "ssl": args.ssl or (not specific_modules),
                    "brute_force": args.brute or (not specific_modules)
                }
            }
            results = scan_web_target(target, specific_modules if specific_modules else None)
            all_results.append(results)
        else:  # C'est une adresse IP ou un réseau
            target = {
                "name": "Cible spécifiée",
                "ip_range": args.target,
                "scan_options": {
                    "port_scan": args.ports or (not specific_modules),
                    "service_detection": True
                }
            }
            results = scan_network_target(target, specific_modules if specific_modules else None)
            all_results.append(results)
    else:
        # Charger les cibles depuis le fichier de configuration
        targets = load_targets(args.config)
        
        # Scanner les cibles web si demandé
        if args.mode in ["all", "web"]:
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                futures = []
                for target in targets.get("web_targets", []):
                    futures.append(executor.submit(scan_web_target, target, specific_modules if specific_modules else None))
                
                for future in futures:
                    results = future.result()
                    all_results.append(results)
        
        # Scanner les cibles réseau si demandé
        if args.mode in ["all", "network"]:
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                futures = []
                for target in targets.get("network_targets", []):
                    futures.append(executor.submit(scan_network_target, target, specific_modules if specific_modules else None))
                
                for future in futures:
                    results = future.result()
                    all_results.append(results)
    
    # Générer le rapport
    logging.info(f"Génération du rapport dans {output_file}")
    report = Report(all_results)
    report.generate(output_file)
    
    logging.info("Scan terminé")

if __name__ == "__main__":
    main()