"""
Host discovery module for the reconnaissance framework.
Identifies active web hosts from discovered subdomains.
"""

import logging
import subprocess
import os
import shutil
from datetime import datetime

logger = logging.getLogger(__name__)

def run(config, db_client):
    """
    Run the host discovery module.
    
    Args:
        config (dict): Configuration dictionary
        db_client (MongoClient): MongoDB client
        
    Returns:
        dict: Results of host discovery including new hosts found
    """
    logger.info("Starting host discovery module")
    
    # Get tool paths from config
    tools_config = config.get('tools', {})
    naabu_path = tools_config.get('naabu')
    
    # Try to find naabu if path is not valid
    if not naabu_path or not os.path.exists(naabu_path):
        logger.warning(f"Naabu not found at configured path: {naabu_path}")
        # Try to find naabu in PATH
        naabu_path = shutil.which('naabu')
        if naabu_path:
            logger.info(f"Found naabu in PATH: {naabu_path}")
        else:
            logger.warning("Naabu not found in PATH")
            return {'error': 'Naabu tool not available', 'new_hosts': []}
    
    # Initialize database
    db = db_client[config.get('mongodb', {}).get('database', 'recon_framework')]
    new_discovered_subdomains = db.new_discovered_subdomains
    new_hosts_discovered = db.new_hosts_discovered
    
    # Get recently discovered subdomains
    recent_subdomains = list(new_discovered_subdomains.find().sort("discovery_date", -1).limit(100))
    
    if not recent_subdomains:
        logger.info("No new subdomains found for host discovery")
        return {'new_hosts': []}
    
    logger.info(f"Found {len(recent_subdomains)} recent subdomains for host discovery")
    
    new_hosts = []
    
    # Process each subdomain
    for subdomain_record in recent_subdomains:
        subdomain = subdomain_record.get('subdomain')
        if not subdomain:
            continue
        
        logger.info(f"Scanning ports for {subdomain}")
        
        try:
            # Run naabu for port scanning (top 100 ports)
            naabu_output = subprocess.check_output(
                [naabu_path, '-host', subdomain, '-top-ports', '100', '-silent'],
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Process naabu output
            if naabu_output:
                open_ports = []
                for line in naabu_output.strip().split('\n'):
                    if line.strip():
                        parts = line.strip().split(':')
                        if len(parts) == 2:
                            host, port = parts
                            try:
                                port_num = int(port)
                                open_ports.append(port_num)
                            except ValueError:
                                logger.warning(f"Invalid port number: {port}")
                
                if open_ports:
                    logger.info(f"Found {len(open_ports)} open ports for {subdomain}: {open_ports}")
                    
                    # Store results in database
                    for port in open_ports:
                        # Check if host:port combination already exists
                        existing_host = new_hosts_discovered.find_one({
                            "subdomain": subdomain,
                            "port": port
                        })
                        
                        if not existing_host:
                            # Add new host to database
                            host_record = {
                                "subdomain": subdomain,
                                "port": port,
                                "discovery_date": datetime.now(),
                                "acunetix_scanned": False,
                                "nuclei_scanned": False
                            }
                            
                            new_hosts_discovered.insert_one(host_record)
                            new_hosts.append(f"{subdomain}:{port}")
                            logger.info(f"Added new host {subdomain}:{port} to database")
                        else:
                            logger.info(f"Host {subdomain}:{port} already exists in database")
                else:
                    logger.info(f"No open ports found for {subdomain}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running naabu for {subdomain}: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during port scanning for {subdomain}: {str(e)}")
    
    logger.info(f"Host discovery completed. Found {len(new_hosts)} new hosts.")
    return {
        'new_hosts': new_hosts
    }
