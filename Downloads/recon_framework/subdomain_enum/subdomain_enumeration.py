"""
Subdomain enumeration module for the reconnaissance framework.
Identifies subdomains for target domains using various tools.
"""

import os
import json
import logging
import subprocess
import tempfile
from datetime import datetime

logger = logging.getLogger(__name__)

def run(config, db_client):
    """
    Run the subdomain enumeration module.
    
    Args:
        config (dict): Configuration dictionary
        db_client (MongoClient): MongoDB client
        
    Returns:
        dict: Results of subdomain enumeration including new subdomains found
    """
    logger.info("Starting subdomain enumeration module")
    
    # Get target domains from config
    target_domains = config.get('targets', {}).get('domains', [])
    if not target_domains:
        logger.error("No target domains specified in configuration")
        return {'error': 'No target domains specified', 'new_subdomains': []}
    
    # Get tool paths from config
    tools_config = config.get('tools', {})
    subfinder_path = tools_config.get('subfinder')
    assetfinder_path = tools_config.get('assetfinder')
    
    # Verify tool existence
    if not os.path.exists(subfinder_path):
        logger.warning(f"Subfinder not found at {subfinder_path}")
        subfinder_path = None
    
    if not os.path.exists(assetfinder_path):
        logger.warning(f"Assetfinder not found at {assetfinder_path}")
        assetfinder_path = None
    
    if not subfinder_path and not assetfinder_path:
        logger.error("No subdomain enumeration tools available")
        return {'error': 'No subdomain enumeration tools available', 'new_subdomains': []}
    
    # Initialize database
    db = db_client[config.get('mongodb', {}).get('database', 'recon_framework')]
    subdomains_monitor = db.subdomains_monitor
    new_discovered_subdomains = db.new_discovered_subdomains
    
    all_new_subdomains = []
    
    # Process each target domain
    for domain in target_domains:
        logger.info(f"Enumerating subdomains for {domain}")
        
        # Create temporary file for storing results
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, f"{domain}_subdomains.json")
        
        # Initialize results dictionary
        results = {
            "subfinder_subdomains": [],
            "assetfinder_subdomains": []
        }
        
        # Run subfinder if available
        if subfinder_path:
            try:
                logger.info(f"Running subfinder for {domain}")
                subfinder_output = subprocess.check_output(
                    [subfinder_path, '-d', domain, '-silent'],
                    stderr=subprocess.STDOUT,
                    text=True
                )
                
                # Process subfinder output
                if subfinder_output:
                    results["subfinder_subdomains"] = [
                        subdomain.strip() for subdomain in subfinder_output.split('\n')
                        if subdomain.strip() and subdomain.strip().endswith(f".{domain}")
                    ]
                    logger.info(f"Subfinder found {len(results['subfinder_subdomains'])} subdomains for {domain}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Error running subfinder: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error with subfinder: {str(e)}")
        
        # Run assetfinder if available
        if assetfinder_path:
            try:
                logger.info(f"Running assetfinder for {domain}")
                assetfinder_output = subprocess.check_output(
                    [assetfinder_path, domain],
                    stderr=subprocess.STDOUT,
                    text=True
                )
                
                # Process assetfinder output
                if assetfinder_output:
                    results["assetfinder_subdomains"] = [
                        subdomain.strip() for subdomain in assetfinder_output.split('\n')
                        if subdomain.strip() and subdomain.strip().endswith(f".{domain}")
                    ]
                    logger.info(f"Assetfinder found {len(results['assetfinder_subdomains'])} subdomains for {domain}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Error running assetfinder: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error with assetfinder: {str(e)}")
        
        # Save results to temporary file
        with open(temp_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        logger.info(f"Saved subdomain enumeration results to {temp_file}")
        
        # Deduplicate subdomains
        all_subdomains = set()
        for tool, subdomains in results.items():
            all_subdomains.update(subdomains)
        
        logger.info(f"Found {len(all_subdomains)} unique subdomains for {domain}")
        
        # Check if domain exists in database
        domain_record = subdomains_monitor.find_one({"domain": domain})
        
        if domain_record:
            # Domain exists, check for new subdomains
            existing_subdomains = set(item["name"] for item in domain_record.get("subdomains", []))
            new_subdomains = all_subdomains - existing_subdomains
            
            if new_subdomains:
                logger.info(f"Found {len(new_subdomains)} new subdomains for {domain}")
                
                # Update subdomains_monitor collection
                new_subdomain_records = []
                for subdomain in new_subdomains:
                    # Determine source tool
                    source_tool = None
                    for tool, tool_subdomains in results.items():
                        if subdomain in tool_subdomains:
                            source_tool = tool.replace("_subdomains", "")
                            break
                    
                    subdomain_record = {
                        "name": subdomain,
                        "discovery_date": datetime.now(),
                        "source_tool": source_tool,
                        "last_seen_date": datetime.now()
                    }
                    new_subdomain_records.append(subdomain_record)
                
                # Update domain record with new subdomains
                subdomains_monitor.update_one(
                    {"domain": domain},
                    {"$push": {"subdomains": {"$each": new_subdomain_records}}}
                )
                
                # Add new subdomains to new_discovered_subdomains collection
                for subdomain in new_subdomains:
                    new_discovered_subdomains.insert_one({
                        "domain": domain,
                        "subdomain": subdomain,
                        "discovery_date": datetime.now()
                    })
                
                all_new_subdomains.extend(new_subdomains)
            else:
                logger.info(f"No new subdomains found for {domain}")
        else:
            # Domain doesn't exist, create new record
            logger.info(f"Creating new domain record for {domain}")
            
            subdomain_records = []
            for subdomain in all_subdomains:
                # Determine source tool
                source_tool = None
                for tool, tool_subdomains in results.items():
                    if subdomain in tool_subdomains:
                        source_tool = tool.replace("_subdomains", "")
                        break
                
                subdomain_record = {
                    "name": subdomain,
                    "discovery_date": datetime.now(),
                    "source_tool": source_tool,
                    "last_seen_date": datetime.now()
                }
                subdomain_records.append(subdomain_record)
            
            # Insert domain record
            subdomains_monitor.insert_one({
                "domain": domain,
                "bug_bounty_platform": None,  # Optional field
                "storage_date": datetime.now(),
                "subdomains": subdomain_records
            })
            
            # Add all subdomains to new_discovered_subdomains collection
            for subdomain in all_subdomains:
                new_discovered_subdomains.insert_one({
                    "domain": domain,
                    "subdomain": subdomain,
                    "discovery_date": datetime.now()
                })
            
            all_new_subdomains.extend(all_subdomains)
        
        # Clean up temporary file
        try:
            os.remove(temp_file)
            os.rmdir(temp_dir)
        except Exception as e:
            logger.warning(f"Failed to clean up temporary files: {str(e)}")
    
    logger.info(f"Subdomain enumeration completed. Found {len(all_new_subdomains)} new subdomains across all domains.")
    return {
        'new_subdomains': list(all_new_subdomains)
    }
