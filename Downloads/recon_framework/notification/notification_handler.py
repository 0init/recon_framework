"""
Notification module for the reconnaissance framework.
Delivers alerts and notifications based on scan results or other events.
"""

import logging
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from discord_webhook import DiscordWebhook, DiscordEmbed

logger = logging.getLogger(__name__)

def send_notifications(config, db_client, scan_results):
    """
    Send notifications based on scan results.
    
    Args:
        config (dict): Configuration dictionary
        db_client (MongoClient): MongoDB client
        scan_results (dict): Results from vulnerability scanning
        
    Returns:
        dict: Notification results
    """
    logger.info("Starting notification module")
    
    # Initialize database
    db = db_client[config.get('mongodb', {}).get('database', 'recon_framework')]
    notifications_collection = db.notifications
    
    # Get vulnerabilities from scan results
    vulnerabilities = scan_results.get('vulnerabilities', [])
    
    if not vulnerabilities:
        logger.info("No vulnerabilities to notify about")
        return {'notifications_sent': 0}
    
    logger.info(f"Processing {len(vulnerabilities)} vulnerabilities for notifications")
    
    # Group vulnerabilities by severity
    severity_groups = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'info').lower()
        if severity in severity_groups:
            severity_groups[severity].append(vuln)
        else:
            severity_groups['info'].append(vuln)
    
    # Prepare notifications
    notifications = []
    
    # Critical and high severity vulnerabilities get urgent notifications
    urgent_vulns = severity_groups['critical'] + severity_groups['high']
    if urgent_vulns:
        notification = {
            'message': f"URGENT: {len(urgent_vulns)} critical/high severity vulnerabilities detected",
            'severity': 'urgent',
            'date': datetime.now(),
            'vulnerabilities': urgent_vulns
        }
        notifications.append(notification)
    
    # Medium severity vulnerabilities
    if severity_groups['medium']:
        notification = {
            'message': f"{len(severity_groups['medium'])} medium severity vulnerabilities detected",
            'severity': 'medium',
            'date': datetime.now(),
            'vulnerabilities': severity_groups['medium']
        }
        notifications.append(notification)
    
    # Low and info severity vulnerabilities
    low_info_vulns = severity_groups['low'] + severity_groups['info']
    if low_info_vulns:
        notification = {
            'message': f"{len(low_info_vulns)} low/info severity vulnerabilities detected",
            'severity': 'low',
            'date': datetime.now(),
            'vulnerabilities': low_info_vulns
        }
        notifications.append(notification)
    
    # Store notifications in database
    for notification in notifications:
        notifications_collection.insert_one(notification)
    
    # Send notifications through appropriate channels
    notifications_sent = 0
    
    for notification in notifications:
        severity = notification.get('severity')
        
        # Send urgent notifications via email
        if severity == 'urgent':
            email_sent = send_email_notification(config, notification)
            if email_sent:
                notifications_sent += 1
        
        # Send all notifications to Discord
        discord_sent = send_discord_notification(config, notification)
        if discord_sent:
            notifications_sent += 1
    
    logger.info(f"Notification module completed. Sent {notifications_sent} notifications.")
    return {
        'notifications_sent': notifications_sent
    }

def send_email_notification(config, notification):
    """
    Send email notification for urgent alerts.
    
    Args:
        config (dict): Configuration dictionary
        notification (dict): Notification data
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    gmail_config = config.get('gmail', {})
    username = gmail_config.get('username')
    password = gmail_config.get('password')
    
    if not username or not password:
        logger.warning("Gmail credentials not configured")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = username
        msg['To'] = username  # Sending to self by default
        msg['Subject'] = notification.get('message', 'Security Alert')
        
        # Build email body
        body = f"Security Alert: {notification.get('message')}\n\n"
        body += f"Date: {notification.get('date')}\n"
        body += f"Severity: {notification.get('severity')}\n\n"
        body += "Vulnerabilities:\n"
        
        for i, vuln in enumerate(notification.get('vulnerabilities', []), 1):
            body += f"\n{i}. {vuln.get('vulnerability_type')} ({vuln.get('severity')})\n"
            body += f"   Host: {vuln.get('host')}\n"
            body += f"   Description: {vuln.get('description')}\n"
            body += f"   Source: {vuln.get('source')}\n"
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to Gmail
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(username, password)
        
        # Send email
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email notification sent to {username}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending email notification: {str(e)}")
        return False

def send_discord_notification(config, notification):
    """
    Send Discord notification.
    
    Args:
        config (dict): Configuration dictionary
        notification (dict): Notification data
        
    Returns:
        bool: True if notification was sent successfully, False otherwise
    """
    discord_config = config.get('discord', {})
    webhook_url = discord_config.get('webhook_url')
    
    if not webhook_url:
        logger.warning("Discord webhook URL not configured")
        return False
    
    try:
        # Create webhook
        webhook = DiscordWebhook(url=webhook_url)
        
        # Set color based on severity
        severity = notification.get('severity')
        if severity == 'urgent':
            color = 0xFF0000  # Red
        elif severity == 'medium':
            color = 0xFFA500  # Orange
        else:
            color = 0x00FF00  # Green
        
        # Create embed
        embed = DiscordEmbed(
            title=notification.get('message'),
            description=f"Severity: {severity}",
            color=color
        )
        
        embed.set_timestamp()
        
        # Add vulnerability details
        vulnerabilities = notification.get('vulnerabilities', [])
        
        # Limit to 10 vulnerabilities to avoid exceeding Discord limits
        for i, vuln in enumerate(vulnerabilities[:10], 1):
            embed.add_embed_field(
                name=f"{i}. {vuln.get('vulnerability_type')} ({vuln.get('severity')})",
                value=f"Host: {vuln.get('host')}\nDescription: {vuln.get('description')}\nSource: {vuln.get('source')}",
                inline=False
            )
        
        if len(vulnerabilities) > 10:
            embed.add_embed_field(
                name="Additional Vulnerabilities",
                value=f"Plus {len(vulnerabilities) - 10} more vulnerabilities not shown",
                inline=False
            )
        
        # Add embed to webhook
        webhook.add_embed(embed)
        
        # Send webhook
        webhook.execute()
        
        logger.info("Discord notification sent")
        return True
        
    except Exception as e:
        logger.error(f"Error sending Discord notification: {str(e)}")
        return False
