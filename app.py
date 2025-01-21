# app.py
from flask import Flask, render_template, jsonify, request, Response
import requests
import time
from datetime import datetime, timedelta
import pandas as pd
import os
from dotenv import load_dotenv
import io
import csv
import logging
from flask_caching import Cache
from config import config

# Load environment variables
load_dotenv()

# Create Flask app with configuration
app = Flask(__name__)
env = os.getenv('FLASK_ENV', 'production')
app.config.from_object(config[env])

# Configure logging
logging.basicConfig(
    level=getattr(logging, app.config['LOG_LEVEL']),
    format=app.config['LOG_FORMAT'],
    datefmt=app.config['LOG_DATE_FORMAT']
)
logger = logging.getLogger(__name__)

# Configure Flask-Caching
cache = Cache(app)

class LookoutAPI:
    def __init__(self):
        self.base_url = "https://api.lookout.com"
        self.app_key = os.getenv("LOOKOUT_APP_KEY")
        self.access_token = None
        self.token_expires_at = None
        
    def get_token(self):
        """Get OAuth token from Lookout API"""
        url = f"{self.base_url}/oauth2/token"
        headers = {
            "Authorization": f"Bearer {self.app_key}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {"grant_type": "client_credentials"}
        
        logger.debug(f"Requesting token from {url}")
        response = requests.post(url, headers=headers, data=data)
        if response.ok:
            token_data = response.json()
            self.access_token = token_data["access_token"]
            self.token_expires_at = datetime.fromtimestamp(token_data["expires_at"] / 1000)
            logger.debug("Successfully obtained access token")
            return self.access_token
        logger.error(f"Failed to get token: {response.text}")
        raise Exception(f"Failed to get token: {response.text}")

    def is_token_valid(self):
        """Check if current token is valid"""
        if not self.access_token or not self.token_expires_at:
            return False
        # Add 5 minute buffer before expiration
        return datetime.now() < (self.token_expires_at - timedelta(minutes=5))

    def api_request(self, endpoint, params=None, paginate=True):
        """Make authenticated request to Lookout API"""
        if not self.is_token_valid():
            self.get_token()
            
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        
        # Create a new params dict to avoid modifying the original
        request_params = params.copy() if params else {}
        
        logger.debug(f"Making request to {endpoint} with params: {request_params}")
        
        # Handle pagination
        if paginate and endpoint in ["/mra/api/v2/devices", "/mra/api/v2/threats", "/mra/api/v2/pcp-threats"]:
            all_results = []
            total_count = 0
            request_params["limit"] = 1000  # Maximum allowed by API
            
            while True:
                try:
                    response = requests.get(
                        f"{self.base_url}{endpoint}",
                        headers=headers,
                        params=request_params
                    )
                    
                    if response.status_code == 429:
                        # Handle rate limiting
                        retry_after = int(response.headers.get('Retry-After', 60))
                        logger.warning(f"Rate limit hit, waiting {retry_after} seconds")
                        time.sleep(retry_after)
                        continue
                        
                    response.raise_for_status()
                    data = response.json()
                    logger.debug(f"Response data: {data}")
                    
                    # Get the appropriate key based on endpoint
                    items_key = "devices" if "devices" in endpoint else "threats"
                    items = data.get(items_key, [])
                    
                    if not items:
                        break
                        
                    all_results.extend(items)
                    total_count = data.get("count", 0)
                    logger.debug(f"Retrieved {len(items)} items, total count: {total_count}")
                    
                    # Update oid for next page
                    if len(items) < request_params["limit"]:
                        break
                    request_params["oid"] = items[-1]["oid"]
                    
                except requests.exceptions.RequestException as e:
                    if response.status_code == 401:
                        logger.warning("Token expired, refreshing...")
                        self.get_token()
                        headers["Authorization"] = f"Bearer {self.access_token}"
                        continue
                    logger.error(f"API request failed: {str(e)}")
                    raise Exception(f"API request failed: {str(e)}")
                    
            return {"count": total_count, items_key: all_results}
        
        # Non-paginated request
        try:
            response = requests.get(
                f"{self.base_url}{endpoint}",
                headers=headers,
                params=request_params
            )
            
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limit hit, waiting {retry_after} seconds")
                time.sleep(retry_after)
                return self.api_request(endpoint, params, paginate)
                
            response.raise_for_status()
            data = response.json()
            logger.debug(f"Response data: {data}")
            return data
            
        except requests.exceptions.RequestException as e:
            if response.status_code == 401:
                logger.warning("Token expired, refreshing...")
                self.get_token()
                return self.api_request(endpoint, params, paginate)
            logger.error(f"API request failed: {str(e)}")
            raise Exception(f"API request failed: {str(e)}")

    def get_security_report(self, timeframe="LAST_30_DAYS"):
        """Gather all security metrics"""
        report = {}
        
        try:
            # Get enrolled devices (total devices with ACTIVATED state)
            logger.info("Fetching enrolled devices...")
            # Get all enrolled devices with platform info
            devices = self.api_request("/mra/api/v2/devices", {
                "state": "ACTIVATED"
            })
            
            # Count devices by platform
            ios_devices = 0
            android_devices = 0
            for device in devices.get("devices", []):
                platform = device.get("platform", "").upper()
                if platform == "IOS":
                    ios_devices += 1
                elif platform == "ANDROID":
                    android_devices += 1
            
            report["total_devices"] = devices["count"]
            report["ios_devices"] = ios_devices
            report["android_devices"] = android_devices
            logger.info(f"Total enrolled devices: {report['total_devices']} (iOS: {ios_devices}, Android: {android_devices})")
            
            # Get devices missing updates
            logger.info("Fetching devices with OS updates...")
            outdated_os = self.api_request("/mra/api/v2/threats", {
                "threat_type": "OS",
                "classification": "OUT_OF_DATE_OS",
                "timeframe": timeframe,
                "status": "OPEN"
            })
            
            logger.info("Fetching devices with security patch updates...")
            outdated_aspl = self.api_request("/mra/api/v2/threats", {
                "threat_type": "OS",
                "classification": "OUT_OF_DATE_ASPL",
                "timeframe": timeframe,
                "status": "OPEN"
            })
            
            # Count unique devices needing updates
            unique_outdated_devices = set()
            for threat in outdated_os.get("threats", []):
                unique_outdated_devices.add(threat.get("device_guid"))
            for threat in outdated_aspl.get("threats", []):
                unique_outdated_devices.add(threat.get("device_guid"))
                
            report["missed_updates"] = len(unique_outdated_devices)
            report["updated_devices"] = report["total_devices"] - report["missed_updates"]
            logger.info(f"Devices needing updates: {report['missed_updates']}")
            
            # Get web content threats by classification
            logger.info("Fetching web content threats...")
            web_classifications = {
                "malicious": "MALICIOUS_CONTENT",
                "unauthorized": "UNAUTHORIZED_CONTENT",
                "phishing": "PHISHING_CONTENT",
                "denylisted": "DENYLISTED_CONTENT"
            }
            
            web_threats = {}
            all_web_threats = []
            
            for key, classification in web_classifications.items():
                response = self.api_request("/mra/api/v2/pcp-threats", {
                    "timeframe": timeframe,
                    "classification": classification
                })
                web_threats[key] = response.get("count", 0)
                all_web_threats.extend(response.get("threats", []))
            
            report["web_threats"] = {
                "total": sum(web_threats.values()),
                "malicious": web_threats["malicious"],
                "unauthorized": web_threats["unauthorized"],
                "phishing": web_threats["phishing"],
                "denylisted": web_threats["denylisted"]
            }
            
            logger.info(f"Total web threats: {report['web_threats']['total']}")
            
            # Get blocked downloads
            logger.info("Fetching blocked downloads...")
            downloads = self.api_request("/mra/api/v2/threats", {
                "timeframe": timeframe,
                "classification": "SIDELOADED_APP",
                "status": "OPEN"
            })
            denylisted_apps = self.api_request("/mra/api/v2/threats", {
                "timeframe": timeframe,
                "classification": "DENYLISTED_APP",
                "status": "OPEN"
            })
            non_store_apps = self.api_request("/mra/api/v2/threats", {
                "timeframe": timeframe,
                "classification": "NON_APP_STORE_SIGNER",
                "status": "OPEN"
            })
            
            report["unauthorized_apps"] = (
                downloads.get("count", 0) +
                denylisted_apps.get("count", 0) +
                non_store_apps.get("count", 0)
            )
            logger.info(f"Total unauthorized apps detected: {report['unauthorized_apps']}")
            
            # Get all malware threats
            logger.info("Fetching malware threats...")
            malware_classifications = [
                "TROJAN", "WORM", "SPYWARE", "BACKDOOR", "BOT",
                "SURVEILLANCEWARE", "ROOT_ENABLER", "EXPLOIT"
            ]
            
            malware_threats = []
            for classification in malware_classifications:
                threat = self.api_request("/mra/api/v2/threats", {
                    "timeframe": timeframe,
                    "classification": classification,
                    "status": "OPEN"
                })
                malware_threats.append(threat.get("count", 0))
            
            report["malware_detected"] = sum(malware_threats)
            logger.info(f"Total malware threats detected: {report['malware_detected']}")

            # Get potentially unwanted applications
            logger.info("Fetching PUA threats...")
            pua_classifications = [
                "RISKWARE", "ADWARE", "CHARGEWARE", "APP_DROPPER",
                "CLICK_FRAUD", "SPAM", "TOLL_FRAUD"
            ]
            
            pua_threats = []
            for classification in pua_classifications:
                threat = self.api_request("/mra/api/v2/threats", {
                    "timeframe": timeframe,
                    "classification": classification,
                    "status": "OPEN"
                })
                pua_threats.append(threat.get("count", 0))
            
            report["pua_detected"] = sum(pua_threats)
            logger.info(f"Total PUA threats detected: {report['pua_detected']}")

            # Get system vulnerabilities
            logger.info("Fetching system vulnerabilities...")
            vuln_classifications = [
                "VULNERABILITY", "ROOT_JAILBREAK", "ACCESS_CONTROL_VIOLATION",
                "NO_DEVICE_LOCK", "DEVELOPER_MODE_ENABLED", "USB_DEBUGGING_ENABLED",
                "UNKNOWN_SOURCES_ENABLED", "UNENCRYPTED"
            ]
            
            vuln_threats = []
            for classification in vuln_classifications:
                threat = self.api_request("/mra/api/v2/threats", {
                    "timeframe": timeframe,
                    "classification": classification,
                    "status": "OPEN"
                })
                vuln_threats.append(threat.get("count", 0))
            
            report["vulnerabilities_detected"] = sum(vuln_threats)
            logger.info(f"Total vulnerabilities detected: {report['vulnerabilities_detected']}")

            # Get network threats
            logger.info("Fetching network threats...")
            network_classifications = [
                "CONNECTIVITY", "ACTIVE_MITM", "ROGUE_WIFI", "VPN_NOT_ENABLED",
                "GATEWAY_ADDRESS_CHANGE", "PORT_SCAN", "SECURE_DNS_NOT_ENABLED"
            ]
            
            network_threats = []
            for classification in network_classifications:
                threat = self.api_request("/mra/api/v2/threats", {
                    "timeframe": timeframe,
                    "classification": classification,
                    "status": "OPEN"
                })
                network_threats.append(threat.get("count", 0))
            
            report["network_threats"] = sum(network_threats)
            logger.info(f"Total network threats detected: {report['network_threats']}")
            
            # Get phishing attacks
            logger.info("Fetching phishing attempts...")
            phishing = self.api_request("/mra/api/v2/pcp-threats", {
                "timeframe": timeframe,
                "classification": "PHISHING_CONTENT"
            })
            report["phishing_attempts"] = phishing.get("count", 0)
            logger.info(f"Total phishing attempts: {report['phishing_attempts']}")
            
            # Process top blocked websites
            blocked_sites = []
            for threat in all_web_threats:
                details = threat.get("details", {})
                if details.get("url"):
                    blocked_sites.append({
                        "url": details["url"],
                        "category": threat.get("classification", "UNKNOWN"),
                        "timestamp": threat.get("detected_at"),
                        "action": details.get("response", "BLOCKED"),
                        "risk": threat.get("risk", "UNKNOWN")
                    })
            
            df = pd.DataFrame(blocked_sites)
            if not df.empty:
                top_sites = df.groupby("url").agg({
                    'category': 'first',
                    'risk': 'first',
                    'timestamp': 'max',
                    'url': 'count'
                }).rename(columns={'url': 'count'}).sort_values('count', ascending=False).head(10)
                
                report["top_blocked_sites"] = [
                    {
                        "url": url,
                        "count": int(row['count']),
                        "category": row['category'],
                        "risk": row['risk'],
                        "last_seen": row['timestamp']
                    }
                    for url, row in top_sites.iterrows()
                ]
            else:
                report["top_blocked_sites"] = []
                
            logger.info("Report generation completed successfully")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate report: {str(e)}")
            raise Exception(f"Failed to generate report: {str(e)}")

    def get_report_csv(self, timeframe="LAST_30_DAYS"):
        """Generate CSV report of security metrics"""
        report = self.get_security_report(timeframe)
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Lookout Security Report'])
        writer.writerow([f'Time Range: {timeframe.replace("_", " ").title()}'])
        writer.writerow([f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'])
        writer.writerow([])
        
        # Write summary metrics
        writer.writerow(['Summary Metrics'])
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Total Enrolled Devices', report['total_devices']])
        writer.writerow(['iOS Devices', report['ios_devices']])
        writer.writerow(['Android Devices', report['android_devices']])
        writer.writerow(['Devices Up to Date', report['updated_devices']])
        writer.writerow(['Devices Needing Updates', report['missed_updates']])
        writer.writerow(['Websites Blocked', report['web_threats']['total']])
        writer.writerow(['Unauthorized Apps Detected', report['unauthorized_apps']])
        writer.writerow(['Malware Detected', report['malware_detected']])
        writer.writerow(['Phishing Attempts', report['phishing_attempts']])
        writer.writerow([])
        
        # Write blocked websites
        writer.writerow(['Top Blocked Websites'])
        writer.writerow(['URL', 'Category', 'Risk Level', 'Block Count', 'Last Seen'])
        for site in report['top_blocked_sites']:
            writer.writerow([
                site['url'],
                site['category'],
                site['risk'],
                site['count'],
                site['last_seen']
            ])
            
        return output.getvalue()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/report')
def get_report():
    timeframe = request.args.get('timeframe', 'LAST_30_DAYS')
    # Validate timeframe parameter
    valid_timeframes = ["ALL", "LAST_30_DAYS", "LAST_60_DAYS", "LAST_90_DAYS", "LAST_6_MONTHS"]
    if timeframe not in valid_timeframes:
        return jsonify({"error": "Invalid timeframe parameter"}), 400
    
    try:
        # Try to get cached report and timestamp
        cached_data = cache.get(f'report_{timeframe}')
        if cached_data:
            logger.debug(f"Returning cached report for timeframe: {timeframe}")
            return jsonify({
                **cached_data,
                'cache_timestamp': datetime.now().isoformat(),
                'is_cached': True
            })
            
        # Generate new report if not cached
        api = LookoutAPI()
        report = api.get_security_report(timeframe)
        
        # Cache the report
        cache.set(f'report_{timeframe}', report)
        logger.debug(f"Cached new report for timeframe: {timeframe}")
        
        return jsonify({
            **report,
            'cache_timestamp': datetime.now().isoformat(),
            'is_cached': False
        })
    except Exception as e:
        logger.error(f"Error in get_report: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/report/export')
def export_report():
    timeframe = request.args.get('timeframe', 'LAST_30_DAYS')
    # Validate timeframe parameter
    valid_timeframes = ["ALL", "LAST_30_DAYS", "LAST_60_DAYS", "LAST_90_DAYS", "LAST_6_MONTHS"]
    if timeframe not in valid_timeframes:
        return jsonify({"error": "Invalid timeframe parameter"}), 400
    
    try:
        # Try to get cached CSV
        cached_csv = cache.get(f'csv_report_{timeframe}')
        if cached_csv:
            logger.debug(f"Returning cached CSV report for timeframe: {timeframe}")
            return Response(
                cached_csv,
                mimetype='text/csv',
                headers={
                    'Content-Disposition': f'attachment; filename=lookout_security_report_{timeframe.lower()}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                }
            )
            
        # Generate new CSV if not cached
        api = LookoutAPI()
        csv_content = api.get_report_csv(timeframe)
        
        # Cache the CSV content
        cache.set(f'csv_report_{timeframe}', csv_content)
        logger.debug(f"Cached new CSV report for timeframe: {timeframe}")
        
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=lookout_security_report_{timeframe.lower()}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )
    except Exception as e:
        logger.error(f"Error in export_report: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)