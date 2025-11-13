#!/usr/bin/env python3
"""
Web Interface for Smart Vulnerability Scanner v2.0
One-click automated scanning with real-time dashboard
"""

from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
import json
import threading
import queue
import time
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import VulnerabilityScanner

app = Flask(__name__)
CORS(app)

# Global state
scan_queue = queue.Queue()
active_scans = {}
scan_results = {}

class WebScanner:
    """Wrapper for scanner with web interface support"""

    def __init__(self, target, config, scan_id):
        self.target = target
        self.config = config
        self.scan_id = scan_id
        self.progress = []
        self.vulnerabilities = []
        self.status = "initializing"
        self.current_scanner = ""

    def log(self, message, level="info"):
        """Log a message with timestamp"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message,
            'scanner': self.current_scanner
        }
        self.progress.append(log_entry)

    def run_scan(self):
        """Run the vulnerability scan"""
        try:
            self.status = "running"
            self.log(f"Starting scan for {self.target}", "success")

            # Import scanner modules
            from modules.sql_injection import SQLInjectionScanner
            from modules.xss_scanner import XSSScanner
            from modules.ssrf_scanner import SSRFScanner
            from modules.open_redirect import OpenRedirectScanner
            from modules.header_injection import HeaderInjectionScanner
            from modules.info_disclosure import InfoDisclosureScanner

            # Create base scanner
            scanner = VulnerabilityScanner(self.target, self.config)

            # Initialize scanners
            scanners = [
                InfoDisclosureScanner(scanner),
                SQLInjectionScanner(scanner),
                XSSScanner(scanner),
                SSRFScanner(scanner),
                OpenRedirectScanner(scanner),
                HeaderInjectionScanner(scanner)
            ]

            total_scanners = len(scanners)

            # Run each scanner
            for idx, scan_module in enumerate(scanners, 1):
                self.current_scanner = scan_module.name
                self.log(f"Running {scan_module.name} ({idx}/{total_scanners})", "info")

                try:
                    results = scan_module.scan()
                    if results:
                        self.vulnerabilities.extend(results)
                        self.log(f"Found {len(results)} vulnerabilities", "warning")
                    else:
                        self.log(f"No vulnerabilities found", "success")
                except Exception as e:
                    self.log(f"Error in {scan_module.name}: {str(e)}", "error")

                # Update progress percentage
                self.status = f"scanning ({int(idx/total_scanners*100)}%)"

            # Scan complete
            self.status = "completed"
            self.log(f"Scan completed. Total vulnerabilities: {len(self.vulnerabilities)}", "success")

            # Save results
            scan_results[self.scan_id] = {
                'target': self.target,
                'scan_date': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities,
                'progress': self.progress,
                'status': self.status
            }

        except Exception as e:
            self.status = "error"
            self.log(f"Critical error: {str(e)}", "error")
            scan_results[self.scan_id] = {
                'error': str(e),
                'status': 'error'
            }

def scan_worker():
    """Background worker for processing scans"""
    while True:
        try:
            scan_id, web_scanner = scan_queue.get()
            active_scans[scan_id] = web_scanner
            web_scanner.run_scan()
            scan_queue.task_done()
        except Exception as e:
            print(f"Worker error: {e}")

# Start background worker
worker_thread = threading.Thread(target=scan_worker, daemon=True)
worker_thread.start()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.json
    target = data.get('target')

    if not target:
        return jsonify({'error': 'Target URL is required'}), 400

    # Generate scan ID
    scan_id = f"scan_{int(time.time())}_{hash(target) % 10000}"

    # Create scanner configuration
    config = {
        'scope': data.get('scope', 'bug-bounty'),
        'threads': data.get('threads', 5),
        'timeout': data.get('timeout', 10),
        'aggressive': data.get('aggressive', False),
        'user_agent': 'SecurityScanner/2.0 (Authorized Bug Bounty Testing)',
        'auto_mode': True  # Automated mode, skip confirmations
    }

    # Create web scanner
    web_scanner = WebScanner(target, config, scan_id)

    # Queue the scan
    scan_queue.put((scan_id, web_scanner))

    return jsonify({
        'scan_id': scan_id,
        'status': 'queued',
        'target': target
    })

@app.route('/api/scan/<scan_id>/status')
def scan_status(scan_id):
    """Get scan status and progress"""
    if scan_id in active_scans:
        scanner = active_scans[scan_id]
        return jsonify({
            'scan_id': scan_id,
            'status': scanner.status,
            'target': scanner.target,
            'progress': scanner.progress[-20:],  # Last 20 log entries
            'vulnerabilities_found': len(scanner.vulnerabilities),
            'current_scanner': scanner.current_scanner
        })
    elif scan_id in scan_results:
        return jsonify({
            'scan_id': scan_id,
            'status': 'completed',
            'results': scan_results[scan_id]
        })
    else:
        return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/scan/<scan_id>/results')
def scan_results_api(scan_id):
    """Get full scan results"""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    else:
        return jsonify({'error': 'Results not found'}), 404

@app.route('/api/scan/<scan_id>/stream')
def scan_stream(scan_id):
    """Server-Sent Events stream for real-time updates"""
    def generate():
        last_index = 0
        while True:
            if scan_id in active_scans:
                scanner = active_scans[scan_id]

                # Send new progress entries
                if len(scanner.progress) > last_index:
                    for entry in scanner.progress[last_index:]:
                        yield f"data: {json.dumps(entry)}\n\n"
                    last_index = len(scanner.progress)

                # Check if scan is complete
                if scanner.status in ['completed', 'error']:
                    yield f"data: {json.dumps({'status': scanner.status, 'done': True})}\n\n"
                    break

            time.sleep(0.5)

    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/scans')
def list_scans():
    """List all scans"""
    scans = []

    # Active scans
    for scan_id, scanner in active_scans.items():
        scans.append({
            'scan_id': scan_id,
            'target': scanner.target,
            'status': scanner.status,
            'vulnerabilities': len(scanner.vulnerabilities)
        })

    # Completed scans
    for scan_id, result in scan_results.items():
        if scan_id not in active_scans:
            scans.append({
                'scan_id': scan_id,
                'target': result.get('target', 'Unknown'),
                'status': result.get('status', 'completed'),
                'vulnerabilities': result.get('total_vulnerabilities', 0)
            })

    return jsonify({'scans': scans})

if __name__ == '__main__':
    print("\n" + "="*70)
    print("  Smart Vulnerability Scanner v2.0 - Web Interface")
    print("  Google-Level Scanner with One-Click Automation")
    print("="*70)
    print("\n🚀 Starting web server...")
    print("📱 Open your browser at: http://localhost:5000")
    print("🎯 Ready for automated scanning!\n")

    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
