from flask import Flask, render_template, request, jsonify, send_file
import subprocess
import json
import threading
import time
import requests
import socket
import re
from urllib.parse import urlparse
import sqlite3
from datetime import datetime
import os
import platform
import ipaddress
from ai_analyzer import AIAnalyzer, add_ai_routes

app = Flask(__name__)

class OSINTScanner:
    def __init__(self):
        self.results = {}
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect('osint_results.db')
        cursor = conn.cursor()
        
        # 프로젝트 테이블 생성
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                color TEXT DEFAULT '#4fd1c7',
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # 스캔 결과 테이블에 프로젝트 ID 컬럼 추가
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                domain TEXT,
                subdomain TEXT,
                ip_address TEXT,
                ports TEXT,
                services TEXT,
                vulnerabilities TEXT,
                poc_codes TEXT,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects (id)
            )
        ''')
        
        # 기본 프로젝트 생성
        cursor.execute('SELECT COUNT(*) FROM projects')
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT INTO projects (name, description, color) 
                VALUES (?, ?, ?)
            ''', ('기본 프로젝트', 'OSINT 스캔 결과를 저장하는 기본 프로젝트입니다.', '#4fd1c7'))
        
        conn.commit()
        conn.close()
    
    def save_results(self, domain, results, project_id=None):
        conn = sqlite3.connect('osint_results.db')
        cursor = conn.cursor()
        
        # 프로젝트 ID가 없으면 기본 프로젝트 사용
        if project_id is None:
            cursor.execute('SELECT id FROM projects WHERE name = ? LIMIT 1', ('기본 프로젝트',))
            result = cursor.fetchone()
            project_id = result[0] if result else 1
        
        for subdomain, data in results.items():
            cursor.execute('''
                INSERT INTO scan_results 
                (project_id, domain, subdomain, ip_address, ports, services, vulnerabilities, poc_codes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                project_id,
                domain,
                subdomain,
                data.get('ip', ''),
                json.dumps(data.get('ports', [])),
                json.dumps(data.get('services', [])),
                json.dumps(data.get('cves', [])),
                json.dumps(data.get('poc_codes', []))
            ))
        
        # 프로젝트 업데이트 날짜 갱신
        cursor.execute('''
            UPDATE projects SET updated_date = CURRENT_TIMESTAMP WHERE id = ?
        ''', (project_id,))
        
        conn.commit()
        conn.close()

scanner = OSINTScanner()

@app.route('/')
def index():
    return render_template('index.html')

def is_valid_ip(ip):
    """IP 주소 유효성 검사"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            # 빈 문자열이나 앞에 0이 있는 경우(예: 001) 제외
            if not part or (len(part) > 1 and part[0] == '0'):
                return False
            num = int(part)
            if not (0 <= num <= 255):
                return False
        return True
    except:
        return False

def is_valid_domain(domain):
    """도메인 이름 유효성 검사"""
    import re
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(pattern, domain) is not None

# 프로젝트 관리 API 엔드포인트들
@app.route('/projects', methods=['GET'])
def get_projects():
    conn = sqlite3.connect('osint_results.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT p.*, COUNT(sr.id) as scan_count 
        FROM projects p 
        LEFT JOIN scan_results sr ON p.id = sr.project_id 
        GROUP BY p.id 
        ORDER BY p.updated_date DESC
    ''')
    projects = []
    for row in cursor.fetchall():
        projects.append({
            'id': row[0],
            'name': row[1],
            'description': row[2],
            'created_date': row[3],
            'updated_date': row[4],
            'color': row[5],
            'status': row[6],
            'scan_count': row[7]
        })
    conn.close()
    return jsonify(projects)

@app.route('/projects', methods=['POST'])
def create_project():
    data = request.json
    name = data.get('name')
    description = data.get('description', '')
    color = data.get('color', '#4fd1c7')
    
    if not name:
        return jsonify({'error': 'Project name is required'}), 400
    
    conn = sqlite3.connect('osint_results.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO projects (name, description, color) 
        VALUES (?, ?, ?)
    ''', (name, description, color))
    project_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({'id': project_id, 'name': name, 'description': description, 'color': color})

@app.route('/projects/<int:project_id>', methods=['PUT'])
def update_project(project_id):
    data = request.json
    name = data.get('name')
    description = data.get('description')
    color = data.get('color')
    status = data.get('status')
    
    conn = sqlite3.connect('osint_results.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE projects 
        SET name = COALESCE(?, name), 
            description = COALESCE(?, description), 
            color = COALESCE(?, color),
            status = COALESCE(?, status),
            updated_date = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (name, description, color, status, project_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/projects/<int:project_id>', methods=['DELETE'])
def delete_project(project_id):
    conn = sqlite3.connect('osint_results.db')
    cursor = conn.cursor()
    
    # 기본 프로젝트는 삭제할 수 없음
    cursor.execute('SELECT name FROM projects WHERE id = ?', (project_id,))
    result = cursor.fetchone()
    if result and result[0] == '기본 프로젝트':
        conn.close()
        return jsonify({'error': 'Cannot delete default project'}), 400
    
    # 프로젝트와 관련된 스캔 결과도 함께 삭제
    cursor.execute('DELETE FROM scan_results WHERE project_id = ?', (project_id,))
    cursor.execute('DELETE FROM projects WHERE id = ?', (project_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/projects/<int:project_id>/scans', methods=['GET'])
def get_project_scans(project_id):
    conn = sqlite3.connect('osint_results.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM scan_results 
        WHERE project_id = ? 
        ORDER BY scan_date DESC
    ''', (project_id,))
    
    scans = []
    for row in cursor.fetchall():
        scans.append({
            'id': row[0],
            'domain': row[2],
            'subdomain': row[3],
            'ip_address': row[4],
            'ports': json.loads(row[5]) if row[5] else [],
            'services': json.loads(row[6]) if row[6] else [],
            'vulnerabilities': json.loads(row[7]) if row[7] else [],
            'poc_codes': json.loads(row[8]) if row[8] else [],
            'scan_date': row[9]
        })
    
    conn.close()
    return jsonify(scans)

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    targets = data.get('targets')  # 단일 또는 복수 타겟
    project_id = data.get('project_id')  # 프로젝트 ID
    bulk_mode = data.get('bulk_mode', False)  # 대량 스캔 모드
    
    # 하위 호환성을 위해 기존 'domain' 필드도 지원
    if not targets and data.get('domain'):
        targets = [data.get('domain')]
    
    if not targets or (isinstance(targets, list) and len(targets) == 0):
        return jsonify({'error': 'At least one target is required'}), 400
    
    # 단일 타겟인 경우 리스트로 변환
    if isinstance(targets, str):
        targets = [targets]
    
    # 타겟 유효성 검사
    valid_targets = []
    invalid_targets = []
    
    for target in targets:
        target = target.strip()
        if not target:
            continue
            
        if is_valid_ip(target) or is_valid_domain(target):
            valid_targets.append(target)
        else:
            invalid_targets.append(target)
    
    if len(valid_targets) == 0:
        return jsonify({'error': 'No valid targets found'}), 400
    
    scan_id = f"scan_{int(time.time())}"
    scanner.results[scan_id] = {
        'status': 'started', 
        'progress': 0, 
        'results': {},
        'targets': valid_targets,
        'invalid_targets': invalid_targets,
        'bulk_mode': bulk_mode,
        'project_id': project_id,
        'completed_count': 0,
        'total_count': len(valid_targets)
    }
    
    thread = threading.Thread(target=perform_bulk_scan if bulk_mode else perform_single_scan, 
                            args=(scan_id, valid_targets, project_id))
    thread.daemon = True
    thread.start()
    
    result = {
        'scan_id': scan_id, 
        'status': 'started',
        'total_targets': len(valid_targets),
        'valid_targets': len(valid_targets)
    }
    
    if invalid_targets:
        result['invalid_targets'] = invalid_targets
        result['invalid_count'] = len(invalid_targets)
    
    return jsonify(result)

@app.route('/scan/<scan_id>/status')
def scan_status(scan_id):
    if scan_id not in scanner.results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scanner.results[scan_id])

@app.route('/scan/<scan_id>/results')
def scan_results(scan_id):
    if scan_id not in scanner.results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scanner.results[scan_id]['results'])

def perform_single_scan(scan_id, targets, project_id=None):
    """단일 타겟 스캔 (기존 로직 유지)"""
    target = targets[0]  # 첫 번째 타겟만 사용
    target_type = 'ip' if is_valid_ip(target) else 'domain'
    
    try:
        scanner.results[scan_id]['status'] = 'running'
        scanner.results[scan_id]['progress'] = 10
        
        if target_type == 'ip':
            hosts_to_scan = [target]
            scanner.results[scan_id]['progress'] = 30
        else:
            hosts_to_scan = discover_subdomains(target)
            scanner.results[scan_id]['progress'] = 30
        
        for i, host in enumerate(hosts_to_scan):
            host_results = scan_host(host)
            scanner.results[scan_id]['results'][host] = host_results
            scanner.results[scan_id]['progress'] = 30 + (i + 1) * 60 / len(hosts_to_scan)
        
        scanner.save_results(target, scanner.results[scan_id]['results'], project_id)
        scanner.results[scan_id]['status'] = 'completed'
        scanner.results[scan_id]['progress'] = 100
        scanner.results[scan_id]['completed_count'] = 1
        
    except Exception as e:
        scanner.results[scan_id]['status'] = 'error'
        scanner.results[scan_id]['error'] = str(e)

def perform_bulk_scan(scan_id, targets, project_id=None):
    """대량 타겟 스캔"""
    try:
        scanner.results[scan_id]['status'] = 'running'
        scanner.results[scan_id]['progress'] = 5
        scanner.results[scan_id]['target_status'] = {}
        
        total_targets = len(targets)
        completed_count = 0
        
        # 각 타겟별 상태 초기화
        for target in targets:
            scanner.results[scan_id]['target_status'][target] = {
                'status': 'pending',
                'progress': 0,
                'error': None
            }
        
        # 각 타겟을 순차적으로 스캔
        for i, target in enumerate(targets):
            try:
                # 타겟 스캔 시작
                scanner.results[scan_id]['target_status'][target]['status'] = 'running'
                scanner.results[scan_id]['target_status'][target]['progress'] = 10
                
                target_type = 'ip' if is_valid_ip(target) else 'domain'
                
                if target_type == 'ip':
                    hosts_to_scan = [target]
                else:
                    hosts_to_scan = discover_subdomains(target)
                
                scanner.results[scan_id]['target_status'][target]['progress'] = 30
                
                # 호스트별 스캔
                target_results = {}
                for j, host in enumerate(hosts_to_scan):
                    host_results = scan_host(host)
                    target_results[host] = host_results
                    
                    # 개별 타겟 진행률 업데이트
                    host_progress = 30 + (j + 1) * 60 / len(hosts_to_scan)
                    scanner.results[scan_id]['target_status'][target]['progress'] = host_progress
                
                # 타겟 결과 저장
                scanner.results[scan_id]['results'][target] = target_results
                scanner.save_results(target, target_results, project_id)
                
                # 타겟 완료 처리
                scanner.results[scan_id]['target_status'][target]['status'] = 'completed'
                scanner.results[scan_id]['target_status'][target]['progress'] = 100
                completed_count += 1
                
            except Exception as target_error:
                # 개별 타겟 오류 처리
                scanner.results[scan_id]['target_status'][target]['status'] = 'error'
                scanner.results[scan_id]['target_status'][target]['error'] = str(target_error)
                completed_count += 1
            
            # 전체 진행률 업데이트
            scanner.results[scan_id]['completed_count'] = completed_count
            scanner.results[scan_id]['progress'] = 5 + (completed_count * 90 / total_targets)
        
        # 전체 스캔 완료
        scanner.results[scan_id]['status'] = 'completed'
        scanner.results[scan_id]['progress'] = 100
        
    except Exception as e:
        scanner.results[scan_id]['status'] = 'error'
        scanner.results[scan_id]['error'] = str(e)

# 기존 perform_scan 함수는 하위 호환성을 위해 유지
def perform_scan(scan_id, target, target_type, project_id=None):
    perform_single_scan(scan_id, [target], project_id)

def discover_subdomains(domain):
    subdomains = set([domain])
    
    # Subfinder를 사용한 서브도메인 탐색 (설치되어 있다면)
    try:
        result = subprocess.run(['subfinder', '-d', domain, '-silent'], 
                              capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line:
                    subdomains.add(line.strip())
    except:
        pass
    
    # 기본 서브도메인 목록으로 브루트포스
    common_subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop']
    for sub in common_subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            subdomains.add(full_domain)
        except:
            pass
    
    return list(subdomains)

def parse_linux_route_legacy(stdout):
    raise NotImplementedError

def get_network_routing_info():
    """네트워크 라우팅 정보 수집"""
    routing_info = {
        'interfaces': [],
        'routes': [],
        'default_gateway': None,
        'network_segments': []
    }
    
    try:
        # Windows와 Linux/macOS에 따라 다른 명령어 사용
        if platform.system() == 'Windows':
            # Windows route print 명령 사용
            result = subprocess.run(['route', 'print'], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                routing_info = parse_windows_route_print(result.stdout)
        else:
            # Linux/macOS ip route 또는 route 명령 사용
            try:
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    routing_info = parse_linux_route(result.stdout)
            except:
                # ip 명령이 없으면 route 명령 시도
                result = subprocess.run(['route', '-n'], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    routing_info = parse_linux_route_legacy(result.stdout)
                    
    except Exception as e:
        print(f"라우팅 정보 수집 오류: {e}")
    
    return routing_info

def parse_windows_route_print(output):
    """Windows route print 출력 파싱"""
    routing_info = {
        'interfaces': [],
        'routes': [],
        'default_gateway': None,
        'network_segments': []
    }
    
    lines = output.split('\n')
    current_section = None
    
    for line in lines:
        line = line.strip()
        
        # 섹션 구분
        if '인터페이스 목록' in line or 'Interface List' in line:
            current_section = 'interfaces'
            continue
        elif 'IPv4 경로 테이블' in line or 'IPv4 Route Table' in line:
            current_section = 'routes'
            continue
        elif '영구 경로' in line or 'Persistent Routes' in line:
            current_section = 'persistent'
            continue
        elif line.startswith('==='):
            continue
            
        # 인터페이스 정보 파싱
        if current_section == 'interfaces' and line and not line.startswith('='):
            # 형식: 23...18 93 41 d4 30 f5 ......Intel(R) Wi-Fi 6E AX211 160MHz
            if '...' in line:
                parts = line.split('......')
                if len(parts) >= 2:
                    interface_id = parts[0].split('...')[0].strip()
                    mac_address = parts[0].split('...')[1].strip() if '...' in parts[0] else ''
                    interface_name = parts[1].strip()
                    
                    routing_info['interfaces'].append({
                        'id': interface_id,
                        'name': interface_name,
                        'mac': mac_address
                    })
        
        # 라우팅 테이블 파싱
        elif current_section == 'routes' and line and not line.startswith('=') and not '네트워크' in line:
            # 공백으로 분리된 라우팅 항목 파싱
            parts = line.split()
            if len(parts) >= 5:
                try:
                    network = parts[0]
                    netmask = parts[1]
                    gateway = parts[2]
                    interface = parts[3]
                    metric = parts[4] if len(parts) > 4 else '0'
                    
                    route_entry = {
                        'network': network,
                        'netmask': netmask,
                        'gateway': gateway,
                        'interface': interface,
                        'metric': metric
                    }
                    
                    routing_info['routes'].append(route_entry)
                    
                    # 기본 게이트웨이 찾기 (0.0.0.0 네트워크)
                    if network == '0.0.0.0' and netmask == '0.0.0.0':
                        routing_info['default_gateway'] = gateway
                    
                    # 네트워크 세그먼트 수집
                    if network != '0.0.0.0' and not network.startswith('127.') and not network.startswith('224.'):
                        try:
                            network_obj = ipaddress.IPv4Network(f"{network}/{netmask}", strict=False)
                            if not network_obj.is_loopback and not network_obj.is_multicast:
                                segment = {
                                    'network': str(network_obj),
                                    'gateway': gateway,
                                    'interface': interface
                                }
                                if segment not in routing_info['network_segments']:
                                    routing_info['network_segments'].append(segment)
                        except:
                            pass
                            
                except Exception as e:
                    continue
    
    return routing_info

def parse_linux_route(output):
    """Linux ip route 출력 파싱"""
    routing_info = {
        'interfaces': [],
        'routes': [],
        'default_gateway': None,
        'network_segments': []
    }
    
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # default via 192.168.1.1 dev wlan0 proto dhcp metric 600
        if line.startswith('default'):
            parts = line.split()
            if 'via' in parts:
                gateway_idx = parts.index('via') + 1
                if gateway_idx < len(parts):
                    routing_info['default_gateway'] = parts[gateway_idx]
            
            route_entry = {'network': '0.0.0.0/0', 'raw': line}
            routing_info['routes'].append(route_entry)
        
        # 192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.100 metric 600
        elif '/' in line:
            parts = line.split()
            if len(parts) > 0:
                network = parts[0]
                route_entry = {'network': network, 'raw': line}
                routing_info['routes'].append(route_entry)
                
                # 네트워크 세그먼트 추가
                try:
                    network_obj = ipaddress.IPv4Network(network, strict=False)
                    if not network_obj.is_loopback and not network_obj.is_multicast:
                        routing_info['network_segments'].append({'network': network})
                except:
                    pass
    
    return routing_info

def analyze_network_topology(routing_info, target_ip=None):
    """네트워크 토폴로지 분석"""
    analysis = {
        'network_type': 'unknown',
        'internal_networks': [],
        'external_networks': [],
        'default_gateway': routing_info.get('default_gateway'),
        'network_segments': routing_info.get('network_segments', []),
        'potential_targets': [],
        'security_implications': []
    }
    
    # 내부/외부 네트워크 분류
    for segment in routing_info.get('network_segments', []):
        network = segment.get('network', '')
        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
            if network_obj.is_private:
                analysis['internal_networks'].append(network)
                
                # 잠재적 스캔 대상 생성 (작은 네트워크만)
                if network_obj.num_addresses <= 256:
                    analysis['potential_targets'].extend([
                        str(ip) for ip in network_obj.hosts()
                    ][:10])  # 최대 10개만
            else:
                analysis['external_networks'].append(network)
        except:
            continue
    
    # 보안 분석
    if len(analysis['internal_networks']) > 1:
        analysis['security_implications'].append({
            'type': 'Multiple Internal Networks',
            'description': '여러 내부 네트워크가 감지되어 네트워크 세그멘테이션 검토가 필요할 수 있습니다.',
            'severity': 'INFO'
        })
    
    if target_ip:
        try:
            target_obj = ipaddress.IPv4Address(target_ip)
            if target_obj.is_private:
                analysis['network_type'] = 'internal'
            else:
                analysis['network_type'] = 'external'
        except:
            pass
    
    return analysis

def scan_host(host):
    results = {
        'ip': '',
        'ports': [],
        'services': [],
        'cves': [],
        'poc_codes': [],
        'routing_info': None,
        'network_analysis': None
    }
    
    try:
        # IP 주소 확인
        results['ip'] = socket.gethostbyname(host)
        
        # 네트워크 라우팅 정보 수집 (첫 번째 호스트에서만)
        try:
            routing_info = get_network_routing_info()
            results['routing_info'] = routing_info
            results['network_analysis'] = analyze_network_topology(routing_info, results['ip'])
        except Exception as routing_error:
            print(f"라우팅 정보 수집 실패: {routing_error}")
            results['routing_info'] = None
            results['network_analysis'] = None
        
        # Nmap 스캔
        nmap_results = run_nmap_scan(host)
        results['ports'] = nmap_results.get('ports', [])
        results['services'] = nmap_results.get('services', [])
        
        # 웹 포트 접속 확인
        web_ports = [80, 443, 8080, 8443]
        for port_info in results['ports']:
            if port_info['port'] in web_ports and port_info['state'] == 'open':
                port_info['web_accessible'] = check_web_accessibility(host, port_info['port'])
        
        # CVE 검색
        for service in results['services']:
            cves = search_cves(service)
            results['cves'].extend(cves)
        
        # PoC 코드 검색
        for cve in results['cves']:
            poc_code = search_poc_code(cve['id'])
            if poc_code:
                results['poc_codes'].append(poc_code)
        
    except Exception as e:
        results['error'] = str(e)
    
    return results

def run_nmap_scan(host):
    results = {'ports': [], 'services': []}
    
    try:
        # 포트 스캔 (Windows에서 권한 문제 해결)
        cmd = ['nmap', '--unprivileged', '-sCV', '-p', '21,22,23,25,53,80,135,139,443,445,993,995,3389,5985,8080,8443', host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(f"Nmap 출력: {result.stdout}")  # 디버그용
            # nmap 텍스트 출력 파싱
            lines = result.stdout.split('\n')
            for line in lines:
                line = line.strip()
                if '/tcp' in line or '/udp' in line:
                    try:
                        parts = line.split()
                        if len(parts) >= 2:
                            port_proto = parts[0].split('/')
                            port = int(port_proto[0])
                            protocol = port_proto[1] if len(port_proto) > 1 else 'tcp'
                            state = parts[1]
                            service = parts[2] if len(parts) > 2 else get_service_name(port)
                            
                            port_info = {
                                'port': port,
                                'protocol': protocol,
                                'state': state,
                                'service': service
                            }
                            results['ports'].append(port_info)
                            
                            if state == 'open':
                                results['services'].append({
                                    'port': port,
                                    'service': service,
                                    'version': extract_version(line)
                                })
                    except (ValueError, IndexError) as e:
                        print(f"nmap 라인 파싱 오류: {line} - {e}")
                        continue
        else:
            print(f"Nmap 실행 실패: {result.stderr}")
    except Exception as e:
        # nmap이 없는 경우 기본 포트 스캔
        print(f"Nmap 실행 실패, 기본 스캔 시작: {e}")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389, 5985, 8080, 8443]
        for port in common_ports:
            if is_port_open(host, port):
                service_name = get_service_name(port)
                port_info = {
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': service_name
                }
                results['ports'].append(port_info)
                
                # 서비스 정보도 추가
                results['services'].append({
                    'port': port,
                    'service': service_name,
                    'version': 'unknown'
                })
    
    return results

def extract_version(line):
    version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', line)
    return version_match.group(1) if version_match else 'unknown'

def is_port_open(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # 타임아웃 증가
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"포트 {port} 스캔 오류: {e}")
        return False

def get_service_name(port):
    services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios-ssn',
        143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps', 
        995: 'pop3s', 3389: 'rdp', 5985: 'winrm', 8080: 'http-alt', 
        8443: 'https-alt'
    }
    return services.get(port, 'unknown')

def check_web_accessibility(host, port):
    try:
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f"{protocol}://{host}:{port}"
        response = requests.get(url, timeout=10, verify=False)
        
        accessibility = {
            'accessible': True,
            'status_code': response.status_code,
            'title': extract_title(response.text),
            'server': response.headers.get('Server', 'unknown'),
            'directories': []
        }
        
        # 디렉토리 브루트포스 실행
        directories = scan_directories(url)
        accessibility['directories'] = directories
        
        return accessibility
    except:
        return {'accessible': False}

def scan_directories(base_url):
    """웹 디렉토리 브루트포스 스캔"""
    directories = []
    
    # 일반적인 디렉토리 목록
    common_dirs = [
        'admin', 'administrator', 'login', 'wp-admin', 'dashboard', 'panel',
        'backup', 'backups', 'data', 'db', 'database', 'sql',
        'config', 'configuration', 'settings', 'setup',
        'test', 'testing', 'dev', 'development', 'staging',
        'api', 'v1', 'v2', 'rest', 'graphql',
        'upload', 'uploads', 'files', 'documents', 'downloads',
        'images', 'img', 'pics', 'photos', 'assets', 'static',
        'js', 'javascript', 'css', 'styles',
        'include', 'includes', 'lib', 'libraries', 'vendor',
        'tmp', 'temp', 'cache', 'logs', 'log',
        'user', 'users', 'account', 'accounts', 'profile', 'profiles',
        'public', 'private', 'secure', 'security',
        'info', 'information', 'about', 'help', 'support',
        'old', 'new', 'archive', 'archives',
        'phpmyadmin', 'adminer', 'mysql', 'phpinfo',
        'robots.txt', 'sitemap.xml', '.htaccess', '.env',
        'readme.txt', 'README.md', 'changelog.txt',
        'web.config', 'wp-config.php', 'config.php'
    ]
    
    print(f"디렉토리 브루트포스 시작: {base_url}")
    
    # 디렉토리 스캔
    for directory in common_dirs:
        try:
            if directory.startswith('.') or directory.endswith(('.txt', '.xml', '.php', '.md', '.config')):
                # 파일들
                test_url = f"{base_url}/{directory}"
            else:
                # 디렉토리들
                test_url = f"{base_url}/{directory}/"
            
            response = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
            
            # 성공적인 응답들
            if response.status_code in [200, 301, 302, 403, 401]:
                dir_info = {
                    'path': directory,
                    'url': test_url,
                    'status_code': response.status_code,
                    'size': len(response.content) if response.content else 0,
                    'redirect': response.headers.get('Location', ''),
                    'server': response.headers.get('Server', ''),
                    'content_type': response.headers.get('Content-Type', ''),
                    'risk_level': assess_directory_risk(directory, response.status_code)
                }
                
                # 특별한 응답 내용 확인
                if response.status_code == 200 and response.content:
                    content = response.text.lower()
                    if 'index of' in content:
                        dir_info['type'] = 'directory_listing'
                        dir_info['risk_level'] = 'HIGH'
                    elif any(keyword in content for keyword in ['login', 'password', 'username', 'admin']):
                        dir_info['type'] = 'login_page'
                        dir_info['risk_level'] = 'MEDIUM'
                    elif any(keyword in content for keyword in ['config', 'database', 'connection']):
                        dir_info['type'] = 'config_file'
                        dir_info['risk_level'] = 'HIGH'
                    else:
                        dir_info['type'] = 'accessible_content'
                
                directories.append(dir_info)
                print(f"  발견: {test_url} ({response.status_code})")
                
        except requests.exceptions.Timeout:
            continue
        except Exception as e:
            continue
    
    print(f"디렉토리 스캔 완료: {len(directories)}개 발견")
    return directories

def assess_directory_risk(directory, status_code):
    """디렉토리 위험도 평가"""
    high_risk_dirs = [
        'admin', 'administrator', 'phpmyadmin', 'adminer',
        'config', 'configuration', 'backup', 'backups',
        'database', 'db', 'sql', '.env', 'web.config',
        'wp-config.php', 'config.php'
    ]
    
    medium_risk_dirs = [
        'login', 'dashboard', 'panel', 'upload', 'uploads',
        'test', 'testing', 'dev', 'development', 'staging',
        'user', 'users', 'account', 'private', 'secure'
    ]
    
    if status_code == 403:
        return 'MEDIUM'  # 접근 금지되었지만 존재함
    elif status_code in [401]:
        return 'HIGH'    # 인증 필요
    elif any(risk_dir in directory.lower() for risk_dir in high_risk_dirs):
        return 'HIGH'
    elif any(risk_dir in directory.lower() for risk_dir in medium_risk_dirs):
        return 'MEDIUM'
    else:
        return 'LOW'

def extract_title(html):
    title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
    return title_match.group(1) if title_match else 'No title'

def search_cves(service_info):
    cves = []
    # CVE 데이터베이스 API 호출 (예: CVE Details, NVD API)
    try:
        service_name = service_info.get('service', '')
        version = service_info.get('version', '')
        
        if service_name and version != 'unknown':
            # NVD API 호출 예시
            api_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0"
            params = {
                'keyword': f"{service_name} {version}",
                'resultsPerPage': 20
            }
            
            response = requests.get(api_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('result', {}).get('CVE_Items', []):
                    cve_id = item['cve']['CVE_data_meta']['ID']
                    description = item['cve']['description']['description_data'][0]['value']
                    
                    cves.append({
                        'id': cve_id,
                        'description': description,
                        'severity': get_cvss_score(item)
                    })
    except:
        pass
    
    return cves

def get_cvss_score(cve_item):
    try:
        impact = cve_item.get('impact', {})
        if 'baseMetricV3' in impact:
            return impact['baseMetricV3']['cvssV3']['baseScore']
        elif 'baseMetricV2' in impact:
            return impact['baseMetricV2']['cvssV2']['baseScore']
    except:
        pass
    return 'N/A'

def search_poc_code(cve_id):
    # GitHub, Exploit-DB 등에서 PoC 코드 검색
    try:
        # GitHub API를 통한 PoC 검색
        github_api = f"https://api.github.com/search/repositories"
        params = {
            'q': f"{cve_id} poc exploit",
            'sort': 'stars',
            'order': 'desc'
        }
        
        response = requests.get(github_api, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('items'):
                repo = data['items'][0]
                return {
                    'cve_id': cve_id,
                    'repository': repo['html_url'],
                    'description': repo['description'],
                    'stars': repo['stargazers_count'],
                    'language': repo['language']
                }
    except:
        pass
    
    return None

if __name__ == '__main__':
    # AI 분석 라우트 추가
    add_ai_routes(app, scanner)
    app.run(debug=True, host='0.0.0.0', port=5002)