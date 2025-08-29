import subprocess
import socket
import time
import threading
import platform
import ipaddress
import requests
import re
import os
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse
from ..config import NmapConfig, config_manager


class HostScanner:
    def __init__(self):
        self.results = {}
    
    def scan_host(self, host: str) -> Dict[str, Any]:
        """FastNmap 스캔 수행"""
        print(f"FastNmap 스캔 시작: {host}")
        
        try:
            # IP 주소 확인
            ip_address = socket.gethostbyname(host)
            print(f"대상 IP: {ip_address}")
            
            # FastNmap 2단계 스캔
            nmap_results = PortScanner().run_nmap_scan(host)
            ports = nmap_results.get('ports', [])
            services = nmap_results.get('services', [])
            
            # 결과 정리
            open_ports = [p for p in ports if p['state'] == 'open']
            
            results = {
                'target': host,
                'ip': ip_address,
                'scan_method': 'FastNmap 2-Stage',
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'open_ports_count': len(open_ports),
                'total_ports_scanned': len(ports),
                'ports': sorted(ports, key=lambda x: x['port']),
                'services': sorted(services, key=lambda x: x['port']),
                'scan_summary': {
                    'status': 'completed',
                    'open_ports': sorted([f"{p['port']}/{p['protocol']} ({p['service']})" for p in open_ports]),
                    'critical_services': sorted(list(set([s['service'] for s in services if s['port'] in [21, 22, 23, 135, 139, 445, 3389]]))),
                    'web_services': sorted([f"{s['service']}:{s['port']}" for s in services if s['port'] in [80, 443, 8080, 8443]]),
                    'common_services': sorted([f"{s['service']}:{s['port']}" for s in services if s['port'] in [21, 22, 23, 25, 53, 80, 443]])
                }
            }
            
            print(f"FastNmap 스캔 완료: {len(open_ports)}개 열린 포트 발견")
            return results
            
        except Exception as e:
            print(f"FastNmap 스캔 실패: {e}")
            return {
                'target': host,
                'ip': '',
                'scan_method': 'FastNmap 2-Stage',
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'error': str(e),
                'open_ports_count': 0,
                'total_ports_scanned': 0,
                'ports': [],
                'services': [],
                'scan_summary': {
                    'status': 'error',
                    'open_ports': [],
                    'critical_services': [],
                    'web_services': [],
                    'common_services': []
                }
            }
    
    def scan_target(self, target: str) -> Dict[str, Any]:
        """단일 타겟에 대한 FastNmap 스캔"""
        return self.scan_host(target)


class PortScanner:
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389, 5985, 8080, 8443]
        self.service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps', 
            995: 'pop3s', 3389: 'rdp', 5985: 'winrm', 8080: 'http-alt', 
            8443: 'https-alt'
        }
    
    def run_nmap_scan(self, host: str) -> Dict[str, List]:
        """FastNmap 2단계 스캔 실행"""
        results = {'ports': [], 'services': []}
        
        try:
            print(f"FastNmap 2단계 스캔 시작: {host}")
            
            # 1단계: 전체 포트 빠른 스캔 (모든 포트 1-65535)
            print("1단계: 전체 포트 빠른 스캔 중...")
            stage1_cmd = ['nmap', '-p-', '--min-rate=1000', '-T4', host]
            
            stage1_result = subprocess.run(stage1_cmd, capture_output=True, text=True, timeout=600)
            open_ports = []
            
            print(f"1단계 명령어 결과코드: {stage1_result.returncode}")
            print(f"1단계 stdout: {stage1_result.stdout[:500]}")
            print(f"1단계 stderr: {stage1_result.stderr}")
            
            if stage1_result.returncode == 0:
                print(f"1단계 완료. 출력: {stage1_result.stdout[:200]}...")
                # 열린 포트 추출
                lines = stage1_result.stdout.split('\n')
                for line in lines:
                    if '/tcp' in line and ('open' in line or 'filtered' in line):
                        try:
                            port = int(line.split('/')[0].strip())
                            open_ports.append(port)
                        except (ValueError, IndexError):
                            continue
                            
                print(f"1단계 결과: {len(open_ports)}개 포트 발견 - {open_ports}")
            else:
                print(f"1단계 실패, 기본 포트로 진행: {stage1_result.stderr}")
                open_ports = [22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5985, 8080, 8443]
            
            # 2단계: 발견된 포트에 대한 상세 스캔
            if open_ports:
                print(f"2단계: {len(open_ports)}개 포트 상세 분석 중...")
                port_list = ','.join(map(str, open_ports))
                stage2_cmd = ['nmap', '-sCV', '-T4', '-p', port_list, host]
                
                stage2_result = subprocess.run(stage2_cmd, capture_output=True, text=True, timeout=180)
                
                if stage2_result.returncode == 0:
                    print(f"2단계 완료. 상세 정보 파싱 중...")
                    # 상세 스캔 결과 파싱
                    lines = stage2_result.stdout.split('\n')
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
                                    service = parts[2] if len(parts) > 2 else self.get_service_name(port)
                                    
                                    port_info = {
                                        'port': port,
                                        'protocol': protocol,
                                        'state': state,
                                        'service': service,
                                        'scan_method': 'fastnmap_2stage'
                                    }
                                    results['ports'].append(port_info)
                                    
                                    if state == 'open':
                                        results['services'].append({
                                            'port': port,
                                            'service': service,
                                            'version': self.extract_version(line),
                                            'scan_method': 'fastnmap_detailed'
                                        })
                            except (ValueError, IndexError) as e:
                                print(f"2단계 파싱 오류: {line} - {e}")
                                continue
                else:
                    print(f"2단계 실패: {stage2_result.stderr}")
            else:
                print("발견된 포트가 없어 2단계 건너뜀")
                
        except Exception as e:
            # nmap이 없는 경우 기본 포트 스캔으로 폴백
            print(f"FastNmap 실행 실패, 기본 스캔으로 폴백: {e}")
            for port in self.common_ports:
                if self.is_port_open(host, port):
                    service_name = self.get_service_name(port)
                    port_info = {
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': service_name,
                        'scan_method': 'fallback_socket'
                    }
                    results['ports'].append(port_info)
                    
                    results['services'].append({
                        'port': port,
                        'service': service_name,
                        'version': 'unknown',
                        'scan_method': 'fallback_socket'
                    })
        
        print(f"FastNmap 스캔 완료: {len(results['ports'])}개 포트, {len(results['services'])}개 서비스")
        return results
    
    def extract_version(self, line: str) -> str:
        """버전 정보 추출"""
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', line)
        return version_match.group(1) if version_match else 'unknown'
    
    def is_port_open(self, host: str, port: int) -> bool:
        """포트 개방 여부 확인"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            print(f"포트 {port} 스캔 오류: {e}")
            return False
    
    def get_service_name(self, port: int) -> str:
        """포트 번호로 서비스명 조회"""
        return self.service_map.get(port, 'unknown')


