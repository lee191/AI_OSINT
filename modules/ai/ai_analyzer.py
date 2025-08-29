import json
from flask import jsonify
import requests
from typing import Dict, List, Any
import re

class AIAnalyzer:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.analysis_cache = {}
    
    def analyze_scan_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """AI 기반 스캔 결과 분석"""
        analysis = {
            'risk_score': 0,
            'risk_level': 'LOW',
            'security_recommendations': [],
            'critical_findings': [],
            'attack_scenarios': [],
            'remediation_priorities': [],
            'threat_intelligence': [],
            'compliance_issues': [],
            'network_topology': {}
        }
        
        if not results:
            return analysis
        
        total_hosts = len(results)
        high_risk_count = 0
        critical_risk_count = 0
        total_vulnerabilities = 0
        total_open_ports = 0
        exposed_services = []
        
        for hostname, host_data in results.items():
            host_analysis = self.analyze_host(hostname, host_data)
            analysis['critical_findings'].extend(host_analysis['findings'])
            analysis['security_recommendations'].extend(host_analysis['recommendations'])
            
            # 위험도 집계
            if host_analysis['risk_level'] == 'CRITICAL':
                critical_risk_count += 1
            elif host_analysis['risk_level'] == 'HIGH':
                high_risk_count += 1
            
            # 통계 집계
            total_vulnerabilities += len(host_data.get('cves', []))
            ports = host_data.get('ports', [])
            open_ports = [p for p in ports if p.get('state') == 'open']
            total_open_ports += len(open_ports)
            
            # 노출된 서비스 수집
            for port in open_ports:
                service_info = {
                    'host': hostname,
                    'port': port.get('port'),
                    'service': port.get('service'),
                    'risk_level': self.assess_service_risk(port)
                }
                exposed_services.append(service_info)
        
        # 향상된 위험도 계산
        analysis['risk_score'] = self.calculate_comprehensive_risk_score(
            total_hosts, critical_risk_count, high_risk_count, 
            total_vulnerabilities, total_open_ports, exposed_services
        )
        
        # 위험도 레벨 결정
        analysis['risk_level'] = self.determine_risk_level(analysis['risk_score'])
        
        # 공격 시나리오 생성
        analysis['attack_scenarios'] = self.generate_attack_scenarios(results)
        
        # 위협 인텔리전스 추가
        analysis['threat_intelligence'] = self.generate_threat_intelligence(results)
        
        # 컴플라이언스 이슈 분석
        analysis['compliance_issues'] = self.analyze_compliance_issues(results)
        
        # 네트워크 토폴로지 분석
        analysis['network_topology'] = self.analyze_network_topology(results)
        
        # 우선순위 수정 권장사항
        analysis['remediation_priorities'] = self.prioritize_remediation(results)
        
        return analysis
    
    def calculate_comprehensive_risk_score(self, total_hosts, critical_count, high_count, 
                                         total_vulns, total_ports, exposed_services):
        """포괄적인 위험도 점수 계산"""
        if total_hosts == 0:
            return 0
        
        # 기본 점수
        base_score = 0
        
        # 치명적 위험 호스트 비율 (최대 40점)
        critical_ratio = (critical_count / total_hosts) * 40
        base_score += critical_ratio
        
        # 높은 위험 호스트 비율 (최대 25점)
        high_ratio = (high_count / total_hosts) * 25
        base_score += high_ratio
        
        # 취약점 밀도 (최대 20점)
        vuln_density = min(20, (total_vulns / total_hosts) * 2)
        base_score += vuln_density
        
        # 노출된 서비스 위험도 (최대 15점)
        high_risk_services = [s for s in exposed_services if s['risk_level'] in ['HIGH', 'CRITICAL']]
        service_risk = min(15, len(high_risk_services) * 3)
        base_score += service_risk
        
        return min(100, int(base_score))
    
    def determine_risk_level(self, risk_score):
        """위험도 점수를 기반으로 레벨 결정"""
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def assess_service_risk(self, port_info):
        """서비스별 위험도 평가"""
        port = port_info.get('port')
        service = port_info.get('service', '').lower()
        
        # 치명적 위험 서비스
        if port in [21, 23, 135, 445] or 'ftp' in service or 'telnet' in service:
            return 'CRITICAL'
        
        # 높은 위험 서비스
        if port in [22, 3389, 5985] or 'ssh' in service or 'rdp' in service or 'winrm' in service:
            return 'HIGH'
        
        # 보통 위험 서비스
        if port in [80, 443, 8080, 8443] or 'http' in service:
            return 'MEDIUM'
        
        return 'LOW'
    
    def generate_threat_intelligence(self, results):
        """위협 인텔리전스 생성"""
        threats = []
        
        for hostname, host_data in results.items():
            ports = host_data.get('ports', [])
            open_ports = [p for p in ports if p.get('state') == 'open']
            
            # 원격 접근 서비스 탐지
            remote_services = [p for p in open_ports if p.get('port') in [22, 3389, 5985, 5986]]
            if remote_services:
                threats.append({
                    'type': 'Remote Access Exposure',
                    'severity': 'HIGH',
                    'description': f'{hostname}에서 {len(remote_services)}개의 원격 접근 서비스가 노출됨',
                    'services': [p.get('port') for p in remote_services],
                    'mitigation': '원격 접근을 VPN이나 방화벽으로 제한하고 강력한 인증 적용'
                })
            
            # 레거시 프로토콜 탐지
            legacy_services = [p for p in open_ports if p.get('port') in [21, 23, 25, 110, 143]]
            if legacy_services:
                threats.append({
                    'type': 'Legacy Protocol Exposure',
                    'severity': 'MEDIUM',
                    'description': f'{hostname}에서 레거시 프로토콜 서비스 발견',
                    'services': [f"{p.get('port')}({p.get('service')})" for p in legacy_services],
                    'mitigation': '최신 보안 프로토콜로 교체 권장'
                })
            
            # Windows 특화 서비스
            windows_services = [p for p in open_ports if p.get('port') in [135, 139, 445]]
            if len(windows_services) >= 2:
                threats.append({
                    'type': 'Windows Service Exposure',
                    'severity': 'HIGH',
                    'description': f'{hostname}에서 여러 Windows 서비스가 노출됨',
                    'services': [p.get('port') for p in windows_services],
                    'mitigation': 'SMB 서명 활성화, 불필요한 공유 제거, 네트워크 접근 제한'
                })
        
        return threats
    
    def analyze_compliance_issues(self, results):
        """컴플라이언스 이슈 분석"""
        issues = []
        
        for hostname, host_data in results.items():
            ports = host_data.get('ports', [])
            open_ports = [p for p in ports if p.get('state') == 'open']
            
            # PCI DSS 관련
            if any(p.get('port') in [80, 8080] for p in open_ports):
                https_ports = [p for p in open_ports if p.get('port') in [443, 8443]]
                if not https_ports:
                    issues.append({
                        'standard': 'PCI DSS',
                        'requirement': '4.1 - 전송 중 데이터 암호화',
                        'finding': f'{hostname}에서 HTTP는 있지만 HTTPS가 없음',
                        'severity': 'HIGH'
                    })
            
            # SOX 관련 (관리자 접근)
            admin_ports = [p for p in open_ports if p.get('port') in [22, 3389, 23]]
            if admin_ports:
                issues.append({
                    'standard': 'SOX',
                    'requirement': '접근 통제',
                    'finding': f'{hostname}에서 관리자 접근 포트 노출',
                    'severity': 'MEDIUM'
                })
            
            # GDPR 관련 (데이터베이스 포트)
            db_ports = [p for p in open_ports if p.get('port') in [1433, 3306, 5432, 1521]]
            if db_ports:
                issues.append({
                    'standard': 'GDPR',
                    'requirement': '데이터 보호',
                    'finding': f'{hostname}에서 데이터베이스 포트 노출 가능',
                    'severity': 'CRITICAL'
                })
        
        return issues
    
    def analyze_network_topology(self, results):
        """네트워크 토폴로지 분석"""
        topology = {
            'internal_hosts': [],
            'external_hosts': [],
            'service_distribution': {},
            'network_segments': []
        }
        
        for hostname, host_data in results.items():
            ip = host_data.get('ip', hostname)
            
            # 내부/외부 분류
            if self.is_internal_ip(ip):
                topology['internal_hosts'].append(hostname)
            else:
                topology['external_hosts'].append(hostname)
            
            # 서비스 분포
            services = host_data.get('services', [])
            for service in services:
                service_name = service.get('service', 'unknown')
                if service_name not in topology['service_distribution']:
                    topology['service_distribution'][service_name] = 0
                topology['service_distribution'][service_name] += 1
            
            # 네트워크 세그먼트 분석
            if '.' in ip:
                network = '.'.join(ip.split('.')[:3]) + '.0/24'
                if network not in topology['network_segments']:
                    topology['network_segments'].append(network)
        
        return topology
    
    def is_internal_ip(self, ip):
        """내부 IP 주소 판별"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            # RFC 1918 private IP ranges
            if parts[0] == '10':
                return True
            if parts[0] == '172' and 16 <= int(parts[1]) <= 31:
                return True
            if parts[0] == '192' and parts[1] == '168':
                return True
            
            # localhost
            if parts[0] == '127':
                return True
                
            return False
        except:
            return False
    
    def analyze_host(self, hostname: str, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """개별 호스트 분석"""
        findings = []
        recommendations = []
        risk_level = 'LOW'
        
        # 포트 분석
        open_ports = host_data.get('ports', [])
        high_risk_ports = []
        
        for port_info in open_ports:
            if port_info.get('state') == 'open':
                port = port_info.get('port')
                service = port_info.get('service', '')
                
                # 위험한 포트 체크
                if port in [21, 23, 25, 53, 135, 139, 445, 1433, 3389]:
                    high_risk_ports.append(port)
                    findings.append({
                        'type': 'high_risk_port',
                        'description': f'위험한 포트 {port} ({service})가 열려있음',
                        'severity': 'HIGH'
                    })
                
                # 웹 서비스 분석
                if port in [80, 443, 8080, 8443] and port_info.get('web_accessible'):
                    web_info = port_info['web_accessible']
                    if web_info.get('accessible'):
                        findings.append({
                            'type': 'web_service',
                            'description': f'웹 서비스 발견: {hostname}:{port}',
                            'details': web_info,
                            'severity': 'INFO'
                        })
        
        # CVE 분석
        cves = host_data.get('cves', [])
        critical_cves = []
        
        for cve in cves:
            severity = cve.get('severity', 0)
            if isinstance(severity, (int, float)) and severity >= 9.0:
                critical_cves.append(cve)
                findings.append({
                    'type': 'critical_vulnerability',
                    'description': f'치명적 취약점 발견: {cve.get("id")}',
                    'severity': 'CRITICAL',
                    'cve_id': cve.get('id'),
                    'score': severity
                })
            elif isinstance(severity, (int, float)) and severity >= 7.0:
                findings.append({
                    'type': 'high_vulnerability',
                    'description': f'높은 위험 취약점: {cve.get("id")}',
                    'severity': 'HIGH',
                    'cve_id': cve.get('id'),
                    'score': severity
                })
        
        # PoC 코드 분석
        poc_codes = host_data.get('poc_codes', [])
        if poc_codes:
            findings.append({
                'type': 'poc_available',
                'description': f'{len(poc_codes)}개의 PoC 코드가 공개되어 있음',
                'severity': 'HIGH',
                'poc_count': len(poc_codes)
            })
        
        # 위험도 결정
        if critical_cves or len(high_risk_ports) > 2:
            risk_level = 'CRITICAL'
        elif high_risk_ports or len(cves) > 5:
            risk_level = 'HIGH'
        elif len(cves) > 0 or len(open_ports) > 10:
            risk_level = 'MEDIUM'
        
        # 권장사항 생성
        recommendations.extend(self.generate_host_recommendations(hostname, host_data, findings))
        
        return {
            'hostname': hostname,
            'findings': findings,
            'recommendations': recommendations,
            'risk_level': risk_level,
            'metrics': {
                'open_ports': len(open_ports),
                'high_risk_ports': len(high_risk_ports),
                'total_cves': len(cves),
                'critical_cves': len(critical_cves),
                'poc_available': len(poc_codes)
            }
        }
    
    def generate_host_recommendations(self, hostname: str, host_data: Dict, findings: List) -> List[str]:
        """호스트별 보안 권장사항 생성"""
        recommendations = []
        
        # 포트 기반 권장사항
        open_ports = [p.get('port') for p in host_data.get('ports', []) if p.get('state') == 'open']
        
        if 21 in open_ports:
            recommendations.append("FTP 서비스를 SFTP로 대체하거나 필요없다면 비활성화하세요")
        
        if 23 in open_ports:
            recommendations.append("Telnet 서비스를 SSH로 대체하세요")
        
        if 445 in open_ports:
            recommendations.append("SMB 서비스의 보안 설정을 강화하고 불필요한 공유를 제거하세요")
        
        if 3389 in open_ports:
            recommendations.append("RDP 접근을 VPN으로 제한하고 강력한 인증을 적용하세요")
        
        # CVE 기반 권장사항
        cves = host_data.get('cves', [])
        if cves:
            recommendations.append(f"{len(cves)}개의 알려진 취약점이 발견되었습니다. 시스템 업데이트를 진행하세요")
        
        # PoC 기반 권장사항
        poc_codes = host_data.get('poc_codes', [])
        if poc_codes:
            recommendations.append("공개된 PoC 코드가 있는 취약점이 발견되었습니다. 즉시 패치를 적용하세요")
        
        # 웹 서비스 권장사항
        web_services = [p for p in host_data.get('ports', []) if p.get('port') in [80, 443, 8080, 8443] and p.get('web_accessible', {}).get('accessible')]
        if web_services:
            recommendations.append("웹 서비스에 대한 보안 헤더와 HTTPS 적용을 확인하세요")
        
        return recommendations
    
    def generate_attack_scenarios(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """가능한 공격 시나리오 생성"""
        scenarios = []
        
        # 스캔 결과 분석
        total_hosts = len(results)
        hosts_with_web = 0
        hosts_with_critical_vulns = 0
        hosts_with_admin_ports = 0
        
        for hostname, host_data in results.items():
            ports = host_data.get('ports', [])
            cves = host_data.get('cves', [])
            
            # 웹 서비스 확인
            web_ports = [80, 443, 8080, 8443]
            if any(p.get('port') in web_ports and p.get('state') == 'open' for p in ports):
                hosts_with_web += 1
            
            # 치명적 취약점 확인
            if any(isinstance(cve.get('severity'), (int, float)) and cve.get('severity') >= 9.0 for cve in cves):
                hosts_with_critical_vulns += 1
            
            # 관리자 포트 확인
            admin_ports = [22, 23, 3389, 5985, 5986]
            if any(p.get('port') in admin_ports and p.get('state') == 'open' for p in ports):
                hosts_with_admin_ports += 1
        
        # 시나리오 생성
        if hosts_with_web > 0:
            scenarios.append({
                'name': 'Web Application Attack',
                'description': f'{hosts_with_web}개의 호스트에서 웹 서비스가 발견되었습니다. 웹 애플리케이션 취약점을 통한 공격이 가능합니다.',
                'likelihood': 'HIGH' if hosts_with_web > total_hosts * 0.5 else 'MEDIUM',
                'impact': 'HIGH',
                'steps': [
                    '웹 애플리케이션 취약점 스캔',
                    'SQL Injection, XSS 등 공격 시도',
                    '파일 업로드 취약점 악용',
                    '웹쉘 업로드 및 시스템 권한 획득'
                ]
            })
        
        if hosts_with_critical_vulns > 0:
            scenarios.append({
                'name': 'Remote Code Execution',
                'description': f'{hosts_with_critical_vulns}개의 호스트에서 치명적 취약점이 발견되었습니다. 원격 코드 실행 공격이 가능합니다.',
                'likelihood': 'CRITICAL',
                'impact': 'CRITICAL',
                'steps': [
                    '공개된 PoC 코드 활용',
                    '취약점을 통한 원격 코드 실행',
                    '시스템 권한 획득',
                    '추가 시스템으로 lateral movement'
                ]
            })
        
        if hosts_with_admin_ports > 0:
            scenarios.append({
                'name': 'Brute Force Attack',
                'description': f'{hosts_with_admin_ports}개의 호스트에서 관리자 서비스가 노출되어 있습니다. 무차별 대입 공격이 가능합니다.',
                'likelihood': 'MEDIUM',
                'impact': 'HIGH',
                'steps': [
                    '사용자명/패스워드 사전 공격',
                    '약한 인증 정보 발견',
                    '관리자 권한 획득',
                    '시스템 완전 장악'
                ]
            })
        
        return scenarios
    
    def prioritize_remediation(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """수정 우선순위 결정"""
        priorities = []
        
        # 모든 발견사항 수집
        all_findings = []
        for hostname, host_data in results.items():
            host_analysis = self.analyze_host(hostname, host_data)
            for finding in host_analysis['findings']:
                finding['hostname'] = hostname
                all_findings.append(finding)
        
        # 우선순위별 분류
        critical_items = [f for f in all_findings if f.get('severity') == 'CRITICAL']
        high_items = [f for f in all_findings if f.get('severity') == 'HIGH']
        
        # 최우선 (Critical)
        if critical_items:
            priorities.append({
                'priority': 1,
                'title': '즉시 조치 필요 (Critical)',
                'description': '치명적 취약점이나 보안 위험이 발견되었습니다.',
                'items': critical_items[:5],  # 상위 5개만
                'timeline': '즉시 (24시간 이내)'
            })
        
        # 높은 우선순위 (High)
        if high_items:
            priorities.append({
                'priority': 2,
                'title': '높은 우선순위 (High)',
                'description': '높은 보안 위험이 발견되었습니다.',
                'items': high_items[:10],  # 상위 10개만
                'timeline': '1주일 이내'
            })
        
        # 일반 권장사항
        general_recommendations = []
        for hostname, host_data in results.items():
            ports = host_data.get('ports', [])
            if len(ports) > 20:
                general_recommendations.append({
                    'type': 'port_reduction',
                    'description': f'{hostname}에서 {len(ports)}개의 포트가 열려있습니다. 불필요한 서비스를 종료하세요.',
                    'hostname': hostname
                })
        
        if general_recommendations:
            priorities.append({
                'priority': 3,
                'title': '일반 보안 강화',
                'description': '전반적인 보안 수준 향상을 위한 권장사항입니다.',
                'items': general_recommendations,
                'timeline': '1개월 이내'
            })
        
        return priorities
    
    def generate_executive_summary(self, results: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """경영진용 요약 보고서 생성"""
        total_hosts = len(results)
        total_vulnerabilities = sum(len(host.get('cves', [])) for host in results.values())
        high_risk_hosts = sum(1 for host in results.values() if self.analyze_host('', host)['risk_level'] in ['HIGH', 'CRITICAL'])
        
        summary = f"""
# 보안 스캔 결과 요약 보고서

## 전체 현황
- 스캔 대상: {total_hosts}개 호스트
- 발견된 취약점: {total_vulnerabilities}개
- 높은 위험 호스트: {high_risk_hosts}개
- 전체 위험도: {analysis['risk_score']}/100

## 주요 발견사항
"""
        
        for i, finding in enumerate(analysis['critical_findings'][:5], 1):
            summary += f"{i}. {finding.get('description', 'N/A')}\n"
        
        summary += f"""
## 권장 조치사항
총 {len(analysis['remediation_priorities'])}개 우선순위로 분류된 조치사항이 있습니다.
"""
        
        for priority in analysis['remediation_priorities'][:3]:
            summary += f"- {priority['title']}: {priority['timeline']}\n"
        
        return summary

# AI 분석 결과를 위한 추가 엔드포인트
def add_ai_routes(app, scanner):
    @app.route('/scan/<scan_id>/analysis')
    def get_ai_analysis(scan_id):
        if scan_id not in scanner.results:
            return jsonify({'error': 'Scan not found'}), 404
        
        results = scanner.results[scan_id].get('results', {})
        if not results:
            return jsonify({'error': 'No results available'}), 400
        
        analyzer = AIAnalyzer()
        analysis = analyzer.analyze_scan_results(results)
        
        return jsonify({
            'analysis': analysis,
            'executive_summary': analyzer.generate_executive_summary(results, analysis)
        })
    
    @app.route('/scan/<scan_id>/report')
    def generate_report(scan_id):
        if scan_id not in scanner.results:
            return jsonify({'error': 'Scan not found'}), 404
        
        results = scanner.results[scan_id].get('results', {})
        if not results:
            return jsonify({'error': 'No results available'}), 400
        
        analyzer = AIAnalyzer()
        analysis = analyzer.analyze_scan_results(results)
        
        # 상세 보고서 생성
        report = {
            'scan_id': scan_id,
            'timestamp': scanner.results[scan_id].get('timestamp', ''),
            'results': results,
            'analysis': analysis,
            'executive_summary': analyzer.generate_executive_summary(results, analysis),
            'technical_details': {
                'total_hosts_scanned': len(results),
                'total_open_ports': sum(len(host.get('ports', [])) for host in results.values()),
                'total_vulnerabilities': sum(len(host.get('cves', [])) for host in results.values()),
                'poc_codes_found': sum(len(host.get('poc_codes', [])) for host in results.values())
            }
        }
        
        return jsonify(report)