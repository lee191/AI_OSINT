import re
import ipaddress
from typing import List, Tuple, Any


class ValidationUtils:
    """데이터 유효성 검사 유틸리티"""
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
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
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """도메인 이름 유효성 검사"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(pattern, domain) is not None
    
    def validate_targets(self, targets: List[str]) -> Tuple[List[str], List[str]]:
        """타겟 목록 유효성 검사"""
        valid_targets = []
        invalid_targets = []
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
                
            if self.is_valid_ip(target) or self.is_valid_domain(target):
                valid_targets.append(target)
            else:
                invalid_targets.append(target)
        
        return valid_targets, invalid_targets


class NetworkUtils:
    """네트워크 관련 유틸리티"""
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """내부 IP 주소 판별"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return ip_obj.is_private
        except:
            return False
    
    @staticmethod
    def is_loopback_ip(ip: str) -> bool:
        """루프백 IP 주소 판별"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return ip_obj.is_loopback
        except:
            return False
    
    @staticmethod
    def get_network_class(ip: str) -> str:
        """네트워크 클래스 분류"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return 'unknown'
            
            first_octet = int(parts[0])
            
            if 1 <= first_octet <= 126:
                return 'A'
            elif 128 <= first_octet <= 191:
                return 'B'
            elif 192 <= first_octet <= 223:
                return 'C'
            elif 224 <= first_octet <= 239:
                return 'D (Multicast)'
            elif 240 <= first_octet <= 255:
                return 'E (Reserved)'
            else:
                return 'unknown'
        except:
            return 'unknown'
    
    @staticmethod
    def calculate_subnet_info(ip: str, netmask: str) -> dict:
        """서브넷 정보 계산"""
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return {
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address),
                'subnet_mask': str(network.netmask),
                'num_addresses': network.num_addresses,
                'num_hosts': len(list(network.hosts())),
                'is_private': network.is_private,
                'is_multicast': network.is_multicast
            }
        except Exception as e:
            return {'error': str(e)}


class StringUtils:
    """문자열 처리 유틸리티"""
    
    @staticmethod
    def extract_version_from_string(text: str) -> str:
        """문자열에서 버전 정보 추출"""
        version_patterns = [
            r'(\d+\.\d+\.\d+)',  # x.y.z
            r'(\d+\.\d+)',       # x.y
            r'v(\d+\.\d+\.\d+)', # vx.y.z
            r'version\s+(\d+\.\d+\.\d+)',  # version x.y.z
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return 'unknown'
    
    @staticmethod
    def clean_html(html: str) -> str:
        """HTML 태그 제거"""
        clean = re.compile('<.*?>')
        return re.sub(clean, '', html)
    
    @staticmethod
    def extract_title_from_html(html: str) -> str:
        """HTML에서 title 추출"""
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            return StringUtils.clean_html(title)
        return 'No title'
    
    @staticmethod
    def truncate_string(text: str, max_length: int = 100) -> str:
        """문자열 자르기"""
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + '...'


class SecurityUtils:
    """보안 관련 유틸리티"""
    
    @staticmethod
    def assess_port_risk(port: int, service: str = '') -> str:
        """포트별 위험도 평가"""
        # 치명적 위험 포트
        critical_ports = {
            21: 'FTP - 암호화되지 않은 파일 전송',
            23: 'Telnet - 암호화되지 않은 원격 접속',
            135: 'RPC - Windows 원격 프로시저 호출',
            445: 'SMB - 파일 공유 프로토콜'
        }
        
        # 높은 위험 포트
        high_risk_ports = {
            22: 'SSH - 원격 접속 (적절히 보안 설정 필요)',
            3389: 'RDP - Windows 원격 데스크톱',
            5985: 'WinRM - Windows 원격 관리',
            5986: 'WinRM HTTPS - Windows 원격 관리 (HTTPS)'
        }
        
        # 보통 위험 포트
        medium_risk_ports = {
            25: 'SMTP - 이메일 서버',
            53: 'DNS - 도메인 이름 서버',
            80: 'HTTP - 웹 서버 (암호화되지 않음)',
            110: 'POP3 - 이메일 수신',
            143: 'IMAP - 이메일 수신',
            993: 'IMAPS - 안전한 IMAP',
            995: 'POP3S - 안전한 POP3',
            8080: 'HTTP 대체 포트',
            8443: 'HTTPS 대체 포트'
        }
        
        if port in critical_ports:
            return f'CRITICAL - {critical_ports[port]}'
        elif port in high_risk_ports:
            return f'HIGH - {high_risk_ports[port]}'
        elif port in medium_risk_ports:
            return f'MEDIUM - {medium_risk_ports[port]}'
        else:
            return f'LOW - {service if service else "Unknown service"}'
    
    @staticmethod
    def categorize_vulnerability_severity(cvss_score: float) -> str:
        """CVSS 점수에 따른 취약점 심각도 분류"""
        if cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        elif cvss_score > 0:
            return 'LOW'
        else:
            return 'INFO'
    
    @staticmethod
    def generate_security_recommendations(findings: List[dict]) -> List[str]:
        """보안 권장사항 생성"""
        recommendations = []
        
        # 발견사항 분석
        open_ports = [f for f in findings if f.get('type') == 'open_port']
        vulnerabilities = [f for f in findings if f.get('type') == 'vulnerability']
        web_services = [f for f in findings if f.get('type') == 'web_service']
        
        # 포트 기반 권장사항
        if open_ports:
            recommendations.append(f"{len(open_ports)}개의 열린 포트가 발견되었습니다. 불필요한 서비스를 종료하세요.")
        
        # 취약점 기반 권장사항
        if vulnerabilities:
            critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
            high_vulns = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
            
            if critical_vulns:
                recommendations.append(f"{len(critical_vulns)}개의 치명적 취약점이 발견되었습니다. 즉시 패치를 적용하세요.")
            if high_vulns:
                recommendations.append(f"{len(high_vulns)}개의 높은 위험 취약점이 발견되었습니다. 빠른 시일 내에 패치하세요.")
        
        # 웹 서비스 기반 권장사항
        if web_services:
            recommendations.append("웹 서비스에 대한 보안 헤더와 HTTPS 적용을 확인하세요.")
        
        if not recommendations:
            recommendations.append("현재까지 특별한 보안 이슈가 발견되지 않았습니다.")
        
        return recommendations


