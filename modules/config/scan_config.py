import json
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class ScanSpeed(Enum):
    """스캔 속도 설정"""
    SLOW = "slow"           # T1 - 매우 느림 (IDS 회피)
    NORMAL = "normal"       # T3 - 일반 속도
    FAST = "fast"          # T4 - 빠른 속도
    INSANE = "insane"      # T5 - 매우 빠름 (부정확할 수 있음)


class PortRange(Enum):
    """포트 범위 설정"""
    TOP_100 = "top_100"         # 상위 100개 포트
    TOP_1000 = "top_1000"       # 상위 1000개 포트 (기본값)
    COMMON = "common"           # 일반적인 포트들
    ALL = "all"                 # 모든 포트 (1-65535)
    CUSTOM = "custom"           # 사용자 정의


@dataclass
class NmapConfig:
    """Nmap 스캔 설정"""
    # 기본 설정
    speed: ScanSpeed = ScanSpeed.FAST
    port_range: PortRange = PortRange.TOP_1000
    custom_ports: str = ""
    min_rate: int = 1000
    max_rate: int = 5000
    
    # 스캔 옵션
    service_version: bool = True        # -sV
    script_scan: bool = True           # -sC
    os_detection: bool = False         # -O
    aggressive: bool = False           # -A
    
    # 타임아웃 설정
    host_timeout: int = 300            # 호스트 타임아웃 (초)
    scan_timeout: int = 600            # 전체 스캔 타임아웃 (초)
    
    # 출력 설정
    save_output: bool = True
    output_format: List[str] = None    # 기본값은 ['normal', 'xml']
    
    # 고급 설정
    parallel_scan: bool = True         # 병렬 스캔
    max_parallel_hosts: int = 5        # 최대 병렬 호스트 수
    stealth_mode: bool = False         # 스텔스 모드
    
    def __post_init__(self):
        if self.output_format is None:
            self.output_format = ['normal', 'xml']
    
    def get_timing_template(self) -> str:
        """타이밍 템플릿 반환"""
        timing_map = {
            ScanSpeed.SLOW: "T1",
            ScanSpeed.NORMAL: "T3", 
            ScanSpeed.FAST: "T4",
            ScanSpeed.INSANE: "T5"
        }
        return f"-{timing_map[self.speed]}"
    
    def get_port_specification(self) -> str:
        """포트 지정 문자열 반환"""
        if self.port_range == PortRange.CUSTOM and self.custom_ports:
            return f"-p{self.custom_ports}"
        elif self.port_range == PortRange.ALL:
            return "-p-"
        elif self.port_range == PortRange.TOP_100:
            return "--top-ports 100"
        elif self.port_range == PortRange.TOP_1000:
            return "--top-ports 1000"
        elif self.port_range == PortRange.COMMON:
            common_ports = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3389,5985,8080,8443"
            return f"-p{common_ports}"
        else:
            return "--top-ports 1000"  # 기본값
    
    def get_scan_options(self) -> List[str]:
        """스캔 옵션 리스트 반환"""
        options = []
        
        if self.service_version:
            options.append("-sV")
        if self.script_scan:
            options.append("-sC")
        if self.os_detection:
            options.append("-O")
        if self.aggressive:
            options.append("-A")
        if self.stealth_mode:
            options.append("-sS")  # SYN 스캔
        
        return options
    
    def get_performance_options(self) -> List[str]:
        """성능 관련 옵션 반환"""
        options = []
        
        options.append(f"--min-rate={self.min_rate}")
        if self.max_rate > self.min_rate:
            options.append(f"--max-rate={self.max_rate}")
        
        options.append(f"--host-timeout={self.host_timeout}s")
        
        if self.parallel_scan and self.max_parallel_hosts > 1:
            options.append(f"--max-hostgroup={self.max_parallel_hosts}")
        
        return options
    
    def to_dict(self) -> Dict[str, Any]:
        """설정을 딕셔너리로 변환"""
        config_dict = asdict(self)
        # Enum을 문자열로 변환
        config_dict['speed'] = self.speed.value
        config_dict['port_range'] = self.port_range.value
        return config_dict
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NmapConfig':
        """딕셔너리에서 설정 객체 생성"""
        # Enum 변환
        if 'speed' in data:
            data['speed'] = ScanSpeed(data['speed'])
        if 'port_range' in data:
            data['port_range'] = PortRange(data['port_range'])
        
        return cls(**data)


class ScanConfigManager:
    """스캔 설정 관리자"""
    
    def __init__(self, config_file: str = "scan_config.json"):
        self.config_file = config_file
        self.default_config = NmapConfig()
        self.profiles = self._load_profiles()
    
    def _load_profiles(self) -> Dict[str, NmapConfig]:
        """프로파일 로드"""
        profiles = {
            "default": self.default_config,
            "quick": NmapConfig(
                speed=ScanSpeed.INSANE,
                port_range=PortRange.TOP_100,
                min_rate=5000,
                service_version=False,
                script_scan=False
            ),
            "comprehensive": NmapConfig(
                speed=ScanSpeed.NORMAL,
                port_range=PortRange.ALL,
                min_rate=500,
                service_version=True,
                script_scan=True,
                os_detection=True
            ),
            "stealth": NmapConfig(
                speed=ScanSpeed.SLOW,
                port_range=PortRange.COMMON,
                min_rate=100,
                stealth_mode=True,
                service_version=False
            ),
            "web_focused": NmapConfig(
                speed=ScanSpeed.FAST,
                port_range=PortRange.CUSTOM,
                custom_ports="80,443,8080,8443,8000,8001,8888,9000,3000,5000",
                service_version=True,
                script_scan=True
            )
        }
        
        # 파일에서 사용자 정의 프로파일 로드
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    saved_profiles = json.load(f)
                    for name, config_data in saved_profiles.items():
                        if name not in profiles:  # 기본 프로파일 덮어쓰기 방지
                            profiles[name] = NmapConfig.from_dict(config_data)
            except Exception as e:
                print(f"프로파일 로드 실패: {e}")
        
        return profiles
    
    def save_profiles(self):
        """프로파일을 파일에 저장"""
        try:
            # 기본 프로파일은 제외하고 사용자 정의 프로파일만 저장
            user_profiles = {}
            default_names = {"default", "quick", "comprehensive", "stealth", "web_focused"}
            
            for name, config in self.profiles.items():
                if name not in default_names:
                    user_profiles[name] = config.to_dict()
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(user_profiles, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"프로파일 저장 실패: {e}")
    
    def get_profile(self, profile_name: str) -> Optional[NmapConfig]:
        """프로파일 조회"""
        return self.profiles.get(profile_name)
    
    def add_profile(self, name: str, config: NmapConfig):
        """프로파일 추가"""
        self.profiles[name] = config
        self.save_profiles()
    
    def delete_profile(self, name: str) -> bool:
        """프로파일 삭제"""
        # 기본 프로파일은 삭제 불가
        default_names = {"default", "quick", "comprehensive", "stealth", "web_focused"}
        if name in default_names:
            return False
        
        if name in self.profiles:
            del self.profiles[name]
            self.save_profiles()
            return True
        return False
    
    def list_profiles(self) -> Dict[str, str]:
        """프로파일 목록과 설명"""
        descriptions = {
            "default": "기본 설정 (Fast/Top1000)",
            "quick": "빠른 스캔 (Top100 포트만)",
            "comprehensive": "전체 스캔 (모든 포트)",
            "stealth": "스텔스 스캔 (IDS 회피)",
            "web_focused": "웹 서비스 중심 스캔"
        }
        
        result = {}
        for name in self.profiles.keys():
            result[name] = descriptions.get(name, "사용자 정의 프로파일")
        
        return result
    
    def get_preset_configs(self) -> Dict[str, Dict[str, Any]]:
        """프리셋 설정들을 API용으로 반환"""
        presets = {}
        for name, config in self.profiles.items():
            presets[name] = {
                'name': name,
                'description': self.list_profiles().get(name, ""),
                'config': config.to_dict()
            }
        return presets


# 전역 설정 관리자 인스턴스
config_manager = ScanConfigManager()