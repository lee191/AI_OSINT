# 개발 가이드라인 - 모듈화 표준

## 📋 개요

앞으로 추가되는 모든 새로운 기능들은 모듈화된 구조를 따라 개발됩니다.

## 🏗️ 모듈 설계 원칙

### 1. **단일 책임 원칙 (SRP)**
- 각 모듈은 하나의 명확한 책임만 가져야 함
- 예: `scanner` 모듈은 스캔 기능만, `database` 모듈은 데이터 관리만

### 2. **폴더 기반 구조**
- 모든 기능은 `modules/` 하위의 별도 폴더에 구현
- 폴더명은 기능을 명확히 표현해야 함

### 3. **표준화된 구조**
```
modules/
├── [기능명]/
│   ├── __init__.py          # 패키지 초기화 및 공개 API
│   ├── [기능명].py         # 메인 구현 파일
│   ├── models.py           # 데이터 모델 (필요시)
│   ├── exceptions.py       # 커스텀 예외 (필요시)
│   └── utils.py           # 모듈 전용 유틸리티 (필요시)
```

## 📁 새로운 모듈 생성 가이드

### Step 1: 폴더 구조 생성
```bash
mkdir modules/[기능명]
touch modules/[기능명]/__init__.py
touch modules/[기능명]/[기능명].py
```

### Step 2: `__init__.py` 작성
```python
"""
[기능명] 모듈

[기능 설명]
"""

from .[기능명] import [메인클래스], [주요함수]

__version__ = "1.0.0"
__author__ = "AI OSINT Team"

__all__ = [
    '[메인클래스]',
    '[주요함수]'
]
```

### Step 3: 메인 구현 파일 작성
```python
"""
[기능명] 모듈의 메인 구현

작성일: YYYY-MM-DD
작성자: [작성자]
버전: 1.0.0
"""

from typing import Dict, List, Any, Optional
import logging

# 다른 내부 모듈 import
from ..utils import ValidationUtils
from ..database import DatabaseManager

logger = logging.getLogger(__name__)


class [메인클래스]:
    """[클래스 설명]"""
    
    def __init__(self):
        """초기화"""
        pass
    
    def main_function(self) -> Dict[str, Any]:
        """주요 기능 구현"""
        pass


def utility_function() -> bool:
    """유틸리티 함수"""
    pass
```

## 🎯 모듈 카테고리 분류

### 1. **Core Modules** (핵심 모듈)
- `database/` - 데이터베이스 관리
- `scanner/` - 스캔 엔진
- `api/` - 웹 API
- `utils/` - 공통 유틸리티

### 2. **Feature Modules** (기능 모듈)
- `ai/` - AI 분석
- `config/` - 설정 관리
- `reporting/` - 보고서 생성 (미래 확장)
- `monitoring/` - 모니터링 (미래 확장)
- `security/` - 보안 기능 (미래 확장)

### 3. **Integration Modules** (통합 모듈)
- `exporters/` - 데이터 내보내기 (미래 확장)
- `parsers/` - 파일 파싱 (미래 확장)
- `connectors/` - 외부 시스템 연동 (미래 확장)

### 4. **Extension Modules** (확장 모듈)
- `plugins/` - 플러그인 시스템 (미래 확장)
- `custom/` - 사용자 정의 기능 (미래 확장)

## ✅ 체크리스트

### 새 모듈 생성 시 확인사항

- [ ] **폴더 구조**: `modules/[기능명]/` 형태로 생성
- [ ] **`__init__.py`**: 공개 API 명시 및 버전 정보 포함
- [ ] **타입 힌트**: 모든 함수/메서드에 타입 힌트 적용
- [ ] **독스트링**: 클래스/함수에 설명 문서 작성
- [ ] **로깅**: 적절한 로깅 구현
- [ ] **에러 처리**: 예외 상황 처리
- [ ] **테스트**: 기능 동작 확인
- [ ] **의존성**: 최소한의 외부 의존성 유지

### 기존 시스템 통합 시 확인사항

- [ ] **Import 경로**: 올바른 모듈 import 경로 사용
- [ ] **API 통합**: 필요시 API 엔드포인트 추가
- [ ] **데이터베이스**: 필요시 테이블/스키마 추가
- [ ] **설정**: 필요시 설정 옵션 추가
- [ ] **문서**: 사용법 및 API 문서 작성

## 🔄 개발 워크플로우

### 1. 기획 단계
```
새 기능 요구사항 → 모듈 설계 → 폴더 구조 계획
```

### 2. 구현 단계
```
폴더 생성 → 기본 구조 작성 → 핵심 기능 구현 → 테스트
```

### 3. 통합 단계
```
기존 시스템 통합 → API 추가 → 문서 작성 → 배포
```

## 📝 명명 규칙

### 폴더명
- 소문자, 단수형 사용
- 하이픈(-) 사용 금지, 언더스코어(_) 사용
- 예: `threat_intelligence`, `data_export`, `network_monitor`

### 파일명
- 소문자, 언더스코어(_) 사용
- 모듈명과 동일한 메인 파일
- 예: `threat_intelligence.py`, `data_export.py`

### 클래스명
- PascalCase 사용
- 기능을 명확히 표현
- 예: `ThreatIntelligenceAnalyzer`, `DataExportManager`

### 함수명
- snake_case 사용
- 동사로 시작
- 예: `analyze_threat_data()`, `export_scan_results()`

## 🔧 예제: 새 모듈 추가

### 예시: Threat Intelligence 모듈 추가

```bash
# 1. 폴더 구조 생성
mkdir modules/threat_intelligence
```

**`modules/threat_intelligence/__init__.py`**
```python
"""
Threat Intelligence 모듈

외부 위협 인텔리전스 소스와 연동하여 스캔 결과를 보강하는 기능을 제공합니다.
"""

from .threat_intelligence import ThreatIntelligenceAnalyzer, ThreatDatabase

__version__ = "1.0.0"
__author__ = "AI OSINT Team"

__all__ = [
    'ThreatIntelligenceAnalyzer',
    'ThreatDatabase'
]
```

**`modules/threat_intelligence/threat_intelligence.py`**
```python
"""
위협 인텔리전스 분석 모듈

작성일: 2024-01-01
버전: 1.0.0
"""

from typing import Dict, List, Any, Optional
import logging
from ..utils import ValidationUtils
from ..database import DatabaseManager

logger = logging.getLogger(__name__)


class ThreatIntelligenceAnalyzer:
    """위협 인텔리전스 분석기"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.validator = ValidationUtils()
    
    def analyze_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """IP 평판 분석"""
        if not self.validator.is_valid_ip(ip):
            raise ValueError("Invalid IP address")
        
        logger.info(f"Analyzing IP reputation for {ip}")
        
        # 구현 로직
        return {
            'ip': ip,
            'reputation': 'clean',
            'threat_score': 0,
            'sources': []
        }


class ThreatDatabase:
    """위협 데이터베이스 관리"""
    
    def __init__(self):
        self.db = DatabaseManager()
    
    def update_threat_feeds(self) -> bool:
        """위협 피드 업데이트"""
        logger.info("Updating threat intelligence feeds")
        # 구현 로직
        return True
```

**API 통합 (`modules/api/api_routes.py`)**
```python
# 새 API 엔드포인트 추가
@app.route('/threat-intelligence/ip/<ip>', methods=['GET'])
def analyze_ip_reputation(ip: str):
    try:
        from ..threat_intelligence import ThreatIntelligenceAnalyzer
        analyzer = ThreatIntelligenceAnalyzer()
        result = analyzer.analyze_ip_reputation(ip)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

## 📊 미래 확장 계획

### Phase 1: 보안 강화
- `modules/security/` - 인증, 권한 관리
- `modules/encryption/` - 데이터 암호화
- `modules/audit/` - 감사 로그

### Phase 2: 기능 확장
- `modules/reporting/` - 고급 보고서 생성
- `modules/notification/` - 알림 시스템
- `modules/scheduling/` - 스케줄링

### Phase 3: 통합 및 자동화
- `modules/orchestration/` - 워크플로우 관리
- `modules/ml_models/` - 머신러닝 모델
- `modules/threat_hunting/` - 위협 사냥

## 🚀 장점

### 1. **유지보수성**
- 기능별 분리로 코드 수정 범위 최소화
- 독립적인 테스트 및 배포 가능

### 2. **확장성**
- 새 기능 추가 시 기존 코드 영향 최소화
- 플러그인 형태의 확장 가능

### 3. **재사용성**
- 모듈 간 기능 재사용 용이
- 다른 프로젝트에서도 모듈 단위 재사용 가능

### 4. **팀워크**
- 모듈별로 담당자 분배 가능
- 병렬 개발 효율성 증대

이제 모든 새로운 기능들이 이 가이드라인을 따라 체계적으로 관리될 것입니다!