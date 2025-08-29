# AI OSINT 모듈 구조 (폴더 분리 버전)

## 모듈화 개요

기존의 단일 파일(app.py - 1033줄)에서 기능별로 폴더 구조로 분리된 모듈화된 구조로 리팩토링되었습니다.

## 📁 폴더 구조

```
AI_OSINT/
├── app.py                    # 메인 애플리케이션 (40줄)
├── requirements.txt          # 의존성 패키지
├── templates/               # HTML 템플릿
│   └── index.html
├── osint_results.db         # SQLite 데이터베이스
├── MODULE_STRUCTURE.md      # 이 문서
├── FASTNMAP_GUIDE.md       # FastNmap 사용 가이드
└── modules/                # 📦 메인 모듈 패키지
    ├── __init__.py
    ├── database/           # 🗄️ 데이터베이스 모듈
    │   ├── __init__.py
    │   └── database.py
    ├── scanner/            # 🔍 스캔 엔진 모듈
    │   ├── __init__.py
    │   └── scanner.py
    ├── api/               # 🌐 웹 API 모듈
    │   ├── __init__.py
    │   └── api_routes.py
    ├── config/            # ⚙️ 설정 관리 모듈
    │   ├── __init__.py
    │   └── scan_config.py
    ├── utils/             # 🛠️ 유틸리티 모듈
    │   ├── __init__.py
    │   └── utils.py
    └── ai/                # 🤖 AI 분석 모듈
        ├── __init__.py
        └── ai_analyzer.py
```

## 📋 각 모듈의 역할

### 1. 🏠 **app.py** - 메인 애플리케이션
- Flask 애플리케이션 팩토리 패턴 사용
- 모든 모듈을 통합하고 서버를 실행
- 메인 페이지 라우트만 포함

**주요 기능:**
- `create_app()`: 애플리케이션 생성 및 초기화
- `main()`: 서버 실행

### 2. 🗄️ **modules/database/** - 데이터베이스 모듈
- SQLite 데이터베이스 관리 전담
- 프로젝트 및 스캔 결과 CRUD 작업

**주요 클래스:**
- `DatabaseManager`: 데이터베이스 CRUD 작업

**주요 기능:**
- 프로젝트 관리 (생성, 조회, 수정, 삭제)
- 스캔 결과 저장 및 조회
- 통계 정보 생성

### 3. 🔍 **modules/scanner/** - 스캔 엔진 모듈
- 네트워크 스캔 및 보안 분석 엔진
- FastNmap 기능 포함

**주요 클래스:**
- `HostScanner`: 호스트 스캔 총괄
- `PortScanner`: 포트 스캔 (Nmap 활용)
- `WebScanner`: 웹 서비스 스캔 및 디렉터리 브루트포스
- `VulnerabilityScanner`: CVE 및 PoC 검색
- `NetworkAnalyzer`: 네트워크 토폴로지 분석
- `FastNmapScanner`: 고속 2단계 Nmap 스캔

**주요 기능:**
- 서브도메인 탐색
- 포트 스캔 및 서비스 식별
- 웹 디렉터리 브루트포스
- 취약점 데이터베이스 조회
- 네트워크 라우팅 정보 분석
- **FastNmap**: 원본 bash 함수와 동일한 2단계 고속 스캔

### 4. 🌐 **modules/api/** - 웹 API 모듈
- REST API 엔드포인트 관리
- FastNmap API 포함

**주요 클래스:**
- `APIRoutes`: Flask 라우트 등록 및 API 핸들러
- `ScanManager`: 스캔 작업 관리 및 스레드 처리

**주요 기능:**
- 프로젝트 관리 API
- 스캔 시작 및 상태 조회 API
- 단일/대량 스캔 처리
- **FastNmap API**: `/fastnmap`, `/fastnmap/batch`, `/fastnmap/profiles`

### 5. ⚙️ **modules/config/** - 설정 관리 모듈
- 스캔 설정 및 프로파일 관리
- FastNmap 프로파일 설정

**주요 클래스:**
- `NmapConfig`: Nmap 스캔 설정 데이터 클래스
- `ScanConfigManager`: 설정 프로파일 관리
- `ScanSpeed`: 스캔 속도 열거형
- `PortRange`: 포트 범위 열거형

**사전 정의 프로파일:**
- `default`: 기본 설정 (T4, Top1000)
- `quick`: 빠른 스캔 (T5, Top100) 
- `comprehensive`: 전체 스캔 (T3, All ports)
- `stealth`: 스텔스 스캔 (T1, IDS 회피)
- `web_focused`: 웹 중심 스캔

### 6. 🛠️ **modules/utils/** - 유틸리티 모듈
- 공통 유틸리티 함수 모음

**주요 클래스:**
- `ValidationUtils`: 데이터 유효성 검사
- `NetworkUtils`: 네트워크 관련 유틸리티  
- `StringUtils`: 문자열 처리
- `SecurityUtils`: 보안 관련 유틸리티
- `FileUtils`: 파일 처리
- `DateUtils`: 날짜/시간 처리
- `ReportUtils`: 보고서 생성

### 7. 🤖 **modules/ai/** - AI 분석 모듈
- AI 기반 보안 분석 (기존 모듈 유지)
- 스캔 결과 분석 및 위협 인텔리전스 생성

**주요 클래스:**
- `AIAnalyzer`: AI 기반 결과 분석

## 🔗 모듈간 의존성

```
app.py
├── modules.database (DatabaseManager)
├── modules.api (APIRoutes, ScanManager)
├── modules.ai (add_ai_routes)
└── Flask, os

modules/api/
├── modules.database (DatabaseManager)
├── modules.utils (ValidationUtils)
├── modules.scanner (HostScanner, FastNmapScanner) [동적 import]
└── modules.config (config_manager, NmapConfig) [동적 import]

modules/scanner/
├── modules.config (NmapConfig, config_manager)
└── 표준 라이브러리 (subprocess, socket, requests 등)

modules/config/
└── 표준 라이브러리 (json, dataclass, enum)

modules/database/
└── 표준 라이브러리 (sqlite3, json, datetime)

modules/utils/
└── 표준 라이브러리 (re, ipaddress 등)

modules/ai/
└── 표준 라이브러리 (독립적)
```

## ⚡ 개선사항

### 1. 코드 구조 개선
- **패키지 구조**: 기능별 폴더 분리로 더 체계적인 관리
- **네임스페이스**: 각 모듈이 독립적인 네임스페이스 보유
- **모듈 로딩**: `__init__.py`를 통한 깔끔한 import 구조

### 2. 유지보수성 향상
- **물리적 분리**: 관련 코드가 같은 폴더에 위치
- **명확한 책임**: 각 폴더가 특정 도메인 담당
- **독립적 개발**: 각 모듈을 독립적으로 개발/테스트 가능

### 3. 확장성 개선
- **새로운 모듈 추가**: 새 폴더 생성으로 기능 확장 용이
- **플러그인 구조**: 각 모듈이 플러그인처럼 동작
- **버전 관리**: 모듈별 독립적인 버전 관리 가능

### 4. FastNmap 통합
- **설정 기반**: 5개 사전 정의 프로파일 + 커스텀 설정
- **API 통합**: 기존 API와 별도 FastNmap API 제공
- **성능 최적화**: 2단계 스캔으로 속도와 정확성 균형

## 🚀 사용법

### 기본 실행
```bash
python app.py
```

### 개발 모드
```bash
export FLASK_ENV=development
python app.py
```

### 모듈별 개별 사용
```python
# 데이터베이스만 사용
from modules.database import DatabaseManager
db = DatabaseManager()

# 스캐너만 사용  
from modules.scanner import HostScanner, FastNmapScanner
scanner = HostScanner()
fast_scanner = FastNmapScanner()

# 설정 관리
from modules.config import config_manager
profiles = config_manager.list_profiles()
```

### FastNmap 사용
```python
# 설정 기반 빠른 스캔
from modules.scanner import FastNmapScanner
scanner = FastNmapScanner()
result = scanner.fastnmap_scan('example.com', 'quick')
```

## 📝 마이그레이션 가이드

### 1. Import 경로 변경
```python
# 기존
from database import DatabaseManager
from scanner import HostScanner
from utils import ValidationUtils

# 변경 후
from modules.database import DatabaseManager
from modules.scanner import HostScanner  
from modules.utils import ValidationUtils
```

### 2. 새로운 기능 활용
```python
# FastNmap 기능
from modules.scanner import FastNmapScanner
from modules.config import config_manager

# 사전 정의 프로파일 사용
scanner = FastNmapScanner()
result = scanner.fastnmap_scan('target.com', 'comprehensive')

# 커스텀 프로파일 생성
from modules.config import NmapConfig
custom_config = NmapConfig(speed=ScanSpeed.INSANE, port_range=PortRange.CUSTOM)
config_manager.add_profile('my_profile', custom_config)
```

### 3. API 호환성
- **기존 API**: 모두 그대로 사용 가능
- **새로운 API**: FastNmap 관련 새 엔드포인트 추가
- **확장된 기능**: 기존 `/scan`에 `use_fastnmap` 옵션 추가

## 🔧 개발자 가이드

### 새 모듈 추가 방법
1. `modules/` 하위에 새 폴더 생성
2. `__init__.py` 파일 작성
3. 모듈 파일 작성
4. 필요시 `app.py`에서 import 및 등록

### 테스트 방법
```bash
# 개별 모듈 테스트
python -c "from modules.scanner import HostScanner; print('Scanner OK')"
python -c "from modules.config import config_manager; print('Config OK')"

# FastNmap 테스트
python -c "
from modules.scanner import FastNmapScanner
scanner = FastNmapScanner()
print('FastNmap OK')
"
```

## 📚 파일 정보

### 백업 및 문서
- **`app_backup.py`**: 기존 단일 파일 백업
- **`MODULE_STRUCTURE.md`**: 이 구조 설명서
- **`FASTNMAP_GUIDE.md`**: FastNmap 상세 사용법

### 설정 파일
- **`requirements.txt`**: Python 패키지 의존성
- **`scan_config.json`**: 사용자 정의 스캔 프로파일 (자동 생성)
- **`osint_results.db`**: SQLite 데이터베이스

### 출력 파일
- **`nmap_scans/`**: FastNmap 스캔 결과 저장 디렉터리 (자동 생성)

이제 더욱 체계적이고 확장 가능한 모듈 구조를 갖추었으며, FastNmap 기능까지 완벽하게 통합되었습니다!