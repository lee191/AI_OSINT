# AI OSINT - FastNmap Scanner

FastNmap 2단계 스캐닝 방식을 활용한 고속 네트워크 보안 분석 도구입니다.

## 🚀 주요 특징

### ⚡ FastNmap 2단계 스캐닝
원본 bash fastnmap 함수와 동일한 방식으로 작동:
1. **1단계**: 전체 포트 빠른 스캔 (`nmap -p- --min-rate=1000 -T4`)
2. **2단계**: 발견된 열린 포트에 대한 상세 스캔 (`nmap -sCV -T4`)

### 🎯 단순하고 깔끔한 결과
- 입력된 호스트만 직접 스캔
- 체계적으로 정리된 스캔 결과
- 포트별 서비스 정보 및 분류
- 중요 서비스 자동 식별

### 🌐 웹 기반 인터페이스
- 직관적인 웹 UI
- 실시간 스캔 진행률 모니터링
- JSON API 지원

## 📁 모듈화된 구조

```
AI_OSINT/
├── app.py                    # Flask 애플리케이션
├── requirements.txt          # 의존성 패키지
├── templates/index.html      # 웹 인터페이스
├── osint_results.db         # SQLite 데이터베이스
└── modules/                 # 모듈 패키지
    ├── database/           # 🗄️ 데이터베이스 관리
    ├── scanner/            # 🔍 FastNmap 스캔 엔진
    ├── api/               # 🌐 REST API
    ├── config/            # ⚙️ 설정 관리
    ├── utils/             # 🛠️ 유틸리티 함수
    └── ai/                # 🤖 AI 분석 (확장 기능)
```

## 🛠️ 설치 및 실행

### 1. 의존성 설치
```bash
pip install -r requirements.txt
```

### 2. Nmap 설치 (권장)
```bash
# Windows: https://nmap.org/download.html
# Linux: sudo apt-get install nmap  
# macOS: brew install nmap
```

### 3. 애플리케이션 실행
```bash
python app.py
```

### 4. 웹 브라우저에서 접속
```
http://localhost:5002
```

## 📖 사용법

### 웹 인터페이스
1. 스캔할 도메인/IP 주소 입력
2. "스캔 시작" 버튼 클릭  
3. 실시간 진행률 확인
4. 스캔 완료 후 결과 조회

### API 사용법

#### 스캔 시작
```bash
curl -X POST http://localhost:5002/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"], "bulk_mode": false}'
```

#### 스캔 상태 확인
```bash
curl http://localhost:5002/scan/{scan_id}/status
```

#### 스캔 결과 조회
```bash
curl http://localhost:5002/scan/{scan_id}/results
```

## 📊 스캔 결과 구조

```json
{
  "target": "example.com",
  "ip": "192.0.2.1", 
  "scan_method": "FastNmap 2-Stage",
  "scan_time": "2024-01-01 12:00:00",
  "open_ports_count": 3,
  "total_ports_scanned": 3,
  "ports": [
    {
      "port": 22,
      "protocol": "tcp", 
      "state": "open",
      "service": "ssh"
    }
  ],
  "services": [
    {
      "port": 22,
      "service": "ssh",
      "version": "OpenSSH 7.4"
    }
  ],
  "scan_summary": {
    "status": "completed",
    "open_ports": ["22/tcp (ssh)", "80/tcp (http)", "443/tcp (https)"],
    "critical_services": ["ssh"],
    "web_services": ["http:80", "https:443"],
    "common_services": ["ssh:22", "http:80", "https:443"]
  }
}
```

## 🗄️ 데이터베이스

### 프로젝트 관리
- 스캔을 프로젝트별로 조직화
- 프로젝트 생성, 수정, 삭제
- 프로젝트별 스캔 기록 관리

### 스캔 결과 저장
- 모든 스캔 결과 자동 저장
- SQLite 데이터베이스 사용
- JSON 형태로 상세 정보 보관

## 🌐 API 엔드포인트

### 프로젝트 관리
- `GET /projects` - 프로젝트 목록
- `POST /projects` - 새 프로젝트 생성
- `PUT /projects/{id}` - 프로젝트 수정
- `DELETE /projects/{id}` - 프로젝트 삭제

### 스캔 관리
- `POST /scan` - 스캔 시작
- `GET /scan/{scan_id}/status` - 스캔 상태
- `GET /scan/{scan_id}/results` - 스캔 결과

### AI 분석 (확장 기능)
- `GET /scan/{scan_id}/analysis` - AI 분석 결과
- `GET /scan/{scan_id}/report` - 종합 보고서

## 🏗️ 개발 가이드라인

### 모듈 설계 원칙
1. **단일 책임 원칙**: 각 모듈은 명확한 하나의 책임
2. **폴더 기반 구조**: `modules/` 하위의 독립적인 폴더
3. **표준화된 구조**: `__init__.py`, 메인 구현 파일, 유틸리티

### 새 모듈 추가 방법
```bash
mkdir modules/[기능명]
touch modules/[기능명]/__init__.py
touch modules/[기능명]/[기능명].py
```

### 모듈 카테고리
- **Core Modules**: database, scanner, api, utils
- **Feature Modules**: ai, config
- **Integration Modules**: exporters, parsers (미래 확장)
- **Extension Modules**: plugins, custom (미래 확장)

## 🔒 보안 고려사항

### 방어적 목적 전용
- 자신이 소유한 시스템의 보안 점검
- 허가받은 모의해킹 테스트  
- 보안 취약점 사전 탐지

### 주의사항
- 타인의 시스템을 무단으로 스캔하지 마세요
- 관련 법률과 규정을 준수하세요
- 발견된 정보를 악용하지 마세요

## 🛠️ 기술 스택

- **Backend**: Python Flask
- **Frontend**: HTML/CSS/JavaScript
- **Database**: SQLite
- **Scanning**: Nmap (FastNmap 방식)
- **Architecture**: 모듈화된 패키지 구조

## 🔄 마이그레이션 히스토리

### v2.0 - FastNmap 전용 단순화
- 기존 복잡한 스캐닝 기능 제거
- FastNmap 2단계 스캐닝에 집중
- 모듈화된 폴더 구조 적용
- 깔끔한 결과 포맷

### v1.0 - 종합 보안 분석 도구
- 서브도메인 탐색
- 취약점 분석 (CVE)
- PoC 코드 검색
- AI 기반 분석

## 📋 미래 확장 계획

### Phase 1: 성능 최적화
- 스캔 속도 개선
- 메모리 사용량 최적화  
- 에러 처리 강화

### Phase 2: 기능 확장 
- 보고서 생성 모듈
- 알림 시스템
- 스케줄링 기능

### Phase 3: 통합 및 자동화
- 워크플로우 관리
- API 통합 개선
- 플러그인 시스템

## 📜 라이선스

이 프로젝트는 방어적 보안 목적으로만 사용되어야 하며, 사용자는 관련 법률과 윤리 규정을 준수해야 합니다.

## 🤝 기여

버그 리포트나 기능 개선 제안은 이슈로 등록해주세요.

---
**AI OSINT FastNmap Scanner** - 빠르고 정확한 네트워크 보안 분석을 위한 도구