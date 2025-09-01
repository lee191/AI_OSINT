# AI OSINT - 네트워크 보안 스캔 도구

FastNmap 2단계 스캐닝 방식을 활용한 고속 네트워크 보안 분석 도구입니다.

## 🚀 주요 특징

### ⚡ FastNmap 2단계 스캐닝
- **1단계**: 전체 포트 빠른 스캔 (`nmap -p- --min-rate=1000 -T4`)
- **2단계**: 발견된 열린 포트에 대한 상세 스캔 (`nmap -sCV -T4`)

### 🎯 통합 관리 시스템
- 프로젝트별 스캔 관리
- 스캔 이력 조회 및 관리
- 실시간 스캔 진행률 모니터링
- 직관적인 웹 인터페이스

### 🌐 웹 기반 다중 페이지
- **홈**: 대시보드 및 시작 페이지
- **프로젝트**: 프로젝트 생성 및 관리
- **스캐너**: 실시간 스캔 실행
- **스캔 이력**: 과거 스캔 결과 조회

## 📁 프로젝트 구조

```
AI_OSINT/
├── app.py                    # Flask 메인 애플리케이션
├── requirements.txt          # Python 의존성 패키지
├── osint_results.db         # SQLite 데이터베이스
├── templates/               # HTML 템플릿
│   ├── index.html          # 홈 페이지
│   ├── projects.html       # 프로젝트 관리
│   ├── scanner.html        # 스캔 실행
│   └── scan_history.html   # 스캔 이력
└── modules/                 # 모듈 패키지
    ├── api/                # 🌐 REST API
    ├── ai/                 # 🤖 AI 분석
    ├── config/             # ⚙️ 설정 관리
    ├── database/           # 🗄️ 데이터베이스 관리
    ├── project/            # 📁 프로젝트 관리
    ├── scanner/            # 🔍 스캔 엔진
    └── utils/              # 🛠️ 유틸리티
```

## 🛠️ 설치 및 실행

### 1. 필수 요구사항
```bash
# Python 3.7 이상
# Nmap 설치 (권장)
```

### 2. 의존성 설치
```bash
pip install -r requirements.txt
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

### 웹 인터페이스 사용
1. **프로젝트 생성**: `/projects` 페이지에서 새 프로젝트 생성
2. **스캔 실행**: `/scanner` 페이지에서 대상 입력 후 스캔 시작
3. **결과 확인**: `/scan-history` 페이지에서 스캔 이력 및 상세 결과 조회

### API 사용법

#### 스캔 시작
```bash
curl -X POST http://localhost:5002/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "project_id": 1}'
```

#### 스캔 상태 확인
```bash
curl http://localhost:5002/api/scans/{scan_id}/status
```

#### 스캔 결과 조회
```bash
curl http://localhost:5002/api/scans/{scan_id}
```

## 🗄️ 데이터베이스 구조

### Projects 테이블
- 프로젝트별 스캔 조직화
- 프로젝트명, 설명, 색상 태그

### Scan Results 테이블
- 모든 스캔 결과 저장
- 대상 도메인, IP, 포트 정보
- 서비스 정보 및 취약점 데이터
- JSON 형태 상세 정보

## 📊 스캔 결과 구조

```json
{
  "id": 1,
  "domain": "example.com",
  "ip_address": "192.0.2.1",
  "ports": [
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "scan_method": "fastnmap_2stage"
    }
  ],
  "services": [
    {
      "port": 80,
      "service": "http",
      "version": "Apache 2.4"
    }
  ],
  "scan_date": "2024-01-01 12:00:00",
  "project_id": 1,
  "status": "completed"
}
```

## 🌐 API 엔드포인트

### 프로젝트 관리
- `GET /api/projects` - 프로젝트 목록
- `POST /api/projects` - 새 프로젝트 생성
- `PUT /api/projects/{id}` - 프로젝트 수정
- `DELETE /api/projects/{id}` - 프로젝트 삭제

### 스캔 관리
- `GET /api/scans` - 스캔 목록 조회
- `POST /api/scans` - 새 스캔 시작
- `GET /api/scans/{id}` - 스캔 상세 조회
- `GET /api/scans/{id}/status` - 스캔 상태 확인

### AI 분석
- `GET /api/scans/{id}/analysis` - AI 분석 결과

## 🎨 주요 기능

### 프로젝트 관리
- 스캔을 프로젝트별로 그룹화
- 색상 코딩으로 시각적 구분
- 프로젝트별 통계 및 요약

### 스캔 이력 관리
- 시간순 스캔 결과 정렬
- 상세 모달로 결과 확인
- 프로젝트별 필터링

### 실시간 스캔
- WebSocket 기반 진행률 표시
- 실시간 로그 출력
- 스캔 중단 기능

## 🔒 보안 고려사항

### 방어적 목적 전용
이 도구는 다음 목적으로만 사용되어야 합니다:
- 자신이 소유한 시스템의 보안 점검
- 허가받은 모의해킹 테스트
- 보안 취약점 사전 탐지

### 주의사항
- 타인의 시스템을 무단으로 스캔하지 마세요
- 관련 법률과 규정을 준수하세요
- 발견된 정보를 악용하지 마세요

## 🛠️ 기술 스택

- **Backend**: Python Flask
- **Frontend**: HTML/CSS/JavaScript (Bootstrap)
- **Database**: SQLite
- **Scanning**: Nmap (FastNmap 방식)
- **Architecture**: 모듈화된 패키지 구조

## 🔧 환경 변수

```bash
# 디버그 모드 활성화
export FLASK_DEBUG=true

# 데이터베이스 경로 (선택사항)
export DATABASE_PATH=osint_results.db
```

## 📋 개발 로드맵

### 현재 버전 (v3.0)
- ✅ 웹 기반 다중 페이지 인터페이스
- ✅ 프로젝트 관리 시스템
- ✅ 스캔 이력 관리
- ✅ FastNmap 2단계 스캐닝

### 향후 계획
- 📊 대시보드 통계 및 차트
- 📧 이메일 알림 시스템
- 📅 스케줄링 기능
- 🔌 플러그인 시스템

## 🐛 문제 해결

### 일반적인 문제

**포트 5002 사용 중 오류**
```bash
# 기존 프로세스 확인
netstat -ano | findstr :5002
# 프로세스 종료
taskkill /PID [PID번호] /F
```

**Nmap 명령어 실행 오류**
- Nmap이 시스템 PATH에 포함되어 있는지 확인
- Windows: https://nmap.org/download.html

## 📜 라이선스

이 프로젝트는 방어적 보안 목적으로만 사용되어야 하며, 사용자는 관련 법률과 윤리 규정을 준수해야 합니다.

## 🤝 기여

버그 리포트나 기능 개선 제안은 이슈로 등록해주세요.

---
**AI OSINT Network Security Scanner** - 효율적이고 체계적인 네트워크 보안 분석 도구