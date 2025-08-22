# AI OSINT Scanner

지능형 도메인 보안 분석 도구입니다. 입력된 도메인에 대해 서브도메인 탐색, 포트 스캔, 취약점 분석, AI 기반 보안 평가를 수행합니다.

## 주요 기능

### 1. 서브도메인 자동 탐색
- Subfinder 도구 활용 (설치되어 있는 경우)
- 일반적인 서브도메인 브루트포스 공격
- DNS 조회를 통한 유효한 서브도메인 확인

### 2. 포트 스캔 및 서비스 탐지
- Nmap 스크립트 실행 (설치되어 있는 경우)
- 기본 포트 스캔 (nmap 미설치시)
- 서비스 버전 탐지
- 웹 포트 접속 가능성 확인

### 3. 취약점 분석
- CVE 데이터베이스 연동
- NVD API를 통한 취약점 정보 수집
- CVSS 점수 기반 위험도 평가

### 4. PoC 코드 검색
- GitHub API를 통한 공개 PoC 코드 검색
- Exploit-DB 연동
- 취약점별 PoC 코드 자동 저장

### 5. AI 기반 보안 분석
- 스캔 결과 종합 분석
- 위험도 점수 자동 계산
- 공격 시나리오 생성
- 우선순위별 수정 권장사항 제공
- 경영진용 요약 보고서 생성

## 설치 및 실행

### 1. 의존성 설치
```bash
pip install -r requirements.txt
```

### 2. 선택사항 (성능 향상을 위해 권장)
```bash
# Subfinder 설치 (서브도메인 탐색 성능 향상)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Nmap 설치 (포트 스캔 성능 향상)
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

## 사용법

1. 웹 인터페이스에서 스캔할 도메인 입력
2. "스캔 시작" 버튼 클릭
3. 스캔 진행상황 실시간 모니터링
4. 결과 확인:
   - **스캔 결과**: 상세한 기술적 정보
   - **AI 분석**: 지능형 보안 분석 결과
   - **경영진 보고서**: 요약된 보안 현황

## 데이터베이스

스캔 결과는 SQLite 데이터베이스(`osint_results.db`)에 자동 저장됩니다.

### 테이블 구조
- `scan_results`: 스캔 결과 저장
  - 도메인, 서브도메인, IP 주소
  - 열린 포트, 서비스 정보
  - 발견된 취약점, PoC 코드
  - 스캔 날짜/시간

## API 엔드포인트

### 스캔 관련
- `POST /scan`: 새로운 스캔 시작
- `GET /scan/<scan_id>/status`: 스캔 진행상황 확인
- `GET /scan/<scan_id>/results`: 스캔 결과 조회

### AI 분석
- `GET /scan/<scan_id>/analysis`: AI 분석 결과 조회
- `GET /scan/<scan_id>/report`: 종합 보고서 생성

## 보안 고려사항

### 방어적 목적 전용
이 도구는 **방어적 보안 목적**으로만 사용되어야 합니다:
- 자신이 소유한 시스템의 보안 점검
- 허가받은 모의해킹 테스트
- 보안 취약점 사전 탐지

### 주의사항
- 타인의 시스템을 무단으로 스캔하지 마세요
- 관련 법률과 규정을 준수하세요
- 발견된 취약점을 악용하지 마세요

## 파일 구조

```
AI_OSINT/
├── app.py                 # 메인 Flask 애플리케이션
├── ai_analyzer.py         # AI 분석 엔진
├── requirements.txt       # Python 의존성
├── README.md             # 사용 설명서
├── templates/
│   └── index.html        # 웹 인터페이스
├── static/
│   └── style.css         # 추가 스타일
└── osint_results.db      # SQLite 데이터베이스 (자동 생성)
```

## 기술 스택

- **Backend**: Python Flask
- **Frontend**: HTML/CSS/JavaScript
- **Database**: SQLite
- **External APIs**: 
  - NVD (National Vulnerability Database)
  - GitHub API
- **Tools Integration**: 
  - Nmap (포트 스캔)
  - Subfinder (서브도메인 탐색)

## 라이선스

이 프로젝트는 방어적 보안 목적으로만 사용되어야 하며, 사용자는 관련 법률과 윤리 규정을 준수해야 합니다.

## 기여

버그 리포트나 기능 개선 제안은 이슈로 등록해주세요.