# Fast Nmap 스캔 기능 가이드

## 개요

원본 `fastnmap()` bash 함수와 동일한 방식으로 작동하는 고속 Nmap 스캔 기능을 추가했습니다.

**원본 fastnmap 함수:**
```bash
fastnmap() {
    if [ -z "$1" ]; then
        echo "Usage: fastnmap <target-ip>"
        return 1
    fi
    ports=$(nmap -p- --min-rate=1000 -T4 "$1" | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
    echo "[*] Open ports: $ports"
    nmap -p"$ports" -sC -sV "$1" -oA "scan_$1"
}
```

## 주요 특징

### ✅ **2단계 스캔 방식** (원본과 동일)
1. **1단계**: 빠른 포트 발견 (`--min-rate`, `-T4`)
2. **2단계**: 발견된 포트에 대한 상세 스캔 (`-sC`, `-sV`)

### ⚡ **설정 기반 성능 조정**
- **속도 설정**: `T1` (느림) ~ `T5` (매우 빠름)
- **포트 범위**: Top100, Top1000, 전체 포트, 커스텀
- **병렬 처리**: 최대 동시 스캔 수 조정

### 🎯 **사전 정의된 프로파일**

| 프로파일 | 설명 | 속도 | 포트 범위 | 용도 |
|----------|------|------|-----------|------|
| `default` | 기본 설정 | T4 | Top1000 | 일반적인 스캔 |
| `quick` | 빠른 스캔 | T5 | Top100 | 빠른 개요 확인 |
| `comprehensive` | 전체 스캔 | T3 | 전체(1-65535) | 상세한 분석 |
| `stealth` | 스텔스 스캔 | T1 | 일반 포트 | IDS 회피 |
| `web_focused` | 웹 중심 | T4 | 웹 포트만 | 웹 애플리케이션 |

## API 사용법

### 1. 단일 타겟 FastNmap 스캔

```bash
curl -X POST http://localhost:5002/fastnmap \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "profile": "quick"
  }'
```

**응답:**
```json
{
  "scan_id": "fastnmap_1703123456",
  "target": "example.com",
  "profile": "quick",
  "status": "started"
}
```

### 2. 배치 FastNmap 스캔

```bash
curl -X POST http://localhost:5002/fastnmap/batch \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.1", "192.168.1.2", "example.com"],
    "profile": "default",
    "max_concurrent": 3
  }'
```

### 3. 기존 스캔에 FastNmap 적용

```bash
curl -X POST http://localhost:5002/scan \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["example.com"],
    "use_fastnmap": true,
    "nmap_profile": "comprehensive"
  }'
```

### 4. 스캔 프로파일 관리

**프로파일 조회:**
```bash
curl http://localhost:5002/fastnmap/profiles
```

**커스텀 프로파일 생성:**
```bash
curl -X POST http://localhost:5002/fastnmap/profiles \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my_custom",
    "config": {
      "speed": "fast",
      "port_range": "custom",
      "custom_ports": "22,80,443,8080,8443",
      "min_rate": 2000,
      "service_version": true,
      "script_scan": true
    }
  }'
```

**프로파일 삭제:**
```bash
curl -X DELETE http://localhost:5002/fastnmap/profiles/my_custom
```

### 5. 스캔 결과 조회

```bash
# 스캔 상태 확인
curl http://localhost:5002/scan/fastnmap_1703123456/status

# 스캔 결과 조회
curl http://localhost:5002/scan/fastnmap_1703123456/results
```

## 설정 옵션

### NmapConfig 파라미터

```python
{
  "speed": "fast",              # slow, normal, fast, insane
  "port_range": "top_1000",     # top_100, top_1000, common, all, custom
  "custom_ports": "22,80,443",  # custom 포트 범위일 때
  "min_rate": 1000,             # 최소 패킷 전송 속도
  "max_rate": 5000,             # 최대 패킷 전송 속도
  "service_version": true,      # -sV 서비스 버전 탐지
  "script_scan": true,          # -sC 스크립트 스캔
  "os_detection": false,        # -O OS 탐지
  "aggressive": false,          # -A 공격적 스캔
  "host_timeout": 300,          # 호스트 타임아웃(초)
  "scan_timeout": 600,          # 전체 스캔 타임아웃(초)
  "save_output": true,          # 파일 저장 여부
  "output_format": ["normal", "json"],  # 출력 형식
  "parallel_scan": true,        # 병렬 스캔
  "max_parallel_hosts": 5,      # 최대 병렬 호스트
  "stealth_mode": false         # 스텔스 모드 (-sS)
}
```

## 실행 예시

### 1. 빠른 개요 스캔
```bash
# 상위 100개 포트만 빠르게 스캔
curl -X POST http://localhost:5002/fastnmap \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "profile": "quick"}'
```

**결과:**
```
[*] Starting fast port discovery on 192.168.1.1
[*] Running command: nmap --top-ports 100 --min-rate=5000 -T5 192.168.1.1
[*] Open ports found: 22,80,443
[*] Starting detailed scan on discovered ports
[*] Running detailed scan: nmap -p22,80,443 -T5 --min-rate=5000 192.168.1.1
[*] Scan completed in 3.45 seconds
```

### 2. 전체 포트 상세 스캔
```bash
# 모든 포트 스캔 (느리지만 완전함)
curl -X POST http://localhost:5002/fastnmap \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "profile": "comprehensive"}'
```

### 3. 웹 서버 집중 스캔
```bash
# 웹 관련 포트만 스캔
curl -X POST http://localhost:5002/fastnmap \
  -H "Content-Type: application/json" \
  -d '{"target": "web.example.com", "profile": "web_focused"}'
```

## 출력 파일

스캔 결과는 `nmap_scans/` 디렉터리에 저장됩니다:

```
nmap_scans/
├── scan_example.com_1703123456.json    # JSON 형식
└── scan_example.com_1703123456.txt     # 텍스트 형식
```

**JSON 출력 예시:**
```json
{
  "target": "example.com",
  "profile": "default",
  "status": "completed",
  "scan_time": 15.67,
  "open_ports": [22, 80, 443],
  "detailed_results": {
    "ports": [
      {
        "port": 22,
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH 7.4"
      }
    ],
    "services": [...]
  }
}
```

## 성능 비교

| 방식 | 시간 | 포트 범위 | 정확도 | 용도 |
|------|------|-----------|--------|------|
| **quick** | ~5초 | Top100 | 높음 | 빠른 개요 |
| **default** | ~30초 | Top1000 | 매우 높음 | 일반 스캔 |
| **comprehensive** | ~300초 | 전체 | 완전함 | 상세 분석 |
| **stealth** | ~600초 | 일반 | 높음 | IDS 회피 |

## 에러 처리

### 자동 폴백 기능
FastNmap이 실패할 경우 자동으로 기본 스캔으로 전환:

```json
{
  "fallback_to_basic": true,
  "fast_scan_error": "Nmap command failed",
  "ports": [...],  // 기본 스캔 결과
}
```

### 일반적인 에러 상황
1. **Nmap 없음**: 기본 포트 스캔으로 폴백
2. **권한 부족**: `--unprivileged` 옵션 자동 추가
3. **타임아웃**: 설정된 시간 내 완료되지 않음
4. **잘못된 타겟**: IP/도메인 형식 검증 실패

## 모니터링

### 실시간 진행 상황
```bash
# 스캔 진행 상황 모니터링
while true; do
  curl -s http://localhost:5002/scan/fastnmap_1703123456/status | jq '.status'
  sleep 2
done
```

### 배치 스캔 상태
```bash
# 배치 스캔의 각 타겟별 상태
curl http://localhost:5002/scan/fastnmap_batch_1703123456/status | jq '.results'
```

## 팁과 권장사항

### 🎯 **프로파일 선택 가이드**
- **정찰 초기**: `quick` 프로파일로 빠른 개요
- **일반 스캔**: `default` 프로파일
- **침투 테스트**: `comprehensive` 프로파일
- **IDS 회피**: `stealth` 프로파일
- **웹 앱 테스트**: `web_focused` 프로파일

### ⚡ **성능 최적화**
- `min_rate`를 높여 속도 향상 (네트워크 안정성 필요)
- `max_parallel_hosts`로 동시 스캔 수 조정
- `host_timeout` 단축으로 응답 없는 호스트 빠르게 넘김

### 🔒 **보안 고려사항**
- 스텔스 모드에서는 `-sS` (SYN 스캔) 사용
- 타이밍 템플릿 `T1`로 IDS 탐지 회피
- `min_rate`를 낮춰 트래픽 양 조절

## 문제 해결

### 1. Nmap이 설치되지 않음
```bash
# Ubuntu/Debian
sudo apt-get install nmap

# CentOS/RHEL
sudo yum install nmap

# Windows
# https://nmap.org/download.html 에서 다운로드
```

### 2. 권한 문제
- Windows: 관리자 권한으로 실행
- Linux: `sudo`로 실행 또는 `--unprivileged` 사용

### 3. 방화벽 차단
- 아웃바운드 연결 허용 확인
- 타겟 네트워크 방화벽 설정 확인

### 4. 성능 이슈
- `min_rate` 값 조정
- `max_parallel_hosts` 감소
- 네트워크 대역폭 확인