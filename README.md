# 취약점 분석 및 수정 Agent (AVR)

Java 소스코드의 취약점을 자동으로 분석하고 패치를 생성하는 AI 기반 시스템입니다.

## 🚀 주요 기능

### Stage 1: 사전 작업
- AST(Abstract Syntax Tree) 노드 추출
- 함수/클래스 단위로 코드 분리
- 메타데이터 수집

### Stage 2: 취약점 분석
1. **LLM 기반 취약점 가설 생성** - GPT, Gemini, Qwen 등 다양한 LLM 지원
2. **정적 분석 규칙 자동 생성** - Semgrep, CodeQL 규칙 생성
3. **취약점 검증** - 생성된 규칙으로 취약점 확인

### Stage 3: 패치 생성
- 검증된 취약점에 대한 자동 패치 코드 생성
- 보안 모범 사례 적용

## 🛠️ 설치 및 설정

### 1. 종속성 설치
```bash
pip install -r requirements.txt
```

### 2. LLM 설정
```bash
# LLM 설정 파일 템플릿 생성
python run_analysis.py --create-config

# 생성된 llm_config.json 파일에서 API 키 설정
```

### 3. 디렉토리 구조
```
AVR/
├── benchmark/Java/VUL4J/VUL4J-1/    # 분석 대상 Java 파일
├── log/                             # 로그 파일 저장
├── rule/                           # 생성된 규칙 파일 저장
├── vulnerability_analyzer.py        # 메인 분석 시스템
├── llm_interfaces.py               # LLM 인터페이스
└── run_analysis.py                 # 실행 스크립트
```

## 📖 사용법

### 기본 실행
```bash
python run_analysis.py
```

### 다양한 옵션
```bash
# 특정 취약점 ID 분석
python run_analysis.py --vuln-id 1

# GPT 사용
python run_analysis.py --llm-type gpt --api-key YOUR_OPENAI_API_KEY

# Gemini 사용
python run_analysis.py --llm-type gemini --api-key YOUR_GEMINI_API_KEY

# Ollama/Qwen 사용 (로컬)
python run_analysis.py --llm-type ollama --model qwen:7b

# 설정 파일 사용
python run_analysis.py --config llm_config.json
```

## 🔧 LLM 설정

### OpenAI GPT
```json
{
  "type": "gpt",
  "model": "gpt-4",
  "api_key": "your_openai_api_key",
  "temperature": 0.1
}
```

### Google Gemini
```json
{
  "type": "gemini",
  "model": "gemini-pro", 
  "api_key": "your_gemini_api_key",
  "temperature": 0.1
}
```

### Ollama (로컬)
```json
{
  "type": "ollama",
  "model": "qwen:7b",
  "base_url": "http://localhost:11434",
  "temperature": 0.1
}
```

## 📊 출력 결과

### 1. 로그 파일
- 위치: `./log/vulnerability_analyzer_YYYYMMDD_HHMMSS.log`
- 내용: 분석 과정의 상세 로그

### 2. 분석 결과
- 위치: `./log/analysis_result_ID_YYYYMMDD_HHMMSS.json`
- 내용: 발견된 취약점, 생성된 패치 등 전체 결과

### 3. 규칙 파일
- Semgrep: `./rule/semgrep{id}-{function_name}`
- CodeQL: `./rule/codeql{id}-{function_name}`

## 🔍 지원하는 취약점 유형

1. **Null Pointer Dereference** - null 값 참조로 인한 오류
2. **Type Confusion** - 잘못된 타입 캐스팅
3. **Unsafe Deserialization** - 안전하지 않은 역직렬화
4. **Input Validation** - 입력 검증 부족
5. **Buffer Overflow** - 버퍼 오버플로우
6. **SQL Injection** - SQL 인젝션
7. **Cross-Site Scripting (XSS)** - XSS 공격
8. **Path Traversal** - 경로 순회 공격

## 🎯 예시 결과

```
🚀 취약점 분석 시작 - VUL4J-1
📁 대상 경로: ./benchmark/Java/VUL4J/VUL4J-1/
🤖 LLM: ollama (qwen:7b)

✅ 분석 완료!
🔍 발견된 취약점: 2개
🔧 생성된 패치: 2개

📋 취약점 요약:
  1. deserialze - high 심각도
     • UNSAFE_DESERIALIZATION: 안전하지 않은 역직렬화 취약점
     • TYPE_CONFUSION: 타입 캐스팅 관련 Type Confusion 취약점

📝 생성된 규칙 파일 (4개):
  • ./rule/semgrep1-deserialze
  • ./rule/codeql1-deserialze
  • ./rule/semgrep1-toObjectArray
  • ./rule/codeql1-toObjectArray

📄 상세 결과: ./log/analysis_result_1_*.json
```

## 🔧 확장 방법

### 새로운 LLM 추가
1. `llm_interfaces.py`에 새로운 LLM 클래스 구현
2. `LLMFactory`에 생성 로직 추가
3. 설정 파일에 새로운 LLM 옵션 추가

### 새로운 취약점 유형 추가
1. `VulnerabilityDetector.generate_hypothesis()` 메소드 수정
2. `generate_semgrep_rule()`, `generate_codeql_rule()` 메소드에 규칙 추가
3. `PatchGenerator.generate_patch()` 메소드에 패치 로직 추가

## 📋 TODO

- [ ] 더 정교한 AST 파싱 (JavaParser 라이브러리 사용)
- [ ] 추가 취약점 유형 지원
- [ ] 패치 검증 시스템
- [ ] 웹 UI 인터페이스
- [ ] 배치 처리 모드
- [ ] 성능 최적화

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 🤝 기여

버그 리포트, 기능 요청, 풀 리퀘스트를 환영합니다!

## 📞 지원

문제가 발생하면 이슈를 생성해주세요. 