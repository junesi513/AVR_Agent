# 프롬프트 관리 시스템

## 📝 개요

`prompts.py` 파일은 취약점 분석을 위한 LLM 프롬프트를 체계적으로 관리하는 시스템입니다. 각 LLM의 특성에 맞춰 최적화된 프롬프트를 제공합니다.

## 🏗️ 구조

### **PromptManager 클래스**

각 LLM별로 최적화된 프롬프트를 제공하는 정적 메소드들:

| 메소드 | 대상 LLM | 설명 |
|--------|----------|------|
| `get_gpt_vulnerability_prompt()` | OpenAI GPT | 가장 상세한 7가지 취약점 유형 분석 |
| `get_gemini_vulnerability_prompt()` | Google Gemini | 4가지 핵심 확인사항 중심 |
| `get_ollama_vulnerability_prompt()` | Ollama/Qwen | 로컬 모델용 간결한 프롬프트 |
| `get_semgrep_rule_prompt()` | 규칙 생성 | Semgrep YAML 규칙 생성용 |
| `get_codeql_rule_prompt()` | 규칙 생성 | CodeQL 쿼리 생성용 |

### **PromptTemplates 클래스**

프롬프트에서 사용되는 상수들:

```python
SECURITY_EXPERT_ROLE = "당신은 Java 보안 전문가입니다."

COMMON_VULNERABILITIES = [
    "Null Pointer Dereference",
    "Type Confusion", 
    "Unsafe Deserialization",
    "Input Validation"
]

EXTENDED_VULNERABILITIES = COMMON_VULNERABILITIES + [
    "Buffer Overflow",
    "SQL Injection", 
    "Cross-Site Scripting (XSS)",
    "Path Traversal"
]
```

## 🎯 LLM별 프롬프트 특징

### **1. OpenAI GPT 프롬프트**
- **파일 위치**: `prompts.py` → `PromptManager.get_gpt_vulnerability_prompt()`
- **특징**: 
  - ✅ **7가지 취약점 유형** 포함 (가장 포괄적)
  - ✅ **상세한 메소드 정보** (수정자, 반환타입, 매개변수 분리)
  - ✅ **evidence 필드** 포함으로 근거 요구
  - ✅ **엄격한 JSON 형식** 지정

```python
# 사용 예시
func_info = {
    "name": "deserialze",
    "full_signature": "public <T> T deserialze(...)",
    "modifiers": ["public"],
    "return_type": "<T> T",
    "parameters": ["DefaultJSONParser parser", "Type type", "Object fieldName"]
}
prompt = PromptManager.get_gpt_vulnerability_prompt(func_info)
```

### **2. Google Gemini 프롬프트**
- **파일 위치**: `prompts.py` → `PromptManager.get_gemini_vulnerability_prompt()`
- **특징**:
  - ✅ **4가지 핵심 확인사항** 중심
  - ✅ **간결한 구조**로 API 특성 고려
  - ✅ **한국어 설명** 명시적 요구
  - ✅ **Gemini API 제약** 고려한 최적화

```python
# 사용 예시
prompt = PromptManager.get_gemini_vulnerability_prompt(func_info)
```

### **3. Ollama (Qwen) 프롬프트**
- **파일 위치**: `prompts.py` → `PromptManager.get_ollama_vulnerability_prompt()`
- **특징**:
  - ✅ **4가지 취약점 유형**에 **한국어 설명** 병기
  - ✅ **단순하고 명확한 지시**로 로컬 모델 성능 고려
  - ✅ **JSON 추출 최적화** (start_idx, end_idx 사용)
  - ✅ **로컬 모델 한계** 고려한 설계

```python
# 사용 예시
prompt = PromptManager.get_ollama_vulnerability_prompt(func_info)
```

## 🔧 사용법

### **기본 사용**

```python
from prompts import PromptManager

# 메소드 정보 준비
func_info = {
    "name": "methodName",
    "full_signature": "public void methodName(String param)",
    "modifiers": ["public"],
    "return_type": "void",
    "parameters": ["String param"]
}

# LLM별 프롬프트 생성
gpt_prompt = PromptManager.get_gpt_vulnerability_prompt(func_info)
gemini_prompt = PromptManager.get_gemini_vulnerability_prompt(func_info)
ollama_prompt = PromptManager.get_ollama_vulnerability_prompt(func_info)
```

### **규칙 생성 프롬프트**

```python
# 취약점 가설 정보
hypothesis = {
    "vulnerabilities": [
        {
            "type": "NULL_POINTER_DEREFERENCE",
            "description": "Null 참조 가능성이 있습니다"
        }
    ]
}

# 규칙 생성 프롬프트
semgrep_prompt = PromptManager.get_semgrep_rule_prompt(1, "methodName", hypothesis)
codeql_prompt = PromptManager.get_codeql_rule_prompt(1, "methodName", hypothesis)
```

### **테스트 실행**

```bash
# 프롬프트 템플릿 테스트
python3 prompts.py

# 출력 예시:
# === 프롬프트 템플릿 테스트 ===
# 1. GPT 프롬프트:
# --------------------------------------------------
# 다음 Java 메소드를 분석하여...
```

## 📁 파일 구조

```
AVR/
├── prompts.py              # 프롬프트 관리 시스템 (NEW!)
├── llm_interfaces.py       # LLM 인터페이스 (프롬프트 분리됨)
├── vulnerability_analyzer.py  # 메인 분석 시스템
└── prompts_README.md       # 이 문서
```

## 🎯 장점

### **1. 관리 편의성**
- ✅ **중앙 집중식 관리**: 모든 프롬프트가 한 파일에
- ✅ **쉬운 수정**: 프롬프트 변경 시 한 곳만 수정
- ✅ **버전 관리**: Git으로 프롬프트 변경 이력 추적

### **2. 가독성 향상**
- ✅ **명확한 분리**: LLM 로직과 프롬프트 분리
- ✅ **타입별 그룹화**: LLM별로 프롬프트 정리
- ✅ **문서화**: 각 프롬프트의 목적과 특징 명시

### **3. 확장성**
- ✅ **새 LLM 추가**: 새로운 메소드만 추가하면 됨
- ✅ **프롬프트 실험**: A/B 테스트 쉽게 가능
- ✅ **템플릿 재사용**: 공통 부분을 상수로 관리

### **4. 테스트 용이성**
- ✅ **독립 실행**: `python3 prompts.py`로 바로 테스트
- ✅ **비교 분석**: 여러 LLM 프롬프트 한번에 확인
- ✅ **디버깅**: 프롬프트 문제 빠르게 발견

## 🔄 기존 시스템과의 통합

### **변경 전** (`llm_interfaces.py`)
```python
# 각 클래스 내부에 프롬프트가 하드코딩됨
def generate_vulnerability_hypothesis(self, func_info):
    prompt = f"""다음 Java 메소드를 분석하여...
    {func_name}
    {signature}
    ..."""  # 긴 프롬프트 코드
```

### **변경 후** (`llm_interfaces.py` + `prompts.py`)
```python
# llm_interfaces.py
from prompts import PromptManager

def generate_vulnerability_hypothesis(self, func_info):
    prompt = PromptManager.get_gpt_vulnerability_prompt(func_info)
    # 깔끔하고 명확함!
```

## 🚀 향후 확장 계획

1. **다국어 지원**: 영어, 일본어 프롬프트 추가
2. **도메인별 프롬프트**: 웹, 모바일, IoT 특화 프롬프트
3. **동적 프롬프트**: 코드 복잡도에 따른 적응형 프롬프트
4. **프롬프트 성능 측정**: 각 프롬프트의 효과 분석 시스템

---

이제 프롬프트 관리가 훨씬 체계적이고 유지보수하기 쉬워졌습니다! 🎉 