"""
LLM 프롬프트 템플릿 관리 시스템

각 LLM별로 최적화된 프롬프트를 제공합니다.
"""

from typing import Dict, Any


class PromptManager:
    """프롬프트 템플릿 관리 클래스"""
    
    @staticmethod
    def get_gpt_vulnerability_prompt(func_info: Dict[str, Any]) -> str:
        """OpenAI GPT용 취약점 분석 프롬프트"""
        func_name = func_info.get("name", "unknown")
        signature = func_info.get("full_signature", "")
        modifiers = func_info.get("modifiers", [])
        return_type = func_info.get("return_type", "")
        parameters = func_info.get("parameters", [])
        implementation = func_info.get("implementation", "")
        
        return f"""Analyze the following Java method to identify potential security vulnerabilities:

Method Name: {func_name}
Signature: {signature}
Modifiers: {', '.join(modifiers)}
Return Type: {return_type}
Parameters: {', '.join(parameters)}

Implementation:
```java
{implementation}
```

Analyze for the following vulnerability types:
1. Null Pointer Dereference
2. Type Confusion
3. Unsafe Deserialization

Please respond in the following JSON format:
{{
    "vulnerabilities": [
        {{
            "type": "vulnerability_type",
            "description": "vulnerability description",
            "severity": "low|medium|high|critical",
            "confidence": 0.0-1.0,
            "evidence": "evidence for the vulnerability"
        }}
    ]
}}

Return an empty array if no vulnerabilities are found."""

    @staticmethod
    def get_gemini_vulnerability_prompt(func_info: Dict[str, Any]) -> str:
        """Google Gemini용 취약점 분석 프롬프트"""
        func_name = func_info.get("name", "unknown")
        signature = func_info.get("full_signature", "")
        implementation = func_info.get("implementation", "")
        
        return f"""As a Java security expert, analyze the following method for security vulnerabilities:

Method: {func_name}
Signature: {signature}

Implementation:
```java
{implementation}
```

Key areas to check:
- Null pointer dereference possibilities
- Type safety issues
- Unsafe deserialization vulnerabilities

Return the result in JSON format:
{{
    "vulnerabilities": [
        {{
            "type": "vulnerability_type",
            "description": "detailed description",
            "severity": "low|medium|high|critical", 
            "confidence": 0.8
        }}
    ]
}}"""

    @staticmethod
    def get_ollama_vulnerability_prompt(func_info: Dict[str, Any]) -> str:
        """Ollama (Qwen 등) 로컬 모델용 취약점 분석 프롬프트"""
        func_name = func_info.get("name", "unknown")
        signature = func_info.get("full_signature", "")
        implementation = func_info.get("implementation", "")
        
        return f"""You are a Java security expert. Analyze the following method for security vulnerabilities.

Method Name: {func_name}
Method Signature: {signature}

Implementation:
```java
{implementation}
```

Vulnerability types to analyze:
1. Null Pointer Dereference - errors from null value references
2. Type Confusion - incorrect type casting
3. Unsafe Deserialization - insecure deserialization

Output the result in the following JSON format:
{{
    "vulnerabilities": [
        {{
            "type": "vulnerability_type",
            "description": "description",
            "severity": "low|medium|high|critical",
            "confidence": 0.7
        }}
    ]
}}

Return an empty array if no vulnerabilities are found."""

    @staticmethod
    def get_semgrep_rule_prompt(vuln_id: int, func_name: str, hypothesis: Dict[str, Any]) -> str:
        """Semgrep 규칙 생성용 프롬프트"""
        vuln_type = hypothesis["vulnerabilities"][0]["type"]
        description = hypothesis["vulnerabilities"][0]["description"]
        
        return f"""Generate a Semgrep rule for the following vulnerability:

Vulnerability Type: {vuln_type}
Function Name: {func_name}
Description: {description}

Please write the rule in Semgrep YAML format. Example:
rules:
  - id: vuln-{vuln_id}-{func_name.lower()}
    message: {description}
    severity: WARNING
    languages: [java]
    pattern-either:
      - pattern: |
          $METHOD(...) {{
            ...
            $VAR.$CALL(...)
            ...
          }}
    metadata:
      category: security
      technology: [java]
      confidence: MEDIUM"""

    @staticmethod
    def get_codeql_rule_prompt(vuln_id: int, func_name: str, hypothesis: Dict[str, Any]) -> str:
        """CodeQL 규칙 생성용 프롬프트"""
        vuln_type = hypothesis["vulnerabilities"][0]["type"]
        description = hypothesis["vulnerabilities"][0]["description"]
        
        return f"""Generate a CodeQL query for the following vulnerability:

Vulnerability Type: {vuln_type}
Function Name: {func_name}
Description: {description}

Please write the query in CodeQL format. Example:
/**
 * @name {description}
 * @description Detect {vuln_type} vulnerability in {func_name} function
 * @kind problem
 * @problem.severity warning
 * @id java/vuln-{vuln_id}-{func_name.lower()}
 */

import java

from Method method, MethodAccess call
where
  method.getName() = "{func_name}" and
  call.getEnclosingCallable() = method
select call, "{description}"
"""


# Prompt template constants
class PromptTemplates:
    """프롬프트 템플릿 상수"""
    
    # Basic role definition
    SECURITY_EXPERT_ROLE = "You are a Java security expert."
    
    # Core vulnerability types (3 types only)
    CORE_VULNERABILITIES = [
        "Null Pointer Dereference",
        "Type Confusion", 
        "Unsafe Deserialization"
    ]
    
    # JSON response format
    JSON_RESPONSE_FORMAT = '''{{
    "vulnerabilities": [
        {{
            "type": "vulnerability_type",
            "description": "vulnerability description",
            "severity": "low|medium|high|critical",
            "confidence": 0.0-1.0
        }}
    ]
}}'''


# Prompt utility functions
def format_method_info(func_info: Dict[str, Any]) -> str:
    """메소드 정보를 문자열로 포맷팅"""
    func_name = func_info.get("name", "unknown")
    signature = func_info.get("full_signature", "")
    modifiers = func_info.get("modifiers", [])
    return_type = func_info.get("return_type", "")
    parameters = func_info.get("parameters", [])
    
    return f"""Method Name: {func_name}
Signature: {signature}
Modifiers: {', '.join(modifiers)}
Return Type: {return_type}
Parameters: {', '.join(parameters)}"""


def get_vulnerability_list_text(detailed: bool = False) -> str:
    """취약점 목록을 텍스트로 변환"""
    vulnerabilities = PromptTemplates.CORE_VULNERABILITIES
    
    if detailed:
        descriptions = [
            "errors from null value references", 
            "incorrect type casting", 
            "insecure deserialization"
        ]
        return '\n'.join([f"{i+1}. {vuln} - {desc}" 
                         for i, (vuln, desc) in enumerate(zip(vulnerabilities, descriptions))])
    else:
        return '\n'.join([f"{i+1}. {vuln}" for i, vuln in enumerate(vulnerabilities)])


if __name__ == "__main__":
    # Prompt template test
    print("=== Prompt Template Test ===")
    
    test_func_info = {
        "name": "deserialze",
        "full_signature": "public <T> T deserialze(DefaultJSONParser parser, Type type, Object fieldName)",
        "modifiers": ["public"],
        "return_type": "<T> T",
        "parameters": ["DefaultJSONParser parser", "Type type", "Object fieldName"],
        "implementation": """    {
        final JSONLexer lexer = parser.lexer;
        int token = lexer.token();
        if (token == JSONToken.NULL) {
            lexer.nextToken(JSONToken.COMMA);
            return null;
        }

        if (token == JSONToken.LITERAL_STRING || token == JSONToken.HEX) {
            byte[] bytes = lexer.bytesValue();
            lexer.nextToken(JSONToken.COMMA);

            if (bytes.length == 0 && type != byte[].class) {
                return null;
            }

            return (T) bytes;
        }

        Class componentClass;
        Type componentType;
        // ... rest of implementation
    }"""
    }
    
    print("\n1. GPT Prompt:")
    print("-" * 50)
    print(PromptManager.get_gpt_vulnerability_prompt(test_func_info))
    
    print("\n2. Gemini Prompt:")
    print("-" * 50)
    print(PromptManager.get_gemini_vulnerability_prompt(test_func_info))
    
    print("\n3. Ollama Prompt:")
    print("-" * 50)
    print(PromptManager.get_ollama_vulnerability_prompt(test_func_info))
    
    print("\n4. Vulnerability List:")
    print("-" * 50)
    print(get_vulnerability_list_text(detailed=True)) 