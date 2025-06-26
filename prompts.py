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
3. Unsafe Deserialization - including:
   - Fastjson deserialization (parseArray, parseObject, JSON.parse)
   - Jackson deserialization (ObjectMapper.readValue)
   - Java native deserialization (ObjectInputStream.readObject)
   - Any method that converts external data to objects without proper validation
   - Methods with names containing: deserialize, parse, decode, unmarshal, fromJson, readValue

CRITICAL: The 'deserialze' method (with typo) is a Fastjson deserialization method and should be flagged as UNSAFE_DESERIALIZATION.

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
        """Google Gemini용 취약점 분석 프롬프트 - 고급 CodeQL 템플릿 정보 포함"""
        func_name = func_info.get("name", "unknown")
        signature = func_info.get("full_signature", "")
        implementation = func_info.get("implementation", "")
        
        return f"""As a Java security expert, perform comprehensive vulnerability analysis for CodeQL generation:

Method: {func_name}
Signature: {signature}

Code:
{implementation}

REQUIRED OUTPUT FORMAT (JSON):
{{
  "vulnerabilities": [
    {{
      "type": "VULNERABILITY_TYPE",
      "description": "Detailed vulnerability description",
      "severity": "high|medium|low",
      "confidence": 0.0-1.0,
      "codeql_analysis_type": "dataflow|controlflow|tainttracking|typetracking|valuetracking",
      
      // DataFlow Analysis Information
      "sources": [
        {{
          "type": "parameter|field|method_return|external_input",
          "name": "parameter_name",
          "position": 0,
          "java_type": "Type",
          "condition": "this.asParameter().getType().getName().matches(\\"*Parser*\\")",
          "description": "External JSON parser input"
        }}
      ],
      "sinks": [
        {{
          "type": "method_call|field_access|return_value",
          "method_name": "parseArray",
          "class_pattern": "*JSON*",
          "condition": "exists(MethodAccess ma | ma.getMethod().getName() = \\"parseArray\\" and this.asExpr() = ma)",
          "description": "Dangerous deserialization call"
        }}
      ],
      "sanitizers": [
        {{
          "type": "validation|sanitization|encoding",
          "method_name": "validate",
          "condition": "this.asExpr().(MethodAccess).getMethod().getName().matches(\\"validate*\\")",
          "description": "Input validation method"
        }}
      ],
      
      // TaintTracking Analysis Information  
      "taint_sources": [
        {{
          "type": "user_input|external_data|untrusted_source",
          "condition": "CodeQL condition for taint source",
          "description": "Source of untrusted data"
        }}
      ],
      "taint_sinks": [
        {{
          "type": "dangerous_operation|security_sensitive",
          "condition": "CodeQL condition for taint sink", 
          "description": "Security-sensitive operation"
        }}
      ],
      "taint_steps": [
        {{
          "from_type": "Type1",
          "to_type": "Type2", 
          "condition": "CodeQL condition for taint propagation",
          "description": "How taint propagates"
        }}
      ],
      
      // ControlFlow Analysis Information
      "conditions": [
        {{
          "type": "if_condition|switch_condition|loop_condition",
          "pattern": "null_check|type_check|range_check",
          "missing": true,
          "condition": "CodeQL condition",
          "description": "Missing security check"
        }}
      ],
      "branches": [
        {{
          "type": "if_branch|else_branch|case_branch",
          "vulnerability": "missing_validation|improper_handling",
          "condition": "CodeQL condition",
          "description": "Vulnerable branch"
        }}
      ],
      "loops": [
        {{
          "type": "for_loop|while_loop|enhanced_for",
          "vulnerability": "infinite_loop|resource_exhaustion",
          "condition": "CodeQL condition", 
          "description": "Vulnerable loop structure"
        }}
      ],
      
      // TypeTracking Analysis Information
      "type_sources": [
        {{
          "type": "unsafe_cast|type_conversion|reflection",
          "from_type": "Object",
          "to_type": "SpecificType",
          "condition": "CodeQL condition",
          "description": "Type source"
        }}
      ],
      "type_sinks": [
        {{
          "type": "method_call|field_access|array_access",
          "expected_type": "ExpectedType", 
          "condition": "CodeQL condition",
          "description": "Type-sensitive operation"
        }}
      ],
      "type_conversions": [
        {{
          "from_type": "Type1",
          "to_type": "Type2",
          "method": "cast|conversion_method",
          "unsafe": true,
          "condition": "CodeQL condition",
          "description": "Unsafe type conversion"
        }}
      ],
      
      // ValueTracking Analysis Information
      "value_sources": [
        {{
          "type": "constant|calculation|user_input",
          "value_pattern": "specific_value|range|format",
          "condition": "CodeQL condition",
          "description": "Value source"
        }}
      ],
      "value_sinks": [
        {{
          "type": "array_index|loop_bound|size_parameter",
          "vulnerability": "buffer_overflow|dos|injection",
          "condition": "CodeQL condition", 
          "description": "Value-sensitive operation"
        }}
      ],
      "value_transformations": [
        {{
          "type": "arithmetic|string_operation|encoding",
          "operation": "+|-|*|/|concat|encode",
          "condition": "CodeQL condition",
          "description": "Value transformation"
        }}
      ]
    }}
  ]
}}

ANALYSIS FOCUS:
1. **DataFlow**: Identify sources of external input and dangerous sinks
2. **TaintTracking**: Find untrusted data propagation paths  
3. **ControlFlow**: Locate missing security checks and vulnerable branches
4. **TypeTracking**: Detect unsafe type conversions and type confusion
5. **ValueTracking**: Track dangerous values leading to buffer overflows or DoS

VULNERABILITY TYPES TO CONSIDER:
- Unsafe Deserialization (Fastjson, Jackson, etc.)
- Null Pointer Dereference
- Type Confusion
- Buffer Overflow
- Integer Overflow
- SQL Injection  
- Command Injection
- Path Traversal
- XML External Entity (XXE)
- Cross-Site Scripting (XSS)

For each vulnerability, provide COMPLETE CodeQL-ready conditions that can be directly used in templates.
Be specific about Java types, method names, and class patterns.
Use proper CodeQL syntax in all conditions."""

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
3. Unsafe Deserialization - insecure deserialization vulnerabilities including:
   - Fastjson deserialization (parseArray, parseObject, JSON.parse)
   - Jackson deserialization (ObjectMapper.readValue)
   - Java native deserialization (ObjectInputStream.readObject)
   - Any method that converts external data to objects without proper validation
   - Look for methods with names containing: deserialize, parse, decode, unmarshal, fromJson, readValue
   - Pay special attention to parser.parseArray(), TypeUtils.cast(), and similar unsafe operations

IMPORTANT: For the 'deserialze' method (note the typo), this is actually a deserialization method from Fastjson library and should be flagged as UNSAFE_DESERIALIZATION if it processes untrusted input.

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