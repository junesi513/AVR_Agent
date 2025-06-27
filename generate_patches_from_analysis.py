#!/usr/bin/env python3

import json
import requests
from pathlib import Path
import datetime
import re

def generate_patch_for_function(func_info, vulnerabilities):
    """특정 함수의 취약점에 대한 패치 생성"""
    
    func_name = func_info.get("name", "unknown")
    signature = func_info.get("full_signature", "")
    implementation = func_info.get("implementation", "")
    
    # 취약점 정보 추출
    vuln_types = []
    vuln_descriptions = []
    for vuln in vulnerabilities:
        vuln_types.append(vuln.get("type", "Unknown"))
        vuln_descriptions.append(vuln.get("description", ""))
    
    # 간단한 패치 생성 프롬프트
    prompt = f"""다음 Java 메서드의 보안 취약점에 대한 패치를 생성해주세요:

함수명: {func_name}
시그니처: {signature}

현재 구현:
```java
{implementation}
```

발견된 취약점:
{', '.join(vuln_types)}

설명: {' / '.join(vuln_descriptions)}

요청사항:
1. 실제 동작하는 Java 코드로 패치 제공
2. 각 패치는 서로 다른 보안 접근 방식 사용
3. 주석으로 패치 이유 설명

JSON 형식으로 응답:
{{
  "patches": [
    {{
      "id": 1,
      "type": "input_validation",
      "code": "완전한 Java 메서드 코드",
      "description": "패치 설명"
    }},
    {{
      "id": 2,
      "type": "whitelist_validation", 
      "code": "완전한 Java 메서드 코드",
      "description": "패치 설명"
    }}
  ]
}}"""

    return call_gemini_api(prompt)

def call_gemini_api(prompt):
    """Gemini API 호출"""
    url = "https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent"
    headers = {"Content-Type": "application/json"}
    params = {"key": "AIzaSyCWA58IOFNqypP0oENiOK5rvKApirD5P_w"}
    
    data = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 3000
        }
    }
    
    try:
        print(f"🔄 Gemini API 호출 중...")
        response = requests.post(url, headers=headers, params=params, json=data, timeout=60)
        
        if response.status_code == 200:
            result = response.json()
            if "candidates" in result and result["candidates"]:
                content = result["candidates"][0]["content"]["parts"][0]["text"]
                print(f"✅ 응답 성공! 길이: {len(content)} 문자")
                return content
            else:
                print("❌ candidates 없음")
                return None
        else:
            print(f"❌ API 호출 실패: {response.status_code}")
            print(f"오류: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ 예외 발생: {e}")
        return None

def extract_json_from_response(response):
    """응답에서 JSON 추출 - 개선된 버전"""
    try:
        # 1. ```json 블록에서 추출
        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            if end > start:
                json_content = response[start:end].strip()
                try:
                    return json.loads(json_content)
                except json.JSONDecodeError:
                    print("⚠️ JSON 블록 파싱 실패, 다른 방법 시도...")
        
        # 2. { } 괄호로 JSON 추출
        start_idx = response.find('{')
        if start_idx >= 0:
            brace_count = 0
            for i, char in enumerate(response[start_idx:], start_idx):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        json_content = response[start_idx:i+1]
                        try:
                            return json.loads(json_content)
                        except json.JSONDecodeError:
                            print("⚠️ 괄호 기반 JSON 파싱 실패...")
                            continue
        
        # 3. 패치 코드를 직접 추출하여 JSON 구성
        patches = []
        
        # Java 코드 블록 찾기
        java_blocks = re.findall(r'```java\s*(.*?)\s*```', response, re.DOTALL)
        
        for i, code_block in enumerate(java_blocks, 1):
            # 설명 찾기 (코드 블록 앞의 텍스트)
            description_match = re.search(r'(\d+\.\s*.*?)```java', response)
            description = description_match.group(1).strip() if description_match else f"패치 {i}"
            
            patches.append({
                "id": i,
                "type": f"patch_{i}",
                "code": code_block.strip(),
                "description": description
            })
        
        if patches:
            return {"patches": patches}
        
        return None
    except Exception as e:
        print(f"JSON 추출 중 예외 발생: {e}")
        return None

def save_response_to_file(response, func_name, vuln_id):
    """응답을 파일에 저장"""
    response_dir = Path(f"log/generated_patches/VUL4J-{vuln_id}/responses")
    response_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    response_file = response_dir / f"{func_name}_response_{timestamp}.txt"
    
    with open(response_file, 'w', encoding='utf-8') as f:
        f.write(f"=== Gemini 패치 생성 응답 ===\n")
        f.write(f"함수명: {func_name}\n")
        f.write(f"시간: {datetime.datetime.now().isoformat()}\n")
        f.write("=" * 50 + "\n\n")
        f.write(response)
    
    print(f"📝 응답 저장됨: {response_file}")
    return response_file

def save_patches_to_file(patches, func_name, vuln_id):
    """생성된 패치를 파일에 저장"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 패치 저장 디렉토리 생성
    patch_dir = Path(f"log/generated_patches/VUL4J-{vuln_id}")
    patch_dir.mkdir(parents=True, exist_ok=True)
    
    # 파일명 생성
    filename = f"{func_name}_patches_{timestamp}.json"
    filepath = patch_dir / filename
    
    # 패치 저장
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump({
            "function": func_name,
            "vulnerability_id": f"VUL4J-{vuln_id}",
            "timestamp": timestamp,
            "patches": patches
        }, f, indent=2, ensure_ascii=False)
    
    print(f"📁 패치 저장됨: {filepath}")
    return filepath

def main():
    """메인 함수"""
    print("🚀 기존 분석 결과 기반 패치 생성 시작")
    
    # 최신 분석 결과 파일 로드
    analysis_file = "log/gemini-1_5-flash/VUL4J-1/analysis_result_1_20250627_111058.json"
    
    try:
        with open(analysis_file, 'r', encoding='utf-8') as f:
            analysis_data = json.load(f)
        
        print(f"📊 분석 결과 로드됨: {analysis_file}")
        
        # 취약점이 발견된 함수들 처리
        vulnerabilities = analysis_data.get("vulnerabilities", [])
        ast_data = analysis_data.get("ast_data", {})
        
        for vuln in vulnerabilities:
            func_name = vuln.get("function", "unknown")
            vuln_list = vuln.get("hypothesis", {}).get("vulnerabilities", [])
            
            print(f"\n🔍 함수 '{func_name}' 패치 생성 중...")
            print(f"   취약점: {[v.get('type') for v in vuln_list]}")
            
            # 해당 함수의 AST 정보 찾기
            func_info = None
            for file_data in ast_data.values():
                for func in file_data.get("functions", []):
                    if func.get("name") == func_name:
                        func_info = func
                        break
                if func_info:
                    break
            
            if func_info and vuln_list:
                # 패치 생성
                response = generate_patch_for_function(func_info, vuln_list)
                
                if response:
                    # 응답 먼저 저장
                    save_response_to_file(response, func_name, 1)
                    
                    # JSON 추출
                    patches_json = extract_json_from_response(response)
                    
                    if patches_json and "patches" in patches_json:
                        patches = patches_json["patches"]
                        print(f"✅ {len(patches)}개 패치 생성 성공!")
                        
                        # 패치 내용 미리보기
                        for i, patch in enumerate(patches, 1):
                            print(f"   {i}. {patch.get('type', 'Unknown')} - {patch.get('description', 'No description')[:50]}...")
                        
                        # 파일에 저장
                        save_patches_to_file(patches, func_name, 1)
                    else:
                        print("❌ 패치 JSON 추출 실패 - 하지만 응답은 저장됨")
                else:
                    print("❌ 패치 생성 실패")
            else:
                print(f"⚠️ 함수 '{func_name}' 정보 또는 취약점 정보 부족")
        
        print("\n🎉 패치 생성 완료!")
        
    except FileNotFoundError:
        print(f"❌ 분석 결과 파일을 찾을 수 없습니다: {analysis_file}")
    except Exception as e:
        print(f"❌ 오류 발생: {e}")

if __name__ == "__main__":
    main() 