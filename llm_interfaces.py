#!/usr/bin/env python3
"""
LLM 인터페이스 구현체들
다양한 LLM 서비스 (GPT, Gemini, Qwen/Ollama)를 지원
"""

import os
import json
import requests
import logging
from typing import Dict, List, Optional, Any
from abc import ABC, abstractmethod
from prompts import PromptManager

def get_response_logger():
    """LLM 응답 전용 로거 반환"""
    return logging.getLogger('llm_response')


class LLMInterface(ABC):
    """LLM 인터페이스 추상 클래스"""
    
    @abstractmethod
    def generate_response(self, prompt: str, **kwargs) -> str:
        """응답 생성"""
        pass
    
    @abstractmethod
    def generate_vulnerability_hypothesis(self, func_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """취약점 가설 생성"""
        pass


class OpenAIGPTInterface(LLMInterface):
    """OpenAI GPT 인터페이스"""
    
    def __init__(self, api_key: str, model: str = "gpt-4", temperature: float = 0.1):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.base_url = "https://api.openai.com/v1/chat/completions"
        self.logger = logging.getLogger(__name__)
    
    def generate_response(self, prompt: str, **kwargs) -> str:
        """GPT API를 사용한 응답 생성"""
        response_logger = get_response_logger()
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "당신은 Java 보안 전문가입니다. 코드의 취약점을 분석하고 패치를 제안합니다."},
                {"role": "user", "content": prompt}
            ],
            "temperature": self.temperature,
            "max_tokens": kwargs.get("max_tokens", 2000)
        }
        
        response_logger.info(f"=== GPT API 호출 시작 ===")
        response_logger.info(f"모델: {self.model}")
        response_logger.info(f"온도: {self.temperature}")
        response_logger.info(f"프롬프트 (일부): {prompt[:200]}...")
        
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            generated_content = result["choices"][0]["message"]["content"]
            
            response_logger.info(f"GPT 응답 성공")
            response_logger.info(f"응답 길이: {len(generated_content)} 문자")
            response_logger.info(f"응답 내용 (일부): {generated_content[:300]}...")
            
            # 전체 응답을 별도로 로깅
            if len(generated_content) < 1000:
                response_logger.info(f"전체 응답: {generated_content}")
            else:
                response_logger.info(f"응답이 너무 길어 일부만 표시됨 (총 {len(generated_content)} 문자)")
            
            return generated_content
        except Exception as e:
            response_logger.error(f"GPT API 호출 실패: {str(e)}")
            self.logger.error(f"GPT API 호출 실패: {str(e)}")
            return ""
    
    def generate_vulnerability_hypothesis(self, func_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """GPT를 사용한 취약점 가설 생성"""
        func_name = func_info.get("name", "unknown")
        
        # 프롬프트 관리자에서 GPT용 프롬프트 가져오기
        prompt = PromptManager.get_gpt_vulnerability_prompt(func_info)
        
        response = self.generate_response(prompt)
        
        # LLM 응답 전체를 별도 파일에 저장
        self._save_detailed_response(func_name, response)
        
        try:
            # JSON 부분 추출 개선
            json_content = self._extract_json_from_response(response)
            if json_content:
                result = json.loads(json_content)
                if result.get("vulnerabilities"):
                    return {
                        "function": func_name,
                        "vulnerabilities": result["vulnerabilities"],
                        "analysis_method": "llm_gpt",
                        "severity": max(v.get("severity", "medium") for v in result["vulnerabilities"]),
                        "detailed_analysis": response,  # 전체 응답 포함
                        "analysis_summary": self._extract_analysis_summary(response)
                    }
        except json.JSONDecodeError as e:
            self.logger.error(f"GPT 응답 JSON 파싱 실패: {e}")
            self.logger.error(f"응답 내용: {response[:500]}...")
        
        return None
    
    def _save_detailed_response(self, func_name: str, response: str):
        """LLM의 상세한 응답을 별도 파일에 저장"""
        try:
            from pathlib import Path
            import datetime
            
            # 응답 저장 디렉토리 생성
            response_dir = Path("log/llm_detailed_responses")
            response_dir.mkdir(parents=True, exist_ok=True)
            
            # 타임스탬프 생성
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # 파일명 생성
            filename = f"{func_name}_{timestamp}_gpt.txt"
            filepath = response_dir / filename
            
            # 응답 저장
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"=== LLM 상세 분석 결과 (GPT) ===\n")
                f.write(f"함수명: {func_name}\n")
                f.write(f"시간: {datetime.datetime.now().isoformat()}\n")
                f.write(f"모델: {self.model}\n")
                f.write(f"응답 길이: {len(response)} 문자\n")
                f.write("=" * 50 + "\n\n")
                f.write(response)
            
            self.logger.info(f"LLM 상세 응답 저장됨: {filepath}")
            
        except Exception as e:
            self.logger.error(f"LLM 응답 저장 실패: {e}")
    
    def _extract_json_from_response(self, response: str) -> Optional[str]:
        """응답에서 JSON 부분을 추출"""
        try:
            # ```json 코드 블록에서 추출
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                if end > start:
                    return response[start:end].strip()
            
            # { } 괄호로 JSON 추출
            start_idx = response.find('{')
            if start_idx >= 0:
                brace_count = 0
                for i, char in enumerate(response[start_idx:], start_idx):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            return response[start_idx:i+1]
            
            return None
            
        except Exception as e:
            self.logger.error(f"JSON 추출 실패: {e}")
            return None
    
    def _extract_analysis_summary(self, response: str) -> str:
        """응답에서 분석 요약 추출"""
        try:
            # JSON 이외의 설명 부분 추출
            lines = response.split('\n')
            summary_lines = []
            
            for line in lines:
                line = line.strip()
                if (line and 
                    not line.startswith('{') and 
                    not line.startswith('}') and 
                    not line.startswith('```') and
                    not line.startswith('"') and
                    len(line) > 10):
                    summary_lines.append(line)
            
            return '\n'.join(summary_lines[:5])  # 처음 5줄만
            
        except Exception as e:
            self.logger.error(f"분석 요약 추출 실패: {e}")
            return "분석 요약 추출 실패"


class GeminiInterface(LLMInterface):
    """Google Gemini 인터페이스"""
    
    def __init__(self, api_key: str, model: str = "gemini-1.5-flash", temperature: float = 0.1):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.base_url = f"https://generativelanguage.googleapis.com/v1/models/{model}:generateContent"
        self.logger = logging.getLogger(__name__)
    
    def generate_response(self, prompt: str, **kwargs) -> str:
        """Gemini API를 사용한 응답 생성"""
        response_logger = get_response_logger()
        
        headers = {
            "Content-Type": "application/json"
        }
        
        params = {
            "key": self.api_key
        }
        
        data = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": kwargs.get("max_tokens", 2000)
            }
        }
        
        response_logger.info(f"=== Gemini API 호출 시작 ===")
        response_logger.info(f"모델: {self.model}")
        response_logger.info(f"온도: {self.temperature}")
        response_logger.info(f"프롬프트 (일부): {prompt[:200]}...")
        
        try:
            response = requests.post(self.base_url, headers=headers, params=params, json=data, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if "candidates" in result and result["candidates"]:
                generated_content = result["candidates"][0]["content"]["parts"][0]["text"]
                
                response_logger.info(f"Gemini 응답 성공")
                response_logger.info(f"응답 길이: {len(generated_content)} 문자")
                response_logger.info(f"응답 내용 (일부): {generated_content[:300]}...")
                
                # 전체 응답을 별도로 로깅
                if len(generated_content) < 1000:
                    response_logger.info(f"전체 응답: {generated_content}")
                else:
                    response_logger.info(f"응답이 너무 길어 일부만 표시됨 (총 {len(generated_content)} 문자)")
                
                return generated_content
            else:
                response_logger.warning("Gemini 응답에 candidates가 없음")
                return ""
        except Exception as e:
            response_logger.error(f"Gemini API 호출 실패: {str(e)}")
            self.logger.error(f"Gemini API 호출 실패: {str(e)}")
            return ""
    
    def generate_vulnerability_hypothesis(self, func_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Gemini를 사용한 취약점 가설 생성"""
        func_name = func_info.get("name", "unknown")
        
        # 프롬프트 관리자에서 Gemini용 프롬프트 가져오기
        prompt = PromptManager.get_gemini_vulnerability_prompt(func_info)
        
        response = self.generate_response(prompt)
        
        # LLM 응답 전체를 별도 파일에 저장
        self._save_detailed_response(func_name, response)
        
        try:
            # JSON 부분 추출 개선
            json_content = self._extract_json_from_response(response)
            if json_content:
                result = json.loads(json_content)
                if result.get("vulnerabilities"):
                    return {
                        "function": func_name,
                        "vulnerabilities": result["vulnerabilities"],
                        "analysis_method": "llm_gemini",
                        "severity": max(v.get("severity", "medium") for v in result["vulnerabilities"]),
                        "detailed_analysis": response,  # 전체 응답 포함
                        "analysis_summary": self._extract_analysis_summary(response)
                    }
        except json.JSONDecodeError as e:
            self.logger.error(f"Gemini 응답 JSON 파싱 실패: {e}")
            self.logger.error(f"응답 내용: {response[:500]}...")
        
        return None
    
    def _save_detailed_response(self, func_name: str, response: str):
        """LLM의 상세한 응답을 별도 파일에 저장"""
        try:
            from pathlib import Path
            import datetime
            
            # 응답 저장 디렉토리 생성
            response_dir = Path("log/llm_detailed_responses")
            response_dir.mkdir(parents=True, exist_ok=True)
            
            # 타임스탬프 생성
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # 파일명 생성
            filename = f"{func_name}_{timestamp}_gemini.txt"
            filepath = response_dir / filename
            
            # 응답 저장
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"=== LLM 상세 분석 결과 (Gemini) ===\n")
                f.write(f"함수명: {func_name}\n")
                f.write(f"시간: {datetime.datetime.now().isoformat()}\n")
                f.write(f"모델: {self.model}\n")
                f.write(f"응답 길이: {len(response)} 문자\n")
                f.write("=" * 50 + "\n\n")
                f.write(response)
            
            self.logger.info(f"LLM 상세 응답 저장됨: {filepath}")
            
        except Exception as e:
            self.logger.error(f"LLM 응답 저장 실패: {e}")
    
    def _extract_json_from_response(self, response: str) -> Optional[str]:
        """응답에서 JSON 부분을 추출"""
        try:
            # ```json 코드 블록에서 추출
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                if end > start:
                    return response[start:end].strip()
            
            # { } 괄호로 JSON 추출
            start_idx = response.find('{')
            if start_idx >= 0:
                brace_count = 0
                for i, char in enumerate(response[start_idx:], start_idx):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            return response[start_idx:i+1]
            
            return None
            
        except Exception as e:
            self.logger.error(f"JSON 추출 실패: {e}")
            return None
    
    def _extract_analysis_summary(self, response: str) -> str:
        """응답에서 분석 요약 추출"""
        try:
            # JSON 이외의 설명 부분 추출
            lines = response.split('\n')
            summary_lines = []
            
            for line in lines:
                line = line.strip()
                if (line and 
                    not line.startswith('{') and 
                    not line.startswith('}') and 
                    not line.startswith('```') and
                    not line.startswith('"') and
                    len(line) > 10):
                    summary_lines.append(line)
            
            return '\n'.join(summary_lines[:5])  # 처음 5줄만
            
        except Exception as e:
            self.logger.error(f"분석 요약 추출 실패: {e}")
            return "분석 요약 추출 실패"


class OllamaInterface(LLMInterface):
    """Ollama (Qwen 등) 인터페이스"""
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "qwen:7b", temperature: float = 0.1):
        self.base_url = base_url
        self.model = model
        self.temperature = temperature
        self.generate_url = f"{base_url}/api/generate"
        self.logger = logging.getLogger(__name__)
    
    def generate_response(self, prompt: str, **kwargs) -> str:
        """Ollama API를 사용한 응답 생성"""
        response_logger = get_response_logger()
        
        data = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_ctx": kwargs.get("max_tokens", 2048)
            }
        }
        
        response_logger.info(f"=== Ollama API 호출 시작 ===")
        response_logger.info(f"모델: {self.model}")
        response_logger.info(f"온도: {self.temperature}")
        response_logger.info(f"서버: {self.base_url}")
        response_logger.info(f"프롬프트 (일부): {prompt[:200]}...")
        
        try:
            response = requests.post(self.generate_url, json=data, timeout=60)
            response.raise_for_status()
            
            result = response.json()
            generated_content = result.get("response", "")
            
            response_logger.info(f"Ollama 응답 성공")
            response_logger.info(f"응답 길이: {len(generated_content)} 문자")
            response_logger.info(f"응답 내용 (일부): {generated_content[:300]}...")
            
            # 전체 응답을 별도로 로깅
            if len(generated_content) < 1000:
                response_logger.info(f"전체 응답: {generated_content}")
            else:
                response_logger.info(f"응답이 너무 길어 일부만 표시됨 (총 {len(generated_content)} 문자)")
            
            return generated_content
        except Exception as e:
            response_logger.error(f"Ollama API 호출 실패: {str(e)}")
            self.logger.error(f"Ollama API 호출 실패: {str(e)}")
            return ""
    
    def generate_vulnerability_hypothesis(self, func_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Ollama를 사용한 취약점 가설 생성"""
        func_name = func_info.get("name", "unknown")
        
        # 프롬프트 관리자에서 Ollama용 프롬프트 가져오기
        prompt = PromptManager.get_ollama_vulnerability_prompt(func_info)
        
        response = self.generate_response(prompt)
        
        # LLM 응답 전체를 별도 파일에 저장
        self._save_detailed_response(func_name, response)
        
        try:
            # JSON 부분 추출 개선
            json_content = self._extract_json_from_response(response)
            if json_content:
                result = json.loads(json_content)
                if result.get("vulnerabilities"):
                    return {
                        "function": func_name,
                        "vulnerabilities": result["vulnerabilities"],
                        "analysis_method": "llm_ollama",
                        "severity": max(v.get("severity", "medium") for v in result["vulnerabilities"]),
                        "detailed_analysis": response,  # 전체 응답 포함
                        "analysis_summary": self._extract_analysis_summary(response)
                    }
        except (json.JSONDecodeError, ValueError) as e:
            self.logger.error(f"Ollama 응답 JSON 파싱 실패: {e}")
            self.logger.error(f"응답 내용: {response[:500]}...")
        
        return None
    
    def _save_detailed_response(self, func_name: str, response: str):
        """LLM의 상세한 응답을 별도 파일에 저장"""
        try:
            from pathlib import Path
            import datetime
            
            # 응답 저장 디렉토리 생성
            response_dir = Path("log/llm_detailed_responses")
            response_dir.mkdir(parents=True, exist_ok=True)
            
            # 타임스탬프 생성
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # 파일명 생성
            filename = f"{func_name}_{timestamp}_ollama.txt"
            filepath = response_dir / filename
            
            # 응답 저장
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"=== LLM 상세 분석 결과 (Ollama) ===\n")
                f.write(f"함수명: {func_name}\n")
                f.write(f"시간: {datetime.datetime.now().isoformat()}\n")
                f.write(f"모델: {self.model}\n")
                f.write(f"응답 길이: {len(response)} 문자\n")
                f.write("=" * 50 + "\n\n")
                f.write(response)
            
            self.logger.info(f"LLM 상세 응답 저장됨: {filepath}")
            
        except Exception as e:
            self.logger.error(f"LLM 응답 저장 실패: {e}")
    
    def _extract_json_from_response(self, response: str) -> Optional[str]:
        """응답에서 JSON 부분을 추출"""
        try:
            # ```json 코드 블록에서 추출
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                if end > start:
                    return response[start:end].strip()
            
            # { } 괄호로 JSON 추출
            start_idx = response.find('{')
            if start_idx >= 0:
                brace_count = 0
                for i, char in enumerate(response[start_idx:], start_idx):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            return response[start_idx:i+1]
            
            return None
            
        except Exception as e:
            self.logger.error(f"JSON 추출 실패: {e}")
            return None
    
    def _extract_analysis_summary(self, response: str) -> str:
        """응답에서 분석 요약 추출"""
        try:
            # JSON 이외의 설명 부분 추출
            lines = response.split('\n')
            summary_lines = []
            
            for line in lines:
                line = line.strip()
                if (line and 
                    not line.startswith('{') and 
                    not line.startswith('}') and 
                    not line.startswith('```') and
                    not line.startswith('"') and
                    len(line) > 10):
                    summary_lines.append(line)
            
            return '\n'.join(summary_lines[:5])  # 처음 5줄만
            
        except Exception as e:
            self.logger.error(f"분석 요약 추출 실패: {e}")
            return "분석 요약 추출 실패"


class LLMFactory:
    """LLM 인터페이스 팩토리"""
    
    @staticmethod
    def create_llm(config, **kwargs) -> LLMInterface:
        """LLM 인터페이스 생성"""
        # config가 문자열인 경우 (기존 방식)
        if isinstance(config, str):
            llm_type = config
            provider_config = kwargs
        else:
            # config가 dict인 경우 (새로운 방식)
            llm_type = config.get("provider", "none")
            provider_config = config
            provider_config.update(kwargs)  # kwargs로 전달된 추가 설정 병합
        
        if llm_type.lower() in ["gpt", "openai"]:
            api_key = provider_config.get("api_key") or os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OpenAI API key가 필요합니다.")
            return OpenAIGPTInterface(
                api_key=api_key,
                model=provider_config.get("model", "gpt-4"),
                temperature=provider_config.get("temperature", 0.1)
            )
        
        elif llm_type.lower() == "gemini":
            api_key = provider_config.get("api_key") or os.getenv("GEMINI_API_KEY")
            if not api_key:
                raise ValueError("Gemini API key가 필요합니다.")
            return GeminiInterface(
                api_key=api_key,
                model=provider_config.get("model", "gemini-1.5-flash"),
                temperature=provider_config.get("temperature", 0.1)
            )
        
        elif llm_type.lower() in ["ollama", "qwen"]:
            return OllamaInterface(
                base_url=provider_config.get("base_url", "http://localhost:11434"),
                model=provider_config.get("model", "qwen:7b"),
                temperature=provider_config.get("temperature", 0.1)
            )
        
        elif llm_type.lower() in ["none", ""]:
            # LLM 없이 실행
            return None
        
        else:
            raise ValueError(f"지원하지 않는 LLM 타입: {llm_type}")


# LLM 설정 파일 예시
def create_llm_config_template():
    """LLM 설정 파일 템플릿 생성"""
    config = {
        "llm_configs": [
            {
                "name": "gpt4",
                "type": "gpt",
                "model": "gpt-4",
                "api_key": "your_openai_api_key_here",
                "temperature": 0.1,
                "enabled": False
            },
            {
                "name": "gemini",
                "type": "gemini", 
                "model": "gemini-1.5-flash",
                "api_key": "your_gemini_api_key_here",
                "temperature": 0.1,
                "enabled": False
            },
            {
                "name": "qwen",
                "type": "ollama",
                "model": "qwen:7b",
                "base_url": "http://localhost:11434",
                "temperature": 0.1,
                "enabled": True
            }
        ],
        "default_llm": "qwen"
    }
    
    with open("llm_config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print("LLM 설정 파일 (llm_config.json) 생성됨")
    print("필요한 API 키를 입력하고 enabled를 true로 설정하세요.") 