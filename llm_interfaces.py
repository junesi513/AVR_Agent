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
        
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except Exception as e:
            self.logger.error(f"GPT API 호출 실패: {str(e)}")
            return ""
    
    def generate_vulnerability_hypothesis(self, func_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """GPT를 사용한 취약점 가설 생성"""
        func_name = func_info.get("name", "unknown")
        
        # 프롬프트 관리자에서 GPT용 프롬프트 가져오기
        prompt = PromptManager.get_gpt_vulnerability_prompt(func_info)
        
        response = self.generate_response(prompt)
        
        try:
            # JSON 파싱 시도
            if response.strip().startswith('{'):
                result = json.loads(response)
                if result.get("vulnerabilities"):
                    return {
                        "function": func_name,
                        "vulnerabilities": result["vulnerabilities"],
                        "analysis_method": "llm_gpt",
                        "severity": max(v.get("severity", "medium") for v in result["vulnerabilities"])
                    }
        except json.JSONDecodeError:
            self.logger.error(f"GPT 응답 JSON 파싱 실패: {response}")
        
        return None


class GeminiInterface(LLMInterface):
    """Google Gemini 인터페이스"""
    
    def __init__(self, api_key: str, model: str = "gemini-pro", temperature: float = 0.1):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.base_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        self.logger = logging.getLogger(__name__)
    
    def generate_response(self, prompt: str, **kwargs) -> str:
        """Gemini API를 사용한 응답 생성"""
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
        
        try:
            response = requests.post(self.base_url, headers=headers, params=params, json=data, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if "candidates" in result and result["candidates"]:
                return result["candidates"][0]["content"]["parts"][0]["text"]
            return ""
        except Exception as e:
            self.logger.error(f"Gemini API 호출 실패: {str(e)}")
            return ""
    
    def generate_vulnerability_hypothesis(self, func_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Gemini를 사용한 취약점 가설 생성"""
        func_name = func_info.get("name", "unknown")
        
        # 프롬프트 관리자에서 Gemini용 프롬프트 가져오기
        prompt = PromptManager.get_gemini_vulnerability_prompt(func_info)
        
        response = self.generate_response(prompt)
        
        try:
            if response.strip().startswith('{'):
                result = json.loads(response)
                if result.get("vulnerabilities"):
                    return {
                        "function": func_name,
                        "vulnerabilities": result["vulnerabilities"],
                        "analysis_method": "llm_gemini",
                        "severity": max(v.get("severity", "medium") for v in result["vulnerabilities"])
                    }
        except json.JSONDecodeError:
            self.logger.error(f"Gemini 응답 JSON 파싱 실패: {response}")
        
        return None


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
        data = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_ctx": kwargs.get("max_tokens", 2048)
            }
        }
        
        try:
            response = requests.post(self.generate_url, json=data, timeout=60)
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            self.logger.error(f"Ollama API 호출 실패: {str(e)}")
            return ""
    
    def generate_vulnerability_hypothesis(self, func_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Ollama를 사용한 취약점 가설 생성"""
        func_name = func_info.get("name", "unknown")
        
        # 프롬프트 관리자에서 Ollama용 프롬프트 가져오기
        prompt = PromptManager.get_ollama_vulnerability_prompt(func_info)
        
        response = self.generate_response(prompt)
        
        try:
            # JSON 부분만 추출
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1
            
            if start_idx >= 0 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                result = json.loads(json_str)
                
                if result.get("vulnerabilities"):
                    return {
                        "function": func_name,
                        "vulnerabilities": result["vulnerabilities"],
                        "analysis_method": "llm_ollama",
                        "severity": max(v.get("severity", "medium") for v in result["vulnerabilities"])
                    }
        except (json.JSONDecodeError, ValueError):
            self.logger.error(f"Ollama 응답 JSON 파싱 실패: {response}")
        
        return None


class LLMFactory:
    """LLM 인터페이스 팩토리"""
    
    @staticmethod
    def create_llm(llm_type: str, **kwargs) -> LLMInterface:
        """LLM 인터페이스 생성"""
        if llm_type.lower() == "gpt" or llm_type.lower() == "openai":
            api_key = kwargs.get("api_key") or os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OpenAI API key가 필요합니다.")
            return OpenAIGPTInterface(
                api_key=api_key,
                model=kwargs.get("model", "gpt-4"),
                temperature=kwargs.get("temperature", 0.1)
            )
        
        elif llm_type.lower() == "gemini":
            api_key = kwargs.get("api_key") or os.getenv("GEMINI_API_KEY")
            if not api_key:
                raise ValueError("Gemini API key가 필요합니다.")
            return GeminiInterface(
                api_key=api_key,
                model=kwargs.get("model", "gemini-pro"),
                temperature=kwargs.get("temperature", 0.1)
            )
        
        elif llm_type.lower() == "ollama" or llm_type.lower() == "qwen":
            return OllamaInterface(
                base_url=kwargs.get("base_url", "http://localhost:11434"),
                model=kwargs.get("model", "qwen:7b"),
                temperature=kwargs.get("temperature", 0.1)
            )
        
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
                "model": "gemini-pro",
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


if __name__ == "__main__":
    # 설정 파일 생성
    create_llm_config_template()
    
    # 테스트 예시
    print("\n=== LLM 인터페이스 테스트 ===")
    
    # Ollama 테스트 (로컬에서 실행 중인 경우)
    try:
        ollama_llm = LLMFactory.create_llm("ollama", model="qwen:7b")
        test_func = {
            "name": "deserialze",
            "full_signature": "public <T> T deserialze(DefaultJSONParser parser, Type type, Object fieldName)",
            "modifiers": ["public"],
            "return_type": "<T> T",
            "parameters": ["DefaultJSONParser parser", "Type type", "Object fieldName"]
        }
        
        result = ollama_llm.generate_vulnerability_hypothesis(test_func)
        if result:
            print("✅ Ollama 테스트 성공")
            print(f"발견된 취약점: {len(result['vulnerabilities'])}개")
        else:
            print("⚠️ Ollama 테스트 - 취약점 없음")
            
    except Exception as e:
        print(f"❌ Ollama 테스트 실패: {str(e)}") 