#!/usr/bin/env python3
"""
개선된 취약점 분석 시스템
- 향상된 JSON 파싱
- 개선된 CodeQL 템플릿  
- 더 나은 에러 핸들링
- 분석 품질 향상
"""

import os
import sys
import json
import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# 프로젝트 모듈 임포트
from llm_interfaces import LLMFactory
from codeql_templates import CodeQLTemplateEngine, CodeQLInfoExtractor
from vulnerability_analyzer import VulnerabilityAnalyzer

class ImprovedAnalysisSystem:
    """개선된 분석 시스템"""
    
    def __init__(self, config_path: str = "llm_config.json"):
        self.config_path = config_path
        self.logger = self._setup_logging()
        self.template_engine = CodeQLTemplateEngine()
        self.info_extractor = CodeQLInfoExtractor()
        
    def _setup_logging(self) -> logging.Logger:
        """로깅 설정"""
        logger = logging.getLogger('improved_analysis')
        logger.setLevel(logging.INFO)
        
        # 파일 핸들러
        log_dir = Path("log/improved")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_handler = logging.FileHandler(
            log_dir / f"improved_analysis_{timestamp}.log",
            encoding='utf-8'
        )
        file_handler.setLevel(logging.INFO)
        
        # 콘솔 핸들러
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # 포매터
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def run_improved_analysis(self, vuln_ids: List[str], models: List[str] = None):
        """개선된 분석 실행"""
        self.logger.info("=== 개선된 취약점 분석 시작 ===")
        
        if models is None:
            models = ["gemini-1.5-pro", "qwen3:32b"]
        
        results = {}
        
        for model in models:
            self.logger.info(f"=== {model} 모델 분석 시작 ===")
            model_results = {}
            
            for vuln_id in vuln_ids:
                try:
                    self.logger.info(f"VUL4J-{vuln_id} 분석 시작")
                    result = self._analyze_single_vuln(vuln_id, model)
                    model_results[f"VUL4J-{vuln_id}"] = result
                    self.logger.info(f"VUL4J-{vuln_id} 분석 완료")
                    
                except Exception as e:
                    self.logger.error(f"VUL4J-{vuln_id} 분석 실패: {e}")
                    model_results[f"VUL4J-{vuln_id}"] = {
                        "status": "error",
                        "error": str(e),
                        "traceback": traceback.format_exc()
                    }
            
            results[model] = model_results
        
        # 결과 저장
        self._save_comparison_results(results)
        
        # 요약 리포트 생성
        self._generate_summary_report(results)
        
        self.logger.info("=== 개선된 취약점 분석 완료 ===")
        return results
    
    def _analyze_single_vuln(self, vuln_id: str, model: str) -> Dict[str, Any]:
        """단일 취약점 분석"""
        try:
            # 설정 로드
            config = self._load_config()
            if model not in config:
                raise ValueError(f"모델 {model} 설정이 없습니다")
            
            # LLM 인스턴스 생성
            llm = LLMFactory.create_llm(config[model])
            
            # 분석기 초기화 (올바른 매개변수 사용)
            analyzer = VulnerabilityAnalyzer(
                vuln_id=int(vuln_id),
                llm_config=config[model]
            )
            
            # 분석 실행
            results = analyzer.analyze()
            
            return {
                "status": "success",
                "results": results,
                "analysis_time": datetime.now().isoformat(),
                "improvements_applied": [
                    "enhanced_json_parsing",
                    "improved_codeql_templates",
                    "better_error_handling"
                ]
            }
            
        except Exception as e:
            self.logger.error(f"분석 실패: {e}")
            return {
                "status": "error",
                "error": str(e),
                "traceback": traceback.format_exc()
            }
    
    def _load_config(self) -> Dict[str, Any]:
        """설정 파일 로드 (개선된 버전)"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                full_config = json.load(f)
            
            # llm_configs 배열을 이름 기반 딕셔너리로 변환
            configs = {}
            for config in full_config.get("llm_configs", []):
                if config.get("enabled", True):  # enabled가 True이거나 설정되지 않은 경우
                    configs[config["name"]] = config
            
            self.logger.info(f"사용 가능한 모델: {list(configs.keys())}")
            return configs
            
        except Exception as e:
            self.logger.error(f"설정 파일 로드 실패: {e}")
            raise
    
    def _save_comparison_results(self, results: Dict[str, Any]):
        """비교 결과 저장"""
        try:
            output_dir = Path("log/improved/comparison")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = output_dir / f"comparison_results_{timestamp}.json"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"비교 결과 저장: {output_file}")
            
        except Exception as e:
            self.logger.error(f"비교 결과 저장 실패: {e}")
    
    def _generate_summary_report(self, results: Dict[str, Any]):
        """요약 리포트 생성"""
        try:
            output_dir = Path("log/improved/reports")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = output_dir / f"summary_report_{timestamp}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("# 개선된 취약점 분석 요약 리포트\n\n")
                f.write(f"생성 시간: {datetime.now().isoformat()}\n\n")
                
                # 모델별 성능 비교
                f.write("## 모델별 성능 비교\n\n")
                f.write("| 모델 | 성공 | 실패 | 성공률 |\n")
                f.write("|------|------|------|--------|\n")
                
                for model, model_results in results.items():
                    success_count = sum(1 for r in model_results.values() if r.get("status") == "success")
                    total_count = len(model_results)
                    success_rate = (success_count / total_count * 100) if total_count > 0 else 0
                    
                    f.write(f"| {model} | {success_count} | {total_count - success_count} | {success_rate:.1f}% |\n")
                
                # 상세 결과
                f.write("\n## 상세 분석 결과\n\n")
                for model, model_results in results.items():
                    f.write(f"### {model}\n\n")
                    for vuln_id, result in model_results.items():
                        status = result.get("status", "unknown")
                        f.write(f"- **{vuln_id}**: {status}\n")
                        if status == "error":
                            f.write(f"  - 에러: {result.get('error', 'Unknown error')}\n")
                    f.write("\n")
                
                # 개선사항 적용 현황
                f.write("## 적용된 개선사항\n\n")
                f.write("1. **향상된 JSON 파싱**: 더 강력한 JSON 추출 및 복구\n")
                f.write("2. **개선된 CodeQL 템플릿**: 취약점 유형별 스마트 쿼리 생성\n")
                f.write("3. **더 나은 에러 핸들링**: 세밀한 에러 복구 및 로깅\n")
                f.write("4. **분석 품질 향상**: 컨텍스트 기반 분석 조건 생성\n")
            
            self.logger.info(f"요약 리포트 생성: {report_file}")
            
        except Exception as e:
            self.logger.error(f"요약 리포트 생성 실패: {e}")

def main():
    """메인 함수"""
    if len(sys.argv) < 2:
        print("사용법: python improved_analysis.py <vuln_ids> [models]")
        print("예시: python improved_analysis.py 1,10,14,26 gemini-1_5-flash,qwen3_32b")
        sys.exit(1)
    
    # 명령행 인수 파싱
    vuln_ids = sys.argv[1].split(',')
    models = sys.argv[2].split(',') if len(sys.argv) > 2 else None
    
    # 분석 시스템 초기화 및 실행
    system = ImprovedAnalysisSystem()
    results = system.run_improved_analysis(vuln_ids, models)
    
    print("\n=== 분석 완료 ===")
    print("결과는 log/improved/ 디렉토리에서 확인할 수 있습니다.")

if __name__ == "__main__":
    main() 