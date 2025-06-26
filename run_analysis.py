#!/usr/bin/env python3
"""
취약점 분석 실행 스크립트
사용법: python run_analysis.py [--vuln-id ID] [--llm-type TYPE] [--config CONFIG_FILE]
"""

import argparse
import json
import sys
from pathlib import Path
from vulnerability_analyzer import AdvancedVulnerabilityAnalyzer
from llm_interfaces import create_llm_config_template


def main():
    parser = argparse.ArgumentParser(description='Java 취약점 분석 및 패치 생성 도구')
    parser.add_argument('--vuln-id', type=int, default=1, help='취약점 ID (기본값: 1)')
    parser.add_argument('--llm-type', type=str, choices=['gpt', 'gemini', 'ollama', 'qwen'], 
                       help='사용할 LLM 타입')
    parser.add_argument('--config', type=str, help='LLM 설정 파일 경로')
    parser.add_argument('--create-config', action='store_true', help='LLM 설정 파일 템플릿 생성')
    parser.add_argument('--api-key', type=str, help='API 키 (GPT/Gemini용)')
    parser.add_argument('--model', type=str, help='사용할 모델명')
    parser.add_argument('--temperature', type=float, default=0.1, 
                       help='LLM temperature 설정 (0.0-1.0, 기본값: 0.1)')
    parser.add_argument('--base-url', type=str, default='http://localhost:11434', 
                       help='Ollama 서버 URL (기본값: http://localhost:11434)')
    
    args = parser.parse_args()
    
    # 설정 파일 생성 모드
    if args.create_config:
        create_llm_config_template()
        return
    
    # LLM 설정
    llm_config = None
    if args.llm_type:
        llm_config = {
            'type': args.llm_type,
            'temperature': args.temperature
        }
        
        if args.api_key:
            llm_config['api_key'] = args.api_key
        
        if args.model:
            llm_config['model'] = args.model
        
        if args.llm_type == 'ollama' or args.llm_type == 'qwen':
            llm_config['base_url'] = args.base_url
            if not args.model:
                llm_config['model'] = 'qwen:7b'
    
    # 설정 파일 로드
    if args.config and Path(args.config).exists():
        try:
            with open(args.config, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
            
            if llm_config:
                # 명령행 인수가 우선
                for key, value in file_config.items():
                    if key not in llm_config:
                        llm_config[key] = value
            else:
                llm_config = file_config
                
        except Exception as e:
            print(f"⚠️ 설정 파일 로드 실패: {str(e)}")
    
    # 분석 실행
    print(f"🚀 취약점 분석 시작 - VUL4J-{args.vuln_id}")
    print(f"📁 대상 경로: ./benchmark/Java/VUL4J/VUL4J-{args.vuln_id}/")
    
    if llm_config:
        temp = llm_config.get('temperature', 0.1)
        print(f"🤖 LLM: {llm_config.get('type', 'unknown')} ({llm_config.get('model', 'default')}, temp={temp})")
    else:
        print("🤖 LLM: 패턴 매칭 모드")
    
    try:
        analyzer = AdvancedVulnerabilityAnalyzer(vuln_id=args.vuln_id, llm_interface=llm_config)
        result = analyzer.analyze()
        
        if result["status"] == "completed":
            # 검증된 취약점과 미검증 취약점 분리
            confirmed_vulns = [v for v in result['vulnerabilities'] if v.get('confirmed', False)]
            unconfirmed_vulns = [v for v in result['vulnerabilities'] if not v.get('confirmed', False)]
            
            # 패치 검증 결과 분석
            validated_patches = result.get('validated_patches', [])
            successful_patches = [p for p in validated_patches if p.get('validation_status') == 'success']
            failed_patches = [p for p in validated_patches if p.get('validation_status') != 'success']
            
            print("\n✅ 분석 완료!")
            print(f"🔍 총 발견된 취약점: {len(result['vulnerabilities'])}개")
            print(f"  ✓ 검증된 취약점: {len(confirmed_vulns)}개")
            print(f"  ⚠️ 미검증 취약점: {len(unconfirmed_vulns)}개")
            print(f"🔧 생성된 패치: {len(result['patches'])}개")
            print(f"✅ 검증된 패치: {len(successful_patches)}개")
            print(f"❌ 검증 실패 패치: {len(failed_patches)}개")
            
            # 검증된 취약점 우선 표시
            if confirmed_vulns:
                print("\n🔥 검증된 취약점:")
                for i, vuln in enumerate(confirmed_vulns[:5], 1):  # 상위 5개만 표시
                    print(f"  {i}. {vuln['function']} - {vuln['severity']} 심각도 ✓")
                    for v in vuln['hypothesis']['vulnerabilities']:
                        print(f"     • {v['type']}: {v['description']}")
            
            # 미검증 취약점 (적당한 수만 표시)
            if unconfirmed_vulns and len(unconfirmed_vulns) <= 10:
                print("\n⚠️ 미검증 취약점 (정적 분석 도구 검증 필요):")
                for i, vuln in enumerate(unconfirmed_vulns[:5], 1):  # 상위 5개만 표시
                    print(f"  {i}. {vuln['function']} - {vuln['severity']} 심각도")
                    for v in vuln['hypothesis']['vulnerabilities']:
                        print(f"     • {v['type']}: {v['description']}")
            elif unconfirmed_vulns:
                print(f"\n⚠️ {len(unconfirmed_vulns)}개의 미검증 취약점이 있습니다. (로그 파일에서 확인)")
            
            # 패치 검증 결과 표시
            if successful_patches:
                print("\n🎯 성공적으로 검증된 패치:")
                for i, patch in enumerate(successful_patches[:3], 1):  # 상위 3개만 표시
                    iterations = patch.get('validation_iterations', 'N/A')
                    print(f"  {i}. {patch['vulnerability_id']} - {iterations}회 반복으로 검증 완료 ✅")
            
            if failed_patches:
                print("\n⚠️ 검증 실패한 패치:")
                for i, patch in enumerate(failed_patches[:3], 1):  # 상위 3개만 표시
                    status = patch.get('validation_status', 'unknown')
                    iterations = patch.get('validation_iterations', 'N/A')
                    print(f"  {i}. {patch['vulnerability_id']} - {status} ({iterations}회 시도)")
            
            # Rule 파일 경로 출력 (새로운 구조 반영)
            rule_dir = Path(f"./rule/VUL4J-{args.vuln_id}")
            if rule_dir.exists():
                rule_files = list(rule_dir.glob("*"))
                if rule_files:
                    print(f"\n📝 생성된 규칙 파일 ({len(rule_files)}개):")
                    for rule_file in rule_files[:10]:  # 상위 10개만 표시
                        print(f"  • {rule_file}")
            
            print(f"\n📄 상세 결과: ./log/VUL4J-{args.vuln_id}/analysis_result_{args.vuln_id}_*.json")
            
        else:
            print(f"❌ 분석 실패: {result.get('error', 'Unknown error')}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️ 사용자에 의해 중단됨")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 예기치 않은 오류: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 