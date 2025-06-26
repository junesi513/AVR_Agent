#!/bin/bash
# CodeQL 환경설정 스크립트

echo "🔧 CodeQL 환경 설정 중..."

# Java 17 환경 설정
export CODEQL_JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export CODEQL_EXTRACTOR_JAVA_ROOT=/opt/codeql/java

# 환경변수 확인
echo "✅ CODEQL_JAVA_HOME: $CODEQL_JAVA_HOME"
echo "✅ CODEQL_EXTRACTOR_JAVA_ROOT: $CODEQL_EXTRACTOR_JAVA_ROOT"

# Java 버전 확인
echo "☕ Java 버전:"
$CODEQL_JAVA_HOME/bin/java -version

echo "🎯 CodeQL 환경 설정 완료!"
echo "이제 다음 명령으로 분석을 실행하세요:"
echo "source setup_codeql_env.sh && python run_analysis.py --llm-type gemini --api-key YOUR_API_KEY" 