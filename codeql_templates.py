"""
고급 CodeQL 템플릿 시스템
LLM이 제공하는 구체적 정보를 바탕으로 다양한 분석 기법의 CodeQL 쿼리를 동적 생성
"""

from typing import Dict, List, Any
import json

class CodeQLTemplateEngine:
    """CodeQL 템플릿 기반 쿼리 생성 엔진"""
    
    def __init__(self):
        self.templates = {
            "dataflow": self._get_dataflow_template(),
            "controlflow": self._get_controlflow_template(),
            "tainttracking": self._get_tainttracking_template(),
            "typetracking": self._get_typetracking_template(),
            "valuetracking": self._get_valuetracking_template()
        }
    
    def generate_query(self, template_type: str, llm_info: Dict[str, Any], vuln_id: int, func_name: str) -> str:
        """LLM 정보를 바탕으로 CodeQL 쿼리 생성"""
        if template_type not in self.templates:
            raise ValueError(f"Unknown template type: {template_type}")
        
        template = self.templates[template_type]
        return template.format(
            vuln_id=vuln_id,
            func_name=func_name,
            **llm_info
        )
    
    def _get_dataflow_template(self) -> str:
        """DataFlow 분석 템플릿"""
        return '''/**
 * @name {name}
 * @description {description}
 * @kind problem
 * @problem.severity {severity}
 * @id java/vuln-{vuln_id}-{func_name}-dataflow
 */

import java
import semmle.code.java.dataflow.DataFlow

{source_classes}

{sink_classes}

{sanitizer_classes}

class VulnConfig extends DataFlow::Configuration {{
  VulnConfig() {{ this = "VulnConfig" }}
  
  override predicate isSource(DataFlow::Node source) {{
    {source_predicates}
  }}
  
  override predicate isSink(DataFlow::Node sink) {{
    {sink_predicates}
  }}
  
  override predicate isBarrier(DataFlow::Node node) {{
    {barrier_predicates}
  }}
}}

from VulnConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "DataFlow: {vulnerability_desc} from $@ to $@",
       source, "source", sink, "sink"
'''

    def _get_controlflow_template(self) -> str:
        """ControlFlow 분석 템플릿"""
        return '''/**
 * @name {name}
 * @description {description}
 * @kind problem
 * @problem.severity {severity}
 * @id java/vuln-{vuln_id}-{func_name}-controlflow
 */

import java

{condition_classes}

{branch_classes}

{loop_classes}

from Method m, {control_elements}
where 
  m.getName() = "{func_name}" and
  {control_conditions} and
  {vulnerability_conditions}
select {select_element}, "ControlFlow: {vulnerability_desc} in control structure"
'''

    def _get_tainttracking_template(self) -> str:
        """TaintTracking 분석 템플릿"""
        return '''/**
 * @name {name}
 * @description {description}
 * @kind path-problem
 * @problem.severity {severity}
 * @id java/vuln-{vuln_id}-{func_name}-taint
 */

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

{taint_source_classes}

{taint_sink_classes}

{additional_taint_step_classes}

class TaintConfig extends TaintTracking::Configuration {{
  TaintConfig() {{ this = "TaintConfig" }}
  
  override predicate isSource(DataFlow::Node source) {{
    {taint_source_predicates}
  }}
  
  override predicate isSink(DataFlow::Node sink) {{
    {taint_sink_predicates}
  }}
  
  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {{
    {additional_taint_steps}
  }}
}}

from TaintConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "TaintTracking: {vulnerability_desc} flows from $@ to $@",
       source.getNode(), "taint source", sink.getNode(), "taint sink"
'''

    def _get_typetracking_template(self) -> str:
        """TypeTracking 분석 템플릿"""
        return '''/**
 * @name {name}
 * @description {description}
 * @kind problem
 * @problem.severity {severity}
 * @id java/vuln-{vuln_id}-{func_name}-typetrack
 */

import java
import semmle.code.java.dataflow.TypeTracker

{type_source_classes}

{type_sink_classes}

{type_conversion_classes}

predicate typeFlowStep(DataFlow::Node node1, DataFlow::Node node2) {{
  {type_flow_conditions}
}}

DataFlow::Node trackType(TypeTracker t) {{
  t.start() and
  {type_start_conditions}
  or
  exists(TypeTracker t2 | result = trackType(t2).track(t2, t))
}}

DataFlow::Node trackType() {{ result = trackType(TypeTracker::end()) }}

from DataFlow::Node source, DataFlow::Node sink
where 
  source = trackType() and
  {type_sink_conditions} and
  sink = {type_sink_expression}
select sink, "TypeTracking: {vulnerability_desc} involves type flow from $@ to $@",
       source, "type source", sink, "type sink"
'''

    def _get_valuetracking_template(self) -> str:
        """ValueTracking 분석 템플릿"""
        return '''/**
 * @name {name}
 * @description {description}
 * @kind problem
 * @problem.severity {severity}
 * @id java/vuln-{vuln_id}-{func_name}-valuetrack
 */

import java

{value_source_classes}

{value_sink_classes}

{value_transformation_classes}

predicate valueFlowStep(DataFlow::Node node1, DataFlow::Node node2) {{
  {value_flow_conditions}
}}

from DataFlow::Node source, DataFlow::Node sink
where 
  {value_source_conditions} and
  {value_transformation_conditions} and
  {value_sink_conditions}
select sink, "ValueTracking: {vulnerability_desc} involves value flow from $@ to $@",
       source, "value source", sink, "value sink"
'''


class CodeQLInfoExtractor:
    """LLM 응답에서 CodeQL 생성에 필요한 정보 추출"""
    
    def extract_dataflow_info(self, llm_response: Dict[str, Any], func_name: str) -> Dict[str, Any]:
        """DataFlow 분석에 필요한 정보 추출"""
        vulnerability = llm_response.get("vulnerabilities", [{}])[0]
        
        return {
            "name": f"DataFlow Analysis for {func_name}",
            "description": vulnerability.get("description", f"DataFlow vulnerability in {func_name}"),
            "severity": vulnerability.get("severity", "high"),
            "vulnerability_desc": vulnerability.get("type", "Unknown vulnerability"),
            
            # Source 정보
            "source_classes": self._generate_source_classes(llm_response.get("sources", [])),
            "source_predicates": self._generate_source_predicates(llm_response.get("sources", [])),
            
            # Sink 정보  
            "sink_classes": self._generate_sink_classes(llm_response.get("sinks", [])),
            "sink_predicates": self._generate_sink_predicates(llm_response.get("sinks", [])),
            
            # Sanitizer 정보
            "sanitizer_classes": self._generate_sanitizer_classes(llm_response.get("sanitizers", [])),
            "barrier_predicates": self._generate_barrier_predicates(llm_response.get("sanitizers", []))
        }
    
    def extract_controlflow_info(self, llm_response: Dict[str, Any], func_name: str) -> Dict[str, Any]:
        """ControlFlow 분석에 필요한 정보 추출"""
        vulnerability = llm_response.get("vulnerabilities", [{}])[0]
        
        return {
            "name": f"ControlFlow Analysis for {func_name}",
            "description": vulnerability.get("description", f"ControlFlow vulnerability in {func_name}"),
            "severity": vulnerability.get("severity", "high"),
            "vulnerability_desc": vulnerability.get("type", "Unknown vulnerability"),
            
            # Control 구조 정보
            "condition_classes": self._generate_condition_classes(llm_response.get("conditions", [])),
            "branch_classes": self._generate_branch_classes(llm_response.get("branches", [])),
            "loop_classes": self._generate_loop_classes(llm_response.get("loops", [])),
            
            # Control flow 조건들
            "control_elements": self._generate_control_elements(llm_response),
            "control_conditions": self._generate_control_conditions(llm_response),
            "vulnerability_conditions": self._generate_vulnerability_conditions(llm_response),
            "select_element": self._generate_select_element(llm_response)
        }
    
    def extract_tainttracking_info(self, llm_response: Dict[str, Any], func_name: str) -> Dict[str, Any]:
        """TaintTracking 분석에 필요한 정보 추출"""
        vulnerability = llm_response.get("vulnerabilities", [{}])[0]
        
        return {
            "name": f"TaintTracking Analysis for {func_name}",
            "description": vulnerability.get("description", f"TaintTracking vulnerability in {func_name}"),
            "severity": vulnerability.get("severity", "high"),
            "vulnerability_desc": vulnerability.get("type", "Unknown vulnerability"),
            
            # Taint source/sink 정보
            "taint_source_classes": self._generate_taint_source_classes(llm_response.get("taint_sources", [])),
            "taint_source_predicates": self._generate_taint_source_predicates(llm_response.get("taint_sources", [])),
            
            "taint_sink_classes": self._generate_taint_sink_classes(llm_response.get("taint_sinks", [])),
            "taint_sink_predicates": self._generate_taint_sink_predicates(llm_response.get("taint_sinks", [])),
            
            # Additional taint step 정보
            "additional_taint_step_classes": self._generate_additional_taint_step_classes(llm_response.get("taint_steps", [])),
            "additional_taint_steps": self._generate_additional_taint_steps(llm_response.get("taint_steps", []))
        }
    
    def extract_typetracking_info(self, llm_response: Dict[str, Any], func_name: str) -> Dict[str, Any]:
        """TypeTracking 분석에 필요한 정보 추출"""
        vulnerability = llm_response.get("vulnerabilities", [{}])[0]
        
        return {
            "name": f"TypeTracking Analysis for {func_name}",
            "description": vulnerability.get("description", f"TypeTracking vulnerability in {func_name}"),
            "severity": vulnerability.get("severity", "high"),
            "vulnerability_desc": vulnerability.get("type", "Unknown vulnerability"),
            
            # Type tracking 정보
            "type_source_classes": self._generate_type_source_classes(llm_response.get("type_sources", [])),
            "type_sink_classes": self._generate_type_sink_classes(llm_response.get("type_sinks", [])),
            "type_conversion_classes": self._generate_type_conversion_classes(llm_response.get("type_conversions", [])),
            
            # Type flow 조건들
            "type_flow_conditions": self._generate_type_flow_conditions(llm_response),
            "type_start_conditions": self._generate_type_start_conditions(llm_response),
            "type_sink_conditions": self._generate_type_sink_conditions(llm_response),
            "type_sink_expression": self._generate_type_sink_expression(llm_response)
        }
    
    def extract_valuetracking_info(self, llm_response: Dict[str, Any], func_name: str) -> Dict[str, Any]:
        """ValueTracking 분석에 필요한 정보 추출"""
        vulnerability = llm_response.get("vulnerabilities", [{}])[0]
        
        return {
            "name": f"ValueTracking Analysis for {func_name}",
            "description": vulnerability.get("description", f"ValueTracking vulnerability in {func_name}"),
            "severity": vulnerability.get("severity", "high"),
            "vulnerability_desc": vulnerability.get("type", "Unknown vulnerability"),
            
            # Value tracking 정보
            "value_source_classes": self._generate_value_source_classes(llm_response.get("value_sources", [])),
            "value_sink_classes": self._generate_value_sink_classes(llm_response.get("value_sinks", [])),
            "value_transformation_classes": self._generate_value_transformation_classes(llm_response.get("value_transformations", [])),
            
            # Value flow 조건들
            "value_flow_conditions": self._generate_value_flow_conditions(llm_response),
            "value_source_conditions": self._generate_value_source_conditions(llm_response),
            "value_transformation_conditions": self._generate_value_transformation_conditions(llm_response),
            "value_sink_conditions": self._generate_value_sink_conditions(llm_response)
        }
    
    # Helper methods for generating CodeQL components
    def _generate_source_classes(self, sources: List[Dict[str, Any]]) -> str:
        """Source 클래스들 생성"""
        if not sources:
            return """class VulnSource extends DataFlow::Node {
  VulnSource() {
    this.asParameter().getName().matches("parser")
  }
}"""
        
        classes = []
        for i, source in enumerate(sources):
            class_name = f"VulnSource{i+1}" if len(sources) > 1 else "VulnSource"
            condition = source.get("condition", 'this.asParameter().getName().matches("input")')
            classes.append(f"""class {class_name} extends DataFlow::Node {{
  {class_name}() {{
    {condition}
  }}
}}""")
        return "\n\n".join(classes)
    
    def _generate_source_predicates(self, sources: List[Dict[str, Any]]) -> str:
        """Source predicate들 생성"""
        if not sources:
            return "source instanceof VulnSource"
        
        predicates = []
        for i, source in enumerate(sources):
            class_name = f"VulnSource{i+1}" if len(sources) > 1 else "VulnSource"
            predicates.append(f"source instanceof {class_name}")
        return " or\n    ".join(predicates)
    
    def _generate_sink_classes(self, sinks: List[Dict[str, Any]]) -> str:
        """Sink 클래스들 생성"""
        if not sinks:
            return """class VulnSink extends DataFlow::Node {
  VulnSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("parseArray") and
      this.asExpr() = ma
    )
  }
}"""
        
        classes = []
        for i, sink in enumerate(sinks):
            class_name = f"VulnSink{i+1}" if len(sinks) > 1 else "VulnSink"
            condition = sink.get("condition", 'exists(MethodAccess ma | ma.getMethod().getName().matches("dangerous") and this.asExpr() = ma)')
            classes.append(f"""class {class_name} extends DataFlow::Node {{
  {class_name}() {{
    {condition}
  }}
}}""")
        return "\n\n".join(classes)
    
    def _generate_sink_predicates(self, sinks: List[Dict[str, Any]]) -> str:
        """Sink predicate들 생성"""
        if not sinks:
            return "sink instanceof VulnSink"
        
        predicates = []
        for i, sink in enumerate(sinks):
            class_name = f"VulnSink{i+1}" if len(sinks) > 1 else "VulnSink"
            predicates.append(f"sink instanceof {class_name}")
        return " or\n    ".join(predicates)
    
    def _generate_sanitizer_classes(self, sanitizers: List[Dict[str, Any]]) -> str:
        """Sanitizer 클래스들 생성"""
        if not sanitizers:
            return ""
        
        classes = []
        for i, sanitizer in enumerate(sanitizers):
            class_name = f"VulnSanitizer{i+1}" if len(sanitizers) > 1 else "VulnSanitizer"
            condition = sanitizer.get("condition", 'this.asExpr().(MethodAccess).getMethod().getName() = "sanitize"')
            classes.append(f"""class {class_name} extends DataFlow::Node {{
  {class_name}() {{
    {condition}
  }}
}}""")
        return "\n\n".join(classes)
    
    def _generate_barrier_predicates(self, sanitizers: List[Dict[str, Any]]) -> str:
        """Barrier predicate들 생성"""
        if not sanitizers:
            return "none()"
        
        predicates = []
        for i, sanitizer in enumerate(sanitizers):
            class_name = f"VulnSanitizer{i+1}" if len(sanitizers) > 1 else "VulnSanitizer"
            predicates.append(f"node instanceof {class_name}")
        return " or\n    ".join(predicates)
    
    # ControlFlow 관련 helper methods
    def _generate_condition_classes(self, conditions: List[Dict[str, Any]]) -> str:
        """Condition 클래스들 생성"""
        return "// Condition classes will be generated based on LLM analysis"
    
    def _generate_branch_classes(self, branches: List[Dict[str, Any]]) -> str:
        """Branch 클래스들 생성"""
        return "// Branch classes will be generated based on LLM analysis"
    
    def _generate_loop_classes(self, loops: List[Dict[str, Any]]) -> str:
        """Loop 클래스들 생성"""
        return "// Loop classes will be generated based on LLM analysis"
    
    def _generate_control_elements(self, llm_response: Dict[str, Any]) -> str:
        """Control element 변수들 생성"""
        return "IfStmt ifstmt"
    
    def _generate_control_conditions(self, llm_response: Dict[str, Any]) -> str:
        """Control 조건들 생성"""
        return "ifstmt.getEnclosingCallable() = m"
    
    def _generate_vulnerability_conditions(self, llm_response: Dict[str, Any]) -> str:
        """취약점 조건들 생성"""
        return "// Vulnerability conditions based on LLM analysis"
    
    def _generate_select_element(self, llm_response: Dict[str, Any]) -> str:
        """Select 요소 생성"""
        return "ifstmt"
    
    # TaintTracking, TypeTracking, ValueTracking의 나머지 helper methods도 유사하게 구현
    def _generate_taint_source_classes(self, taint_sources: List[Dict[str, Any]]) -> str:
        return self._generate_source_classes(taint_sources)
    
    def _generate_taint_source_predicates(self, taint_sources: List[Dict[str, Any]]) -> str:
        return self._generate_source_predicates(taint_sources)
    
    def _generate_taint_sink_classes(self, taint_sinks: List[Dict[str, Any]]) -> str:
        return self._generate_sink_classes(taint_sinks)
    
    def _generate_taint_sink_predicates(self, taint_sinks: List[Dict[str, Any]]) -> str:
        return self._generate_sink_predicates(taint_sinks)
    
    def _generate_additional_taint_step_classes(self, taint_steps: List[Dict[str, Any]]) -> str:
        return "// Additional taint step classes"
    
    def _generate_additional_taint_steps(self, taint_steps: List[Dict[str, Any]]) -> str:
        return "// Additional taint steps"
    
    # TypeTracking helper methods
    def _generate_type_source_classes(self, type_sources: List[Dict[str, Any]]) -> str:
        return "// Type source classes"
    
    def _generate_type_sink_classes(self, type_sinks: List[Dict[str, Any]]) -> str:
        return "// Type sink classes"
    
    def _generate_type_conversion_classes(self, type_conversions: List[Dict[str, Any]]) -> str:
        return "// Type conversion classes"
    
    def _generate_type_flow_conditions(self, llm_response: Dict[str, Any]) -> str:
        return "// Type flow conditions"
    
    def _generate_type_start_conditions(self, llm_response: Dict[str, Any]) -> str:
        return "// Type start conditions"
    
    def _generate_type_sink_conditions(self, llm_response: Dict[str, Any]) -> str:
        return "// Type sink conditions"
    
    def _generate_type_sink_expression(self, llm_response: Dict[str, Any]) -> str:
        return "// Type sink expression"
    
    # ValueTracking helper methods
    def _generate_value_source_classes(self, value_sources: List[Dict[str, Any]]) -> str:
        return "// Value source classes"
    
    def _generate_value_sink_classes(self, value_sinks: List[Dict[str, Any]]) -> str:
        return "// Value sink classes"
    
    def _generate_value_transformation_classes(self, value_transformations: List[Dict[str, Any]]) -> str:
        return "// Value transformation classes"
    
    def _generate_value_flow_conditions(self, llm_response: Dict[str, Any]) -> str:
        return "// Value flow conditions"
    
    def _generate_value_source_conditions(self, llm_response: Dict[str, Any]) -> str:
        return "// Value source conditions"
    
    def _generate_value_transformation_conditions(self, llm_response: Dict[str, Any]) -> str:
        return "// Value transformation conditions"
    
    def _generate_value_sink_conditions(self, llm_response: Dict[str, Any]) -> str:
        return "// Value sink conditions" 