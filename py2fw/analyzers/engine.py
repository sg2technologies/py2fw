from __future__ import annotations

from py2fw.analyzers.attack_surface import find_attack_surface
from py2fw.analyzers.duplicate_rules import find_duplicate_rules
from py2fw.analyzers.hygiene import find_documentation_gaps
from py2fw.analyzers.models import AnalysisReport
from py2fw.analyzers.risk_score import calculate_risk_score
from py2fw.analyzers.shadow_rules import find_shadowed_rules
from py2fw.analyzers.unused_objects import find_unused_objects, find_unused_services
from py2fw.compiler.ir import FirewallIR


def analyze_ir(ir: FirewallIR) -> AnalysisReport:
    findings = [
        *find_attack_surface(ir),
        *find_duplicate_rules(ir),
        *find_shadowed_rules(ir),
        *find_unused_objects(ir),
        *find_unused_services(ir),
        *find_documentation_gaps(ir),
    ]
    return AnalysisReport(risk_score=calculate_risk_score(findings), findings=tuple(findings))
