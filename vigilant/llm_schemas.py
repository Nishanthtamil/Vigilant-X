from pydantic import BaseModel

class PRIntentLLMResponse(BaseModel):
    purpose: str
    changed_modules: list[str] = []
    risk_areas: list[str] = []
    code_law_violations_suspected: list[str] = []

class APISurfaceLLMResponse(BaseModel):
    sources: list[str] = []
    sinks: list[str] = []

class DeepScanFinding(BaseModel):
    rule_id: str
    severity: str  # "CRITICAL" | "ADVISORY"
    line_number: int = 0
    explanation: str = ""
    verified_fix: str = ""

class DeepScanLLMResponse(BaseModel):
    findings: list[DeepScanFinding] = []

class ContextScoreLLMResponse(BaseModel):
    score: float
    reason: str = ""

class NitpickItem(BaseModel):
    line: int = 0
    category: str = "style"
    comment: str = ""
    suggestion: str = ""

class NitpickLLMResponse(BaseModel):
    nitpicks: list[NitpickItem] = []
