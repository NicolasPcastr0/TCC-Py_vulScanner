from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    category: str
    name: str
    test: str
    status: str
    severity: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    