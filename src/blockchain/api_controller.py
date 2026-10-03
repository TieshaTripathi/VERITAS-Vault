"""
FastAPI Controller for Blockchain Forensic AI Side-Panel.

Endpoints:
- POST /api/v1/forensics/investigate: Validates target, checks cache, evaluates heuristics, queries AI narrative, formats React Flow graph.
- POST /api/v1/forensics/vault/lock: Receives investigation payload + client PDF, generates SHA-256 hash, signs & persists to Firebase.
- GET /api/v1/forensics/cache/stats: Returns API cache metrics.
"""

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

from src.blockchain.risk_engine import RiskEngine
from src.blockchain.ai_narrative import AINarrativeGenerator
from src.blockchain.vault_service import CryptographicVault
from src.blockchain.cache_layer import ForensicCache

app = FastAPI(
    title="Blockchain Forensic AI Side-Panel API",
    description="Security Investigator API for raw chain ingestion, heuristic risk scoring, AI narrative, and cryptographic vault lock.",
    version="1.0.0"
)

# Enable CORS for React Frontend (typically running on localhost:5173 or localhost:3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize core services
risk_engine = RiskEngine()
ai_generator = AINarrativeGenerator(model_name="gpt-4o")
vault_service = CryptographicVault()
forensic_cache = ForensicCache(default_ttl_seconds=300)


class InvestigateRequest(BaseModel):
    target: str = Field(..., description="EVM wallet address (0x...) or TxHash")
    force_refresh: bool = Field(False, description="Bypass cache and force re-analysis")
    simulate_llm_failure: bool = Field(False, description="Simulate LLM failure to test rule-based fallback")


class LockVaultRequest(BaseModel):
    investigator_id: str = Field(..., description="ID or badge number of investigator locking dossier")
    target: str = Field(..., description="Target wallet address or TxHash")
    risk_evaluation: Dict[str, Any] = Field(..., description="Composite risk score and threat flags")
    ai_narrative_result: Dict[str, Any] = Field(..., description="Generated AI narrative and findings")
    pdf_base64: Optional[str] = Field(None, description="Client-generated PDF base64 string from jsPDF")


@app.get("/")
def read_root():
    return {
        "status": "ONLINE",
        "service": "Blockchain Forensic AI Side-Panel API",
        "version": "1.0.0"
    }


@app.post("/api/v1/forensics/investigate")
def investigate_target(req: InvestigateRequest):
    """
    Core forensic pipeline endpoint.
    1. Validation
    2. Cache check
    3. Heuristic data pulling & risk evaluation
    4. AI narrative generation (with fallback)
    5. React Flow node graph formatting
    """
    target = req.target.strip()

    # 1. Validate Target Format
    val_res = risk_engine.validate_address_or_tx(target)
    if not val_res["valid"]:
        raise HTTPException(status_code=400, detail=val_res["error"])

    formatted_target = val_res["formatted"]

    # 2. Check API Cache Layer (unless force_refresh is True)
    if not req.force_refresh and not req.simulate_llm_failure:
        cached_result = forensic_cache.get(formatted_target)
        if cached_result:
            cached_result["is_cached"] = True
            return cached_result

    # 3. Heuristic Engine Execution
    raw_heuristics = risk_engine.fetch_heuristics_data(formatted_target, target_type=val_res["type"])
    risk_evaluation = risk_engine.evaluate_risk(raw_heuristics)

    # 4. AI Narrative Generation
    ai_narrative_result = ai_generator.generate_narrative(
        target=formatted_target,
        risk_metrics=risk_evaluation,
        raw_heuristics=raw_heuristics,
        simulate_failure=req.simulate_llm_failure
    )

    # 5. Interactive Node Graph Context for React Flow
    graph_context = risk_engine.generate_node_graph_context(
        target=formatted_target,
        raw_data=raw_heuristics,
        risk_analysis=risk_evaluation
    )

    # Assemble complete response payload
    response_payload = {
        "target": formatted_target,
        "target_type": val_res["type"],
        "is_cached": False,
        "raw_heuristics": raw_heuristics,
        "risk_evaluation": risk_evaluation,
        "ai_narrative_result": ai_narrative_result,
        "graph_context": graph_context
    }

    # Store in Cache Layer
    forensic_cache.set(formatted_target, response_payload)

    return response_payload


@app.post("/api/v1/forensics/vault/lock")
def lock_dossier_to_vault(req: LockVaultRequest):
    """
    Cryptographic Vault Lock endpoint.
    Computes server-side SHA-256 hash, generates tamper-evident proof certificate, and commits to Firebase.
    """
    try:
        dossier = vault_service.create_court_ready_dossier(
            investigator_id=req.investigator_id,
            target_address=req.target,
            risk_evaluation=req.risk_evaluation,
            ai_narrative_result=req.ai_narrative_result,
            client_pdf_base64=req.pdf_base64
        )
        return {
            "status": "LOCKED",
            "message": "Dossier cryptographically locked and stored.",
            "dossier": dossier
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to lock dossier: {str(e)}")


@app.get("/api/v1/forensics/cache/stats")
def get_cache_stats():
    return forensic_cache.stats()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.blockchain.api_controller:app", host="0.0.0.0", port=8000, reload=True)
