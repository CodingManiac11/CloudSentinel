"""
CloudSentinel REST API

FastAPI-based REST API for programmatic access to CloudSentinel.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path
import asyncio
import uuid
import os

# Determine the base directory - works both locally and on Railway
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Try multiple possible frontend locations
POSSIBLE_FRONTEND_DIRS = [
    BASE_DIR / "dashboard" / "dist",
    Path("/app/dashboard/dist"),  # Docker/Railway path
    Path(os.environ.get("FRONTEND_DIR", "")) if os.environ.get("FRONTEND_DIR") else None,
]

FRONTEND_DIR = None
for path in POSSIBLE_FRONTEND_DIRS:
    if path and path.exists():
        FRONTEND_DIR = path
        break

# Fallback to default if none found
if FRONTEND_DIR is None:
    FRONTEND_DIR = BASE_DIR / "dashboard" / "dist"

# Create FastAPI app
app = FastAPI(
    title="CloudSentinel API",
    description="Cloud Misconfiguration Security Scanner API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scans (in production, use a database)
scans_db: Dict[str, Any] = {}
remediations_db: Dict[str, Any] = {}


# Request/Response models
class ScanRequest(BaseModel):
    providers: List[str] = ["aws", "azure", "kubernetes"]
    demo_mode: bool = True
    include_predictions: bool = True


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class RemediationRequest(BaseModel):
    misconfiguration_id: str
    auto_apply: bool = False


class ApprovalRequest(BaseModel):
    approval_id: str
    approved: bool
    comment: Optional[str] = None


# API Routes

@app.get("/")
async def root():
    """Serve frontend at root, or API info if not built"""
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "service": "CloudSentinel API",
        "version": "1.0.0",
        "status": "healthy",
        "docs": "/api/docs",
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.post("/scans", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Create a new security scan.
    
    The scan runs in the background. Use GET /scans/{scan_id} to check status.
    """
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    
    # Initialize scan record
    scans_db[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "providers": request.providers,
        "demo_mode": request.demo_mode,
        "results": None,
    }
    
    # Run scan in background
    background_tasks.add_task(run_scan_task, scan_id, request)
    
    return ScanResponse(
        scan_id=scan_id,
        status="running",
        message="Scan started. Use GET /scans/{scan_id} to check status."
    )


async def run_scan_task(scan_id: str, request: ScanRequest):
    """Background task to run the scan"""
    try:
        from ..discovery.aws_provider import AWSProvider
        from ..discovery.azure_provider import AzureProvider
        from ..discovery.kubernetes_provider import KubernetesProvider
        from ..discovery.resource_graph import ResourceGraphBuilder
        from ..detection.detection_engine import DetectionEngine
        from ..risk.attack_graph import AttackGraphGenerator
        from ..risk.prioritizer import RiskPrioritizer
        from ..ai.predictive_detector import PredictiveDetector
        
        all_resources = []
        
        # Discover resources
        if "aws" in request.providers:
            aws = AWSProvider()
            await aws.connect()
            all_resources.extend(await aws.discover_resources())
        
        if "azure" in request.providers:
            azure = AzureProvider()
            await azure.connect()
            all_resources.extend(await azure.discover_resources())
        
        if "kubernetes" in request.providers:
            k8s = KubernetesProvider()
            await k8s.connect()
            all_resources.extend(await k8s.discover_resources())
        
        # Build graph and run detection
        graph = ResourceGraphBuilder()
        graph.add_resources(all_resources)
        
        engine = DetectionEngine()
        scan_result = engine.scan_resources(all_resources)
        
        # Generate attack paths
        attack_gen = AttackGraphGenerator(graph)
        attack_paths = attack_gen.generate_attack_paths(scan_result.misconfigurations)
        
        # Prioritize
        prioritizer = RiskPrioritizer()
        priority_summary = prioritizer.summarize_priorities(
            prioritizer.prioritize_findings(scan_result.misconfigurations, attack_paths)
        )
        
        # Predictions
        predictions = {}
        if request.include_predictions:
            predictor = PredictiveDetector()
            pred_results = predictor.analyze_and_predict(all_resources)
            predictions = predictor.get_prediction_summary(pred_results)
        
        # Update scan record
        scans_db[scan_id].update({
            "status": "completed",
            "completed_at": datetime.now().isoformat(),
            "results": {
                "resources_scanned": len(all_resources),
                "misconfigurations": scan_result.to_dict(),
                "attack_paths": [ap.to_dict() for ap in attack_paths],
                "priority_summary": priority_summary,
                "predictions": predictions,
                "overall_grade": scan_result.overall_grade,
                "overall_risk_score": scan_result.overall_risk_score,
            }
        })
    except Exception as e:
        scans_db[scan_id].update({
            "status": "failed",
            "error": str(e),
        })


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    """
    Get scan status and results.
    """
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scans_db[scan_id]


@app.get("/scans")
async def list_scans(limit: int = 10, status: Optional[str] = None):
    """
    List all scans.
    """
    scans = list(scans_db.values())
    
    if status:
        scans = [s for s in scans if s.get("status") == status]
    
    return {
        "scans": scans[:limit],
        "total": len(scans),
    }


@app.get("/scans/{scan_id}/misconfigurations")
async def get_misconfigurations(scan_id: str, severity: Optional[str] = None):
    """
    Get misconfigurations from a scan.
    """
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans_db[scan_id]
    if scan.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed")
    
    misconfigs = scan.get("results", {}).get("misconfigurations", {}).get("misconfigurations", [])
    
    if severity:
        misconfigs = [m for m in misconfigs if m.get("severity") == severity]
    
    return {"misconfigurations": misconfigs, "total": len(misconfigs)}


@app.get("/scans/{scan_id}/attack-paths")
async def get_attack_paths(scan_id: str):
    """
    Get attack paths from a scan.
    """
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans_db[scan_id]
    if scan.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed")
    
    attack_paths = scan.get("results", {}).get("attack_paths", [])
    
    return {"attack_paths": attack_paths, "total": len(attack_paths)}


@app.post("/remediations")
async def create_remediation(request: RemediationRequest):
    """
    Create a remediation action for a misconfiguration.
    """
    remediation_id = f"rem-{uuid.uuid4().hex[:8]}"
    
    remediations_db[remediation_id] = {
        "id": remediation_id,
        "misconfiguration_id": request.misconfiguration_id,
        "status": "pending_approval" if not request.auto_apply else "approved",
        "created_at": datetime.now().isoformat(),
        "auto_apply": request.auto_apply,
    }
    
    return {
        "remediation_id": remediation_id,
        "status": remediations_db[remediation_id]["status"],
        "message": "Remediation created. Approval required." if not request.auto_apply else "Remediation approved for execution."
    }


@app.get("/remediations/{remediation_id}")
async def get_remediation(remediation_id: str):
    """
    Get remediation status.
    """
    if remediation_id not in remediations_db:
        raise HTTPException(status_code=404, detail="Remediation not found")
    
    return remediations_db[remediation_id]


@app.post("/remediations/{remediation_id}/approve")
async def approve_remediation(remediation_id: str, request: ApprovalRequest):
    """
    Approve or reject a remediation.
    """
    if remediation_id not in remediations_db:
        raise HTTPException(status_code=404, detail="Remediation not found")
    
    remediations_db[remediation_id].update({
        "status": "approved" if request.approved else "rejected",
        "approved_at": datetime.now().isoformat(),
        "comment": request.comment,
    })
    
    return remediations_db[remediation_id]


@app.post("/remediations/{remediation_id}/execute")
async def execute_remediation(remediation_id: str):
    """
    Execute an approved remediation.
    """
    if remediation_id not in remediations_db:
        raise HTTPException(status_code=404, detail="Remediation not found")
    
    rem = remediations_db[remediation_id]
    if rem.get("status") != "approved":
        raise HTTPException(status_code=400, detail="Remediation must be approved first")
    
    # Simulate execution
    remediations_db[remediation_id].update({
        "status": "completed",
        "executed_at": datetime.now().isoformat(),
        "result": "success",
    })
    
    return remediations_db[remediation_id]


@app.get("/dashboard/summary")
async def get_dashboard_summary():
    """
    Get dashboard summary data.
    """
    # Find the most recent completed scan
    completed_scans = [s for s in scans_db.values() if s.get("status") == "completed"]
    
    if not completed_scans:
        return {
            "message": "No completed scans. Run a scan first.",
            "total_scans": len(scans_db),
        }
    
    latest = completed_scans[-1]
    results = latest.get("results", {})
    
    return {
        "latest_scan_id": latest.get("scan_id"),
        "overall_grade": results.get("overall_grade", "?"),
        "overall_risk_score": results.get("overall_risk_score", 0),
        "resources_scanned": results.get("resources_scanned", 0),
        "findings_summary": results.get("misconfigurations", {}).get("findings", {}),
        "attack_paths_count": len(results.get("attack_paths", [])),
        "predictions": results.get("predictions", {}),
        "priority_summary": results.get("priority_summary", {}),
    }


# --- Serve Frontend Static Files ---

# Mount static assets if frontend is built
if FRONTEND_DIR.exists():
    # Serve static assets (JS, CSS, images)
    assets_dir = FRONTEND_DIR / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")


# Catch-all route for React SPA - must be last!
@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    """
    Serve the React frontend for all non-API routes.
    This enables client-side routing.
    """
    # Check if requesting a static file
    file_path = FRONTEND_DIR / full_path
    if file_path.exists() and file_path.is_file():
        return FileResponse(file_path)
    
    # For all other routes, serve index.html (React will handle routing)
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    
    # If frontend not built, return API info
    return {
        "message": "CloudSentinel API",
        "docs": "/api/docs",
        "note": "Frontend not built. Run 'npm run build' in dashboard/ directory."
    }
