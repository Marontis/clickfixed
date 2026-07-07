"""
ClickFixed — Agent Platform Deployer
====================================

Deploys the ADK threat pipeline from agent.py to the Google Cloud Agent Platform.
Usage:
  python deploy.py
"""

import os
import subprocess
import sys
import vertexai
from vertexai.preview import reasoning_engines

def run_command(cmd: list) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except subprocess.CalledProcessError as exc:
        print(f"Error running cmd {' '.join(cmd)}: {exc.stderr}")
        return ""
    except Exception as exc:
        print(f"Error running cmd {' '.join(cmd)}: {exc}")
        return ""

def main():
    print("[ClickFixed Deployer] Auto-detecting GCP configurations...")
    
    # 1. Resolve Project ID
    project_id = os.environ.get("PROJECT_ID") or os.environ.get("FIRESTORE_PROJECT_ID")
    if not project_id:
        project_id = run_command(["gcloud", "config", "get-value", "project"])
        
    if not project_id:
        print("CRITICAL: Could not resolve GCP Project ID. Set PROJECT_ID environment variable or authenticate via gcloud.")
        sys.exit(1)
        
    # 2. Resolve Region
    region = os.environ.get("REGION")
    if not region:
        region = run_command(["gcloud", "config", "get-value", "compute/region"])
    if not region:
        region = "us-central1" # default fallback
        
    staging_bucket = f"gs://clickfixed-agent-staging-{project_id}"
    
    print(f"[ClickFixed Deployer] Target Project: {project_id}")
    print(f"[ClickFixed Deployer] Target Region:  {region}")
    print(f"[ClickFixed Deployer] Staging Bucket: {staging_bucket}")
    
    # Initialize Vertex AI SDK
    vertexai.init(
        project=project_id,
        location=region,
        staging_bucket=staging_bucket
    )
    
    # Import the ADK app to deploy
    # Note: importing agent.py triggers instruction loading from local skills/ directories
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from agent import app as adk_app
    
    # Define required package dependencies for the Reasoning Engine environment
    requirements = [
        "google-adk[a2a,mcp]>=1.0.0",
        "google-cloud-aiplatform>=1.48.0",
        "google-generativeai>=0.8.0",
        "httpx>=0.27.0",
        "python-dotenv>=1.0.0"
    ]
    
    print("[ClickFixed Deployer] Starting deployment to Vertex AI Agent Engine (Reasoning Engine)...")
    try:
        remote_agent = reasoning_engines.ReasoningEngine.create(
            reasoning_engine=adk_app,
            requirements=requirements,
            extra_packages=["agent.py", "skills"],
            display_name="ClickFixed Threat Pipeline"
        )
        print("\n==========================================================================")
        print("[SUCCESS] Agent deployed successfully to Google Cloud Agent Platform!")
        print(f"Resource Name: {remote_agent.resource_name}")
        print("==========================================================================\n")
    except Exception as exc:
        print(f"\n[ERROR] Deployment failed: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
