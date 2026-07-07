# Terraform configuration for Click Fixed Threat Intelligence infrastructure

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.50.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ── 1. Enable Required Google Cloud APIs ──────────────────────────
resource "google_project_service" "services" {
  for_each = toset([
    "run.googleapis.com",              # Cloud Run
    "firestore.googleapis.com",        # Firestore
    "artifactregistry.googleapis.com", # Artifact Registry
    "cloudbuild.googleapis.com",       # Cloud Build (for docker builds)
    "webrisk.googleapis.com",          # Web Risk API
    "aiplatform.googleapis.com",       # Vertex AI API
    "cloudtrace.googleapis.com",       # Cloud Trace API
    "agentregistry.googleapis.com",     # Agent Registry API
    "storage.googleapis.com"           # Cloud Storage API
  ])
  service            = each.key
  disable_on_destroy = false
}

# ── 2. Provision Firestore Database (Native Mode) ──────────────────
# Note: Google Cloud allows one Firestore database named "(default)" per project.
resource "google_firestore_database" "database" {
  name        = "(default)"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"

  # Ensure APIs are enabled before creating the database
  depends_on = [google_project_service.services]
}

# ── 2.1. Provision Staging GCS Bucket for Agent Deployment ──────────
resource "google_storage_bucket" "agent_staging" {
  name          = "clickfixed-agent-staging-${var.project_id}"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true

  depends_on = [google_project_service.services]
}

# ── 3. Artifact Registry for Agent Docker Container ───────────────
resource "google_artifact_registry_repository" "repo" {
  location      = var.region
  repository_id = "clickfixed-agent-repo"
  description   = "Docker repository for Click Fixed ADK Threat Intel Agent"
  format        = "DOCKER"

  depends_on = [google_project_service.services]
}

# ── 4. Dedicated Service Account for Cloud Run ───────────────────
resource "google_service_account" "agent_sa" {
  account_id   = "clickfixed-agent-sa"
  display_name = "Click Fixed ADK Agent Service Account"
}

# Grant Datastore User role to allow read/write access to Firestore
resource "google_project_iam_member" "firestore_access" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.agent_sa.email}"
}

# Grant Vertex AI User role to allow agent model inference
resource "google_project_iam_member" "vertex_access" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.agent_sa.email}"
}

# Grant Storage Object Admin role to the service account on the staging bucket
resource "google_storage_bucket_iam_member" "staging_bucket_access" {
  bucket = google_storage_bucket.agent_staging.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.agent_sa.email}"
}

# ── 5. Cloud Run Service ──────────────────────────────────────────
# Prepares the Cloud Run configuration.
# Note: Before running 'terraform apply' the first time, you can deploy a placeholder image,
# or push the Docker image to the registry. We configure this with a placeholder image first
# so the infrastructure deploys successfully, and then you can push the real container via ADK.
resource "google_cloud_run_v2_service" "agent_service" {
  name     = "clickfixed-threat-agent"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false

  template {
    service_account = google_service_account.agent_sa.email

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.repo.repository_id}/agent:latest"

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      env {
        name  = "GOOGLE_API_KEY"
        value = var.gemini_api_key
      }

      env {
        name  = "FIRESTORE_PROJECT_ID"
        value = var.project_id
      }

      env {
        name  = "REASONING_ENGINE_DISPLAY_NAME"
        value = "ClickFixed Threat Pipeline"
      }

      env {
        name  = "WEBRISK_API_KEY"
        value = var.webrisk_api_key
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_project_service.services,
    google_artifact_registry_repository.repo,
    google_firestore_database.database
  ]
}

# Allow unauthenticated access (public ingress) for A2A communication
resource "google_cloud_run_v2_service_iam_member" "public_access" {
  location = google_cloud_run_v2_service.agent_service.location
  name     = google_cloud_run_v2_service.agent_service.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
