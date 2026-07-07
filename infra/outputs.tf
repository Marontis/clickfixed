output "artifact_registry_uri" {
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.repo.repository_id}"
  description = "The URI of the Artifact Registry repository to push the agent image to"
}

output "agent_service_url" {
  value       = google_cloud_run_v2_service.agent_service.uri
  description = "The public endpoint of the deployed ADK Threat Intel Agent (paste this in extension Options)"
}

output "service_account_email" {
  value       = google_service_account.agent_sa.email
  description = "The dedicated service account created for the threat agent container"
}

output "deploy_guide" {
  value = <<EOT
================================================================================
Click Fixed Infrastructure Provisioned!
================================================================================

1. Build and push your Docker container to the Artifact Registry repository:
   gcloud auth configure-docker ${var.region}-docker.pkg.dev
   
   cd ../agent
   docker build -t ${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.repo.repository_id}/agent:latest .
   docker push ${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.repo.repository_id}/agent:latest

2. Copy the endpoint URL and paste it in the Chrome Extension's Options page:
   ${google_cloud_run_v2_service.agent_service.uri}
================================================================================
EOT
  description = "Helpful instructions for completing the deployment"
}
