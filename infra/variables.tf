variable "project_id" {
  type        = string
  description = "The GCP Project ID where resources will be provisioned"
}

variable "region" {
  type        = string
  description = "The target deployment region (e.g., us-central1)"
  default     = "us-central1"
}

variable "gemini_api_key" {
  type        = string
  sensitive   = true
  description = "The Gemini API Key from Google AI Studio used by the Threat Intel Agent"
}

variable "webrisk_api_key" {
  type        = string
  sensitive   = true
  description = "Optional Web Risk Submission API key (leave empty to use Safe Browsing fallback)"
  default     = ""
}
