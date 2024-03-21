terraform {
  # This module is now only being tested with Terraform 0.13.x. However, to make upgrading easier, we are setting
  # 0.12.26 as the minimum version, as that version added support for required_providers with source URLs, making it
  # forwards compatible with 0.13.x code.
  required_version = ">= 0.12.26"
}

provider "google" {
  region = "us-central1"
}

# website::tag::1:: Deploy a cloud instance
resource "google_compute_instance" "example" {
  name         = var.instance_name
  machine_type = "e2-highcpu-32"
  zone         = "us-central1-c"

  # website::tag::2:: Run Ubuntu 22.04 on the instance
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }
}

# website::tag::3:: Allow the user to pass in a custom name for the instance
variable "instance_name" {
  description = "The Name to use for the Cloud Instance."
  default     = "gcp-hello-world-example"
}
