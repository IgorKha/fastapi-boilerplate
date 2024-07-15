# System Software Documentation

This document provides an overview of the software components located in the `system` directory of the web-API project. The `system` directory contains essential configurations and services required for the operation of the backend and security aspects of the project.

## Contents

- [System Software Documentation](#system-software-documentation)
  - [Contents](#contents)
  - [Backend Services](#backend-services)
    - [API Service](#api-service)
  - [Security Certificates](#security-certificates)
    - [Cert Bootstrap](#cert-bootstrap)
  - [Nginx Configuration](#nginx-configuration)
  - [Conclusion](#conclusion)

## Backend Services

### API Service

The `fastapi-api.service` file located in [system/backend/fastapi-api.service](system/backend/fastapi-api.service) is a systemd service unit file for managing the lifecycle of the API backend service. This service ensures that the API is started at boot time and managed by systemd.

## Security Certificates

The `cert` directory contains files and instructions for setting up security certificates required for secure communication.

### Cert Bootstrap

Refer to [system/cert/README.md](system/cert/README.md) for instructions on the initial creation of security certificates. These certificates are necessary for running nginx securely. The directory includes:

- `api-cert`: A script for generating certificates.
- `api-cert.service`: A systemd service file for managing the certificate generation process.

Certificates should be placed as follows:

- `api-cert` -> `/usr/bin/api-cert`
- `api-cert.service` -> `/lib/systemd/system/api-cert.service`

It is recommended to enable the `api-cert.service` by default to ensure certificates are generated upon the first run of the device.

## Nginx Configuration

The `nginx.conf` file located in [system/nginx/nginx.conf](system/nginx/nginx.conf) provides the configuration for the Nginx web server. This configuration is tailored to serve the web-API, ensuring efficient handling of client requests and secure communication.

## Conclusion

The `system` directory contains critical components for the operation and security of the web-API. It is essential to properly configure and manage these components to ensure the smooth and secure operation of the service.
