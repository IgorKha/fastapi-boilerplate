# Web-API

The Web-API is a FastAPI-based project designed to manage small devices. It provides a robust and secure API for device management, leveraging the FastAPI framework for high performance and easy scalability. The project is licensed under the MIT License, ensuring that it is free to use, modify, and distribute.

## Features

- **Device Management**: Securely manage and monitor small devices through a comprehensive set of API endpoints.
- **Security**: Includes configurations for secure operation, including SSL certificates and CORS settings.
- **Development Environment**: Configured for an efficient development experience with Visual Studio Code settings.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Docker and Docker Compose (for development environment)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/IgorKha/fastapi-boilerplate
cd fastapi-boilerplate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

### Development Environment

To set up and run the development environment:

Just press F5 in your VSCode

This will start the application in development mode, with live reloading enabled.

### Production Environment

For production deployment, ensure that you have configured the necessary security settings and SSL certificates as described in [system/cert/README.md](system/cert/README.md) and [system/nginx/nginx.conf](system/nginx/nginx.conf).

1. Configure the system directory components as per the [system/README.md](system/README.md) instructions.
2. Deploy the application using a production-grade server like Uvicorn:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

or use [system/backend/fastapi-api.service](system/backend/fastapi-api.service)
