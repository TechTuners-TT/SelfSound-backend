# Selfsound-backend

![Banner](https://github.com/TechTuners-TT/backend/blob/main/docs/img/backend-banner.png?raw=true)

Backend development for SelfSound — a social network for musicians that merges the best of Threads and SoundCloud using FastAPI.

---
<div align="center">
  <a href="docs/PROJECT-STRUCTURE.md">🧭 Backend structure</a> -
  <a href="https://www.example.com">📖 About project</a> -
  <a href="docs/CONTRIBUTING.md">🔧 How to contribute?</a>
</div>

---

# Table of Contents

1. [Requirements](#requirements)  
   - [Setup Environment Variables](#setup-environment-variables)  
2. [How to Start Working?](#how-to-start-working)  
   - [Project Setup](#project-setup)  
   - [Running the Server](#run-development-server)  
3. [How to Contribute?](#how-to-contribute)  
4. [Deployment](#deployment)  
   - [Linting](#linting)  
   - [Manual Deployment](#manual-deployment)  
5. [Testing](#testing)  
   - [Unit Tests](#run-unit-tests)  
   - [Security Checks](#run-security-checks)  

---

## Requirements

Before starting development or contributing to this backend, make sure you have:

- ✅ Python 3.10 or later  
- ✅ `pip` & `venv` installed  
- ✅ `.env` file with proper credentials and tokens  

### Setup Environment Variables

1. Ask the DevOps engineer for access to the project `.env` file.
2. Place the `.env` file in the root directory of the backend project.
3. Sample `.env` keys (example only):

```env
DATABASE_URL=your_database_url
SECRET_KEY=your_secret_key
SUPABASE_API_KEY=your_supabase_key
```
‼️ Do not commit this file or share its content publicly.

---

## How to start working?
### Project Setup

Create a virtual environment and install all dependencies:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### Run Development Server

To start the FastAPI development server with Uvicorn:

```bash
uvicorn main:app --reload
```

Then go to http://localhost:8000 to access the API.

---

## How to contribute?

We welcome contributions! Before creating a PR, please check the [Contribution Guide](docs/CONTRIBUTING.md).

### Testing
## Run Unit Tests

To run tests using pytest:

```bash
pytest
```

## Run Security Checks

For secure coding practices, use Bandit and Safety:

```bash
bandit -r .
```
