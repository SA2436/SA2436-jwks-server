# SA2436-jwks-server
CSCE 3550 Project 1
Develop a RESTful JWKS server that provides public keys with unique identifiers (kid) for verifying JSON Web Tokens (JWTs), implements key expiry for enhanced security, includes an authentication endpoint, and handles the issuance of JWTs with expired keys based on a query parameter.

Chooses an appropriate language (python) and web server (flask web framework) for the task.

# JWKS Server (Python + FastAPI)

## Setup
1. create venv: `python -m venv .venv && source .venv/bin/activate`
2. install: `pip install -r requirements.txt`

## Run
`make run`
Server listens on `http://127.0.0.1:8080`

## Endpoints
- `GET /jwks` -> JWKS (unexpired keys only)
- `POST /auth` -> {"token": "..."} signed with newest unexpired key (kid in header)
- `POST /auth?expired=1` -> returns token signed with newest **expired** key; token `exp` equals key expiry

## Tests
`make test` shows coverage. Include screenshots of:
- test client `curl` / responses
- test suite output showing coverage percentage
