# SA2436-jwks-server
CSCE 3550 Project 1
Develop a RESTful JWKS server that provides public keys with unique identifiers (kid) for verifying JSON Web Tokens (JWTs), implements key expiry for enhanced security, includes an authentication endpoint, and handles the issuance of JWTs with expired keys based on a query parameter.

Chooses an appropriate language (python) and web server (flask web framework) for the task.

I used chatGPT to see how to set it up and how to run and fix the code files on test client and test suite.

# JWKS Server (Python + FastAPI)

## Setup
1. create venv: `python3 -m venv .venv && source .venv/bin/activate`
2. install: `pip install -r requirements.txt`

## Run
`make -f makefile.mak`
Server listens on `http://127.0.0.1:8080`

## Endpoints
- Start Server `uvicorn app.main:app --port 8080 --reload`
- Get a second terminal to `git clone git@github.com:jh125486/CSCE3550.git` into CSCE3550 repo and `cd CSCE3550`
- Run the go test client `go run main.go project1`
- `GET /jwks` -> JWKS (unexpired keys only)
- `POST /auth` -> {"token": "..."} signed with newest unexpired key (kid in header)
- `POST /auth?expired=1` -> returns token signed with newest **expired** key; token `exp` equals key expiry

## Tests
`make test` shows coverage. Include screenshots of:
- test client `curl` / responses
- test suite output showing coverage percentage export `PYTHONPATH=$(pwd)` then `pytest --cov=app tests/`
