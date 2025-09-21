.PHONY: run test

run:
	uvicorn app.main:app --port 8080 --reload

test:
	pytest --maxfail=1 --disable-warnings -q --cov=. --cov-report=term
