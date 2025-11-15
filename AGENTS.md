# Repository Guidelines

## Project Structure & Module Organization
TinyPi-SIEM keeps all runtime assets under `TinyPi`: `docker-compose.yml` defines the single `siemapp` service, `app/main.py` hosts the FastAPI entry point, and `app/templates/*.html` render the dashboard views. The build context includes `app/Dockerfile` (uvicorn base) and `app/requirements.txt`. Logs persist in SQLite at `/data/siem.db` mounted by the compose volume. Add new Python modules next to `main.py`, keeping parsing helpers grouped near the detection constants to prevent circular imports, and stage static assets under `app/static` so FastAPI’s `StaticFiles` mount can serve them.

## Build, Test, and Development Commands
- `cd TinyPi && sudo docker compose up --build -d`: build the image, provision the `/data` volume, and start the SIEM + syslog UDP listener on ports 8000/5514.
- `cd TinyPi && sudo docker compose down`: stop containers and keep the persisted SQLite volume intact.
- `cd TinyPi/app && pip install -r requirements.txt && uvicorn main:app --reload --host 0.0.0.0 --port 8000`: run the API directly for iterative development.

## Coding Style & Naming Conventions
Target Python 3.10+, follow PEP 8 with four-space indentation, and keep modules type hinted (as already done for database helpers). Name detection constants in `UPPER_SNAKE_CASE`, FastAPI routes in `snake_case`, and template blocks using lowercase-hyphen ids. Prefer async endpoints, small dependency-free helpers, and guard any filesystem or network access with environment variables defined in `docker-compose.yml`.

## Testing Guidelines
No automated suite exists yet; create `TinyPi/app/tests/` and add `pytest` cases named `test_<feature>.py`. Use `httpx.AsyncClient` or FastAPI’s `TestClient` to post synthetic syslog payloads, assert database side effects via the SQLite connection helpers, and aim for ≥80% coverage on parsing utilities and alert generation. Run locally with `cd TinyPi/app && pytest -q` before pushing.

## Commit & Pull Request Guidelines
History shows concise present-tense messages (`Add files via upload`, `Updated README.md`). Keep that style, summarize the behavioral change in ≤72 characters, and add details in the body if the change spans multiple modules. PRs should link an issue or describe the motivation, list manual/automated test evidence, include screenshots for template changes, and call out any new environment variables or ports that downstream Raspberry Pi deployments must set.

## Security & Configuration Tips
Protect the default `SIEM_HTTP_INGEST_TOKEN` by overriding it in compose overrides or environment files, and avoid checking real log data into Git. When experimenting locally, point `SIEM_DB` to a workspace path rather than `/data` so sensitive entries stay outside commits. Rotate tokens whenever sharing sample dashboards.
