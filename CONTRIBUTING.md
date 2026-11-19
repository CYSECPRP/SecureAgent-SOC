# Contributing to SecureAgent-SOC

Thank you for helping. SecureAgent-SOC is a four-person university research project, so the process is kept light.

## Set up

You need Python 3.12, Docker with Compose v2 and [Git LFS](https://git-lfs.com). The `Makefile` targets assume Linux, macOS or WSL.

```bash
git lfs install
git clone https://github.com/CYSECPRP/SecureAgent-SOC.git
cd SecureAgent-SOC
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt -r attack_simulator/requirements.txt
```

Do not need the datasets? Clone with `GIT_LFS_SKIP_SMUDGE=1` to skip about 535 MB of downloads (see [`data/README.md`](data/README.md)).

## Run the tests

The tests talk to real PostgreSQL, Redis and OPA services, and they expect the database tables to exist.

```bash
make up    # start PostgreSQL, Redis, Qdrant and OPA in Docker
make dev   # start the API once: it creates the tables on start-up (stop it with Ctrl+C)
make test  # run the backend test suite
```

The same tests run on every push and pull request in [GitHub Actions](.github/workflows/ci.yml).

## Make a change

1. Create a branch from `main`, for example `feature/n1-graph-check`, `fix/ingest-dedup` or `docs/quick-start`.
2. Keep each commit small, with a short subject in the imperative mood (`Add N1 graph check`).
3. Add or update tests in `backend/tests/` for every change in `backend/src/`. A new OPA rule needs a case in `backend/tests/test_opa.py`.
4. Open a pull request into `main`, fill in the template and ask a teammate to review it.
5. Merge when the review is done and CI is green.

## Code style

- Python follows [PEP 8](https://peps.python.org/pep-0008/), with type hints on new functions.
- Keep FastAPI routes thin and put the logic in modules under `backend/src/`.
- Never commit secrets. `.env` is ignored by Git; put safe defaults in `.env.example`.

## Data

- Datasets live in Git LFS under `data/raw/`, `data/processed/` and `data/splits/`. Keep large files inside these folders.
- Only add data whose licence allows redistribution. For a new source, add it to `data/scripts/download_datasets.py`, put its licence text in `data/LICENSES/` and add a row to the table in [`data/README.md`](data/README.md).

## Security issues

Please do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md) instead.
