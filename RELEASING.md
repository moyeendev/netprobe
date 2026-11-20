# Releasing NetProbe

## One-time setup (repository owner)

1. **Zenodo (software archive):** sign in at <https://zenodo.org> with GitHub, open
   *Account → GitHub* and switch on `moyeendev/netprobe`. Every GitHub release is then
   archived with its own DOI under one concept DOI (all versions). `.zenodo.json` holds the
   metadata. This is a separate record from any other project.
2. **PyPI (not yet enabled):** the name `netprobe` is already taken on PyPI by an unrelated
   project, so a distribution name must be chosen before publishing. Then add a trusted
   publisher at <https://pypi.org> (*Your account → Publishing*) for workflow `release.yml`,
   environment `pypi`, and add a `pypi` job to the workflow.
3. Check the authors in `pyproject.toml`, `CITATION.cff` and `.zenodo.json`.

## Each release

1. Set `__version__` in `src/netprobe/__init__.py` and `version` in `pyproject.toml`, and
   `version` / `date-released` in `CITATION.cff`.
2. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` (the release notes
   are taken from this section) and start a new empty `[Unreleased]` section.
3. Check locally:

   ```bash
   pytest -q && ruff check .
   python -m build && python -m twine check --strict dist/*
   ```

4. Commit, then tag and push:

   ```bash
   git tag -a vX.Y.Z -m "NetProbe X.Y.Z"
   git push origin main vX.Y.Z
   ```

   `.github/workflows/release.yml` checks that the tag matches the version, builds,
   smoke-tests the wheel on Linux, Windows and macOS, and creates the GitHub release; Zenodo
   then mints the DOI.
5. Add the version DOI to `CITATION.cff` (`doi:`) and to the README.

## Evaluation data

The evaluation output (`evaluation-results/` from `examples/run_evaluation.sh`) is deposited
as a separate Zenodo *dataset* record, not in this repository.
