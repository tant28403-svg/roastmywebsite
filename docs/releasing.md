# Releasing

## Version bump

Update `pyproject.toml` and `src/roastmywebsite/__init__.py`.

## Build

```bash
python -m build
```

## Publish

Tag a release:

```bash
git tag v0.2.0
git push origin v0.2.0
```

GitHub Actions publishes to PyPI and GHCR.