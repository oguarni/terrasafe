from setuptools import setup, find_packages

setup(
    name="terravault",
    version="1.0.0",
    packages=find_packages(),
    # The floor is load-bearing, not decoration. Every workflow pins
    # python-version '3.10' and the image is python:3.10-slim, but nothing
    # declared that to tooling, so Dependabot resolved against the newest
    # interpreter it supports and proposed scikit-learn 1.9.0 (needs >=3.11)
    # and numpy 2.5.2 (needs >=3.12). Both are uninstallable here, and the
    # runtime group PR failed at pip install rather than at a test. Declaring
    # the floor is what keeps future dependency PRs resolvable.
    python_requires=">=3.10",
    install_requires=[
        "python-hcl2==4.3.5",
        "scikit-learn==1.7.2",
        "numpy==2.2.6",
        "joblib==1.5.3",
        "fastapi",
        "uvicorn",
        "pydantic",
        "pydantic-settings",
        "sqlalchemy",
        "asyncpg",
        "alembic",
        "redis",
        "bcrypt",
        "aiofiles",
        "python-multipart>=0.0.27",
        "python-dotenv",
        "slowapi",
        "prometheus-client",
    ],
    entry_points={
        "console_scripts": [
            "terravault=terravault.main:main",
        ],
    },
)
