from setuptools import setup, find_packages

setup(
    name="terrasafe",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "python-hcl2==4.3.2",
        "scikit-learn==1.3.2",
        "numpy==1.24.3",
        "joblib==1.3.2",
    ],
    entry_points={
        "console_scripts": [
            "terrasafe=terrasafe.cli:main",
        ],
    },
)
