from setuptools import setup, find_packages

setup(
    name="domain_scanner",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        # dependencies
    ],
    python_requires=">=3.6",
)