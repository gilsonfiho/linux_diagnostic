"""
Setup do projeto Linux SSH Diagnostics.
"""
from setuptools import setup, find_packages

setup(
    name="linux-ssh-diagnostics",
    version="1.0.0",
    description="Diagnóstico automatizado de sistemas Linux via SSH",
    author="Linux SSH Diagnostics",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=[
        "paramiko>=3.4.0",
        "fpdf2>=2.7.9",
    ],
    entry_points={
        "console_scripts": [
            "linux-diag=main:main",
        ],
    },
)
