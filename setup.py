"""Setup configuration for enterprise-ai-agents."""

from setuptools import setup, find_packages

setup(
    name="enterprise-ai-agents",
    version="0.1.0",
    description="Enterprise AI agents and skills for cybersecurity tools",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.10",
    install_requires=[],
    extras_require={
        "dev": ["pytest>=7.0"],
    },
)
