from setuptools import setup, find_packages

setup(
    name="binja-mcp-server",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "mcp>=1.6.0",
        "requests>=2.32.3",
    ],
    extras_require={
        "test": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
        ],
    },
) 