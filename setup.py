"""PathProbe v3.0 — Advanced Adaptive Path Traversal Testing Framework."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [
        line.strip() for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="pathprobe",
    version="3.0.0",
    author="PathProbe Contributors",
    description="Advanced Adaptive Path Traversal Testing Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/pathprobe",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "pathprobe=pathprobe.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords="security pentesting path-traversal lfi vulnerability-scanner",
)
