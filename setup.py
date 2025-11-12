from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="web-vuln-scanner",
    version="1.0.0",
    author="CyberScan Pro Team",
    author_email="team@cyberscan.pro",
    description="Professional Website Vulnerability Scanner with OWASP Top 10 Coverage",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Bharath-A-007/web-vuln-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cyberscan=app:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["templates/*", "static/*", "static/css/*", "static/js/*", "static/images/*"],
    },
)
