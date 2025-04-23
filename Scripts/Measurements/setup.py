from setuptools import setup, find_packages

setup(
    name="DNSExplorer",
    version="1.0.0",
    description="A DNS analysis and GeoIP lookup tool",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "geoip2",
        "argparse"
    ],
    entry_points={
        "console_scripts": [
            "dnsexplorer=dns_explorer.main:main"
        ]
    },
)
