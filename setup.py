from setuptools import setup, find_packages

setup(
    name="credvault",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.0",
        "cryptography>=41.0.0",
        "pyyaml>=6.0",
        "pyperclip>=1.8.0",
        "pynacl>=1.5.0",
    ],
    entry_points={
        "console_scripts": [
            "credvault=credvault.__main__:cli",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
)
