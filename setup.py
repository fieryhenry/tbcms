import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("src/cpsmailbox/files/version.txt", "r", encoding="utf-8") as fh:
    version = fh.read()

setuptools.setup(
    name="cpsmailbox",
    version=version,
    author="fieryhenry",
    description="",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fieryhenry/cpsmailbox",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.9",
    install_requires=["Flask", "PyJWT", "Requests"],
    include_package_data=True,
    package_data={"cpsmailbox": ["py.typed"]},
)
