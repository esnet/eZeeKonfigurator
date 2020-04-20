import os
import setuptools

with open('requirements_common.txt') as f:
    requirements = f.read().splitlines()

# Check if we're running in a CI environment
if os.environ.get("CI"):
    env = os.environ.get('ENVIRONMENT', "DEVELOPMENT")
else:
    env = os.environ.get('ENVIRONMENT', "PRODUCTION")

# Additional requirements for development or production
if env:
    with open('requirements_%s.txt' % env.lower()) as f:
        requirements += f.read().splitlines()

setuptools.setup(
    name="eZeeKonfigurator",
    version="0.1",
    author="Vlad Grigorescu",
    author_email="vlad@es.net",
    description="A front-end to manage Zeek configurations",
    packages=setuptools.find_packages(),
    include_package_data=True,
    install_requires=requirements,
    scripts=['manage.py', 'eZeeKonfigurator/standalone_scripts/brokerd.py'],
)