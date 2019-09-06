import setuptools

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="eZeeKonfigurator",
    version="0.1",
    author="Vlad Grigorescu",
    author_email="vlad@es.net",
    description="A front-end to manage Zeek configurations",
    packages=setuptools.find_packages(),
    package_data={'ezeekonfigurator_client': ['.git/*']},
    install_requires=requirements,
    scripts=['manage.py'],
)