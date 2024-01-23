from setuptools import setup, find_packages
from distutils.util import convert_path

main_ns = {}
ver_path = convert_path('pyssh/version.py')
with open(ver_path) as ver_file:
    exec(ver_file.read(), main_ns)

setup(
    name='pyssh',
    version=main_ns['__version__'],
    description='SSH Server and Client library',
    long_description='SSH Server and Client library',
    author='Ensar Gök',
    license_files=('LICENSE',),
    install_requires = [
        'cryptography',
        'pycryptodome'
    ]
)
