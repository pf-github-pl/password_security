from setuptools import setup

#python3 setup.py sdist

setup(
    name='password_validator',
    version='0.1',
    description='Validate password against policy and leaks',
    packages=['password_validator'],
    install_requires=['requests==2.28.1']
)