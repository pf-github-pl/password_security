# Password security validator
## Description
Application for password validation.

Validates:
1. against password policy:
    - min. 8 char
    - min. 1 special char `!@#$%^&*`
    - min. 1 uppercase letter
    - min. 1 lowercase letter
2. if password was not leaked, using [HaveIBeenPwned.com database API](https://haveibeenpwned.com/API/v3).

## Requirements
requests==2.28.1

## Package building instructions
1. clone the repository
2. create package `python3 setup.py sdist`
3. copy created pkg from `./dist/password_validator-0.1.tar.gz` to your project directory
4. install using pip `pip install password_validator-0.1.tar.gz`