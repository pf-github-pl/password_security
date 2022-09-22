"""Module containing password validators"""

from abc import ABC, abstractmethod
from hashlib import sha1
import pathlib
import logging
from datetime import datetime
from requests import get


pathlib.Path('./logs/').mkdir(parents=True, exist_ok=True)
log_path = './logs/' + datetime.now().strftime('%Y%m%d_%H%M%S') + '_validator.log'
logging.basicConfig(level='INFO', filename=log_path)


class Validator(ABC):
    """Abstract class to represent a validator containing validation method"""
    @abstractmethod
    def __init__(self):
        pass
    @abstractmethod
    def validate(self):
        """Takes password as a string and evaluates if is valid against some conditions"""


class LengthValidator(Validator):
    """Check if password has a minimum of 8 chars"""
    def __init__(self, password: str, min_length=8):
        self.password = password
        self.min_length = min_length

    def validate(self):
        return len(self.password) >= self.min_length


class SpecialCharValidator(Validator):
    """Verify if password contains at least one of the list of special characters: !@#$%^&"""
    def __init__(self, password: str):
        self.password = password

    def validate(self):
        return any(not char.isalnum() for char in self.password)


class NumberValidator(Validator):
    """Verify if password contains at least one digit"""
    def __init__(self, password: str):
        self.password = password

    def validate(self):
        return any(str(num) in self.password for num in range(10))


class LowercaseValidator(Validator):
    """Verify if password contains at least one lowercase letter"""
    def __init__(self, password: str):
        self.password = password

    def validate(self):
        return any(char.islower() for char in self.password)


class UppercaseValidator(Validator):
    """Verify if password contains at least one uppercase letter"""
    def __init__(self, password: str):
        self.password = password

    def validate(self):
        return any(char.isupper() for char in self.password)


class PasswordPolicyValidator(Validator):
    """Takes password as a string and asserts that it contains at least:
        - 8 characters
        - 1 digit
        - 1 special character
        - 1 lowercase letter
        - 1 uppercase letter
        and returns True if all conditions are met ar False otherwise"""
    def __init__(self, password):
        self.password = password
        self.validators = [
            LengthValidator,
            NumberValidator,
            SpecialCharValidator,
            LowercaseValidator,
            UppercaseValidator
        ]

    def validate(self):
        for class_name in self.validators:
            try:
                assert class_name(self.password).validate()
            except AssertionError:
                logging.info('Hasło %s nie spełnia wymogów polityki.', self.password)
                return False
        return True


class HaveIBeenPwnedValidator(Validator):
    """Class representing validator for Have I Been Pwned database of leaked passwords"""
    def __init__(self, password):
        self.password = password

    def get_password_hash(self):
        """Take password and hash it using sha1 algo, return uppercased hex string"""
        return sha1(self.password.encode('utf-8')).hexdigest().upper()

    @staticmethod
    def get_api_response(hash_prefix):
        """Take hash prefix containing first 5 chars,
        send request to Have I Been Pwned API and return a list of lines"""
        url = 'https://api.pwnedpasswords.com/range/' + hash_prefix
        try:
            with get(url, timeout=5) as content:
                return content.text.splitlines()
        except Exception as exception:
            logging.critical(exception)
            raise exception

    def validate(self):
        """Take password and validate if it was in any leak,
        if it was not leakead return True, otherwise False"""
        password_hash = self.get_password_hash()
        hash_prefix = password_hash[:5]
        suffix_leaks = self.get_api_response(hash_prefix)
        hashes_leaks = [line.split(':') for line in suffix_leaks]

        for leaked_hash_suffix, leaks in hashes_leaks:
            if leaked_hash_suffix == password_hash[5:]:
                logging.info(
                    'Hasło: %s o hashu %s wyciekło %s razy.',
                    self.password,
                    password_hash[:5] + leaked_hash_suffix,
                    leaks
                )
                return False
        return True


class PasswordValidator(Validator):
    """Password Validator abstraction"""
    def __init__(self, password: str):
        """Construct a password object taking password string"""
        self.password = password

    def validate(self):
        """Verify if password object is valid,
        using two validators: PolicyValidator - validates password policies,
        and HaveIBeenPwnedValidator - validates if password was not leaked already
        Returns True if both validators returns True, and False otherwise"""
        policy_validator = PasswordPolicyValidator(self.password)
        leaks_validator = HaveIBeenPwnedValidator(self.password)
        if policy_validator.validate():
            return leaks_validator.validate()
        return False
