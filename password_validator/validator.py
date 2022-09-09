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
    def validate(self, password: str):
        """Takes password as a string and evaluates if is valid against some conditions"""


class PolicyValidator(Validator):
    """Class representing validator for a set of password policy rules"""
    @staticmethod
    def has_length(password):
        """Check if password has a minimum of 8 chars"""
        return len(password) >= 8

    @staticmethod
    def contains_special_char(password):
        """Verify if password contains at least one of the list of special characters: !@#$%^&"""
        # special_chars = '''!@#$%^&*()_+-=[]{};:'"\|<>?,./`~'''
        special_chars = '!@#$%^&*'
        pass_special_chars = [char for char in password if char in special_chars]
        return len(pass_special_chars) > 0

    @staticmethod
    def contains_numbers(password):
        """Verify if password contains at least one digit"""
        numbers = [char for char in password if char in '1234567890']
        return len(numbers) > 0

    @staticmethod
    def contains_lowercase(password):
        """Verify if password contains at least one lowercase letter"""
        lowercase_letters = [char for char in password if char.islower()]
        return len(lowercase_letters) > 0

    @staticmethod
    def contains_uppercase(password):
        """Verify if password contains at least one uppercase letter"""
        uppercase_letters = [char for char in password if char.isupper()]
        return len(uppercase_letters) > 0

    def validate(self, password):
        """Takes password as a string and asserts that it contains at least:
        - 8 characters
        - 1 digit
        - 1 special character
        - 1 lowercase letter
        - 1 uppercase letter
        and returns True if all conditions are met ar False otherwise"""
        try:
            assert self.has_length(password)
            assert self.contains_numbers(password)
            assert self.contains_special_char(password)
            assert self.contains_lowercase(password)
            assert self.contains_uppercase(password)
        except AssertionError:
            # logging.info(f'Hasło {password} nie spełnia wymogów polityki.')
            logging.info('Hasło %s nie spełnia wymogów polityki.', password)
            return False
        return True

class HaveIBeenPwnedValidator(Validator):
    """Class representing validator for Have I Been Pwned database of leaked passwords"""
    @staticmethod
    def get_password_hash(password):
        """Take password and hash it using sha1 algo, return uppercased hex string"""
        return sha1(password.encode('utf-8')).hexdigest().upper()

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

    def validate(self, password):
        """Take password and validate if it was in any leak,
        if it was not leakead return True, otherwise False"""
        password_hash = self.get_password_hash(password)
        hash_prefix = password_hash[:5]
        suffix_leaks = self.get_api_response(hash_prefix)
        suffix_leaks_tup = [(line.split(':')[0], line.split(':')[1]) for line in suffix_leaks]
        hashes_leaks = [(hash_prefix + suffix, leaks) for suffix, leaks in suffix_leaks_tup]

        for leaked_hash, leaks in hashes_leaks:
            if leaked_hash == password_hash:
                # logging.info(f'Hasło: {password} o hashu {leaked_hash} wyciekło {leaks} razy.')
                logging.info('Hasło: %s o hashu %s wyciekło %s razy.', password, leaked_hash, leaks)
                return False
        return True
