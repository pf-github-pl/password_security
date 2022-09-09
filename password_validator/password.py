"""Module containing Password class and methods"""

from password_validator.validator import PolicyValidator, HaveIBeenPwnedValidator


class Password:
    """Password abstraction"""
    def __init__(self, password: str):
        """Construct a password object taking password string"""
        self.password = password

    def is_valid(self):
        """Verify if password object is valid,
        using two validators: PolicyValidator - validates password policies,
        and HaveIBeenPwnedValidator - validates if password was not leaked already
        Returns True if both validators returns True, and False otherwise"""
        policy_validator = PolicyValidator()
        leaks_validator = HaveIBeenPwnedValidator()
        if policy_validator.validate(self.password):
            return leaks_validator.validate(self.password)
        return False
