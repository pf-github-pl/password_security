from password_validator.validator import PolicyValidator, HaveIBeenPwnedValidator


class Password:
    def __init__(self, password: str):
        self.password = password

    def is_valid(self):
        policy_validator = PolicyValidator()
        leaks_validator = HaveIBeenPwnedValidator()
        if policy_validator.validate(self.password):
            return leaks_validator.validate(self.password)
        return False

    def __repr__(self):
        return f'Your password: {self.password}'
