from validator import Validator


class Password:
    def __init__(self, password: str):
        self.password = password

    def is_valid(self):
        validator = Validator(self.password)
        return validator.validate()

    def __repr__(self):
        return f'Your password: {self.password}'
