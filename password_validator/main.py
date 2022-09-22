"""Password validator app main module"""

from password_validator.validator import PasswordValidator


def filter_safe_passwords(in_file: str, out_file: str):
    """Method taking a file that contains a list of passwords (every password in new line),
    verify if each of them it is safe, validating if it fulfills password policy,
    and if was not leaked (according to HaveIBeenPwned database API),
    write a list of safe passwords to the output file"""
    with open(in_file, 'r', encoding='utf-8') as inp, open(out_file, 'w', encoding='utf-8') as out:
        pass_stripped = [password.strip() for password in inp.readlines()]
        safe_passwords = [pwd + '\n' for pwd in pass_stripped if PasswordValidator(pwd).validate()]
        out.writelines(safe_passwords)


if __name__ == '__main__':
    filter_safe_passwords('passwords.txt', 'safe_passwords.txt')
