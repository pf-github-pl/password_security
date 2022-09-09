from password_validator.password import Password


def filter_safe_passwords(in_file: str, out_file: str):
    with open(in_file, 'r', encoding='utf-8') as inp, open(out_file, 'w', encoding='utf-8') as out:
        passwords_stripped = [password.strip() for password in inp.readlines()]
        safe_passwords = [pwd + '\n' for pwd in passwords_stripped if Password(pwd).is_valid()]
        out.writelines(safe_passwords)


def validate_single_password(password: str):
    return Password(password).is_valid()


if __name__ == '__main__':
    filter_safe_passwords('passwords.txt', 'safe_passwords.txt')
