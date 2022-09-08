from password import Password


if __name__ == '__main__':
    password = Password('superstrongpassword')
    print(password)
    print(password.is_valid())
