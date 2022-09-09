from password_validator.password import Password


def test_password_obj_creation():
    assert Password('Admin123').password == 'Admin123'


def test_password_is_valid():
    assert Password('abc').is_valid() is False
    assert Password('12345678').is_valid() is False
    assert Password('askldjflks!!@!$#').is_valid() is False
    assert Password('asdfasdfsdaf!@!@!1212').is_valid() is False
    assert Password('TWEFFDSAEFSAFSDF33134@$$').is_valid() is False
    assert Password('123!@#qweASD').is_valid() is False
    assert Password('SADFASGfddsfgs@#$%563gfds@').is_valid() is True
