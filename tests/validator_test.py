from password_validator.validator import (
    PasswordValidator,
    LengthValidator,
    SpecialCharValidator,
    LowercaseValidator,
    UppercaseValidator,
    NumberValidator,
    PasswordPolicyValidator,
    HaveIBeenPwnedValidator
    )


def test_password_obj_creation():
    assert PasswordValidator('Admin123').password == 'Admin123'


def test_password_is_valid():
    assert PasswordValidator('abc').validate() is False
    assert PasswordValidator('12345678').validate() is False
    assert PasswordValidator('askldjflks!!@!$#').validate() is False
    assert PasswordValidator('asdfasdfsdaf!@!@!1212').validate() is False
    assert PasswordValidator('TWEFFDSAEFSAFSDF33134@$$').validate() is False
    assert PasswordValidator('123!@#qweASD').validate() is False
    assert PasswordValidator('SADFASGfddsfgs@#$%563gfds@').validate() is True


def test_pass_length():
    assert LengthValidator('abc').validate() is False
    assert LengthValidator('1234567').validate()is False
    assert LengthValidator('12345678').validate() is True
    assert LengthValidator('abcdefghijklmnopqrstuvwxz').validate() is True


def test_pass_has_special_char():
    assert SpecialCharValidator('abc').validate() is False
    assert SpecialCharValidator('dsafsa3').validate() is False
    assert SpecialCharValidator('2fasf').validate() is False
    assert SpecialCharValidator('!@#$$%').validate() is True
    assert SpecialCharValidator('ABCD4aASDF0asdf#$').validate() is True
    assert SpecialCharValidator('12345!5678').validate() is True


def test_pass_has_number():
    assert NumberValidator('abc').validate() is False
    assert NumberValidator('dsafsa').validate() is False
    assert NumberValidator('fasf').validate() is False
    assert NumberValidator('!@#$$%3').validate() is True
    assert NumberValidator('ABCD4aASDF0asdf#$').validate() is True
    assert NumberValidator('12345!5678').validate() is True


def test_pass_has_lowercase():
    assert LowercaseValidator('abc').validate() is True
    assert LowercaseValidator('dsafsa3').validate() is True
    assert LowercaseValidator('2fasf').validate() is True
    assert LowercaseValidator('!@#$$%').validate() is False
    assert LowercaseValidator('ABCD23234$').validate() is False
    assert LowercaseValidator('12345!5678').validate() is False


def test_pass_has_uppercase():
    assert UppercaseValidator('!@#$$%XXX').validate() is True
    assert UppercaseValidator('ABCD23234$').validate() is True
    assert UppercaseValidator('12345!5678A').validate() is True
    assert UppercaseValidator('abc').validate() is False
    assert UppercaseValidator('dsafsa3').validate() is False
    assert UppercaseValidator('2fasf').validate() is False


def test_policy_validator():
    assert PasswordPolicyValidator('12!@#$$%XiwXX').validate() is True
    assert PasswordPolicyValidator('ABCD23234$aukp').validate() is True
    assert PasswordPolicyValidator('q12345!5678A').validate() is True
    assert PasswordPolicyValidator('ab2%Ac').validate() is False
    assert PasswordPolicyValidator('$$@%safsa3').validate() is False
    assert PasswordPolicyValidator('fasf12ADFAASDF').validate() is False


def test_same_hashing_results():
    leak_validator1 = HaveIBeenPwnedValidator('Admin123')
    leak_validator2 = HaveIBeenPwnedValidator('Admin123')
    leak_validator3 = HaveIBeenPwnedValidator('Admin123!')
    assert leak_validator1.get_password_hash() == leak_validator2.get_password_hash()
    assert leak_validator3.get_password_hash() != leak_validator2.get_password_hash()


def test_api_response_empty_hash():
    leak_validator = HaveIBeenPwnedValidator('')
    try:
        leak_validator.get_api_response('')
    except Exception:
        assert True


def test_api_response():
    leak_validator = HaveIBeenPwnedValidator('')
    assert type(leak_validator.get_api_response('A23SAD')) is list
    assert len(leak_validator.get_api_response('A23SAD')) > 0


def test_api_response_hash(requests_mock):
    data = '00264A0EA456B57A3FC7258B13F3D29B3C0:11\n00294015E5A8513C73396D18309F3FFF34A:1'
    requests_mock.get('https://api.pwnedpasswords.com/range/A94A8', text=data)
    assert len(HaveIBeenPwnedValidator('').get_api_response('A94A8')[0].split(':')[0]) == 40 - 5
    assert int(HaveIBeenPwnedValidator('').get_api_response('A94A8')[0].split(':')[1]) > 0


def test_not_leaked():
    assert HaveIBeenPwnedValidator('Admin1234!').validate() is False
    assert HaveIBeenPwnedValidator('DSAFasdf23bjghf^34#@').validate() is True