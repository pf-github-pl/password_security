from password_validator.validator import PolicyValidator, HaveIBeenPwnedValidator


def test_pass_length():
    policy_validator = PolicyValidator()
    assert policy_validator.has_length('abc') is False
    assert policy_validator.has_length('1234567') is False
    assert policy_validator.has_length('12345678') is True
    assert policy_validator.has_length('abcdefghijklmnopqrstuvwxz') is True


def test_pass_has_special_char():
    policy_validator = PolicyValidator()
    assert policy_validator.contains_special_char('abc') is False
    assert policy_validator.contains_special_char('dsafsa3') is False
    assert policy_validator.contains_special_char('2fasf') is False
    assert policy_validator.contains_special_char('!@#$$%') is True
    assert policy_validator.contains_special_char('ABCD4aASDF0asdf#$') is True
    assert policy_validator.contains_special_char('12345!5678') is True

def test_pass_has_lowercase():
    policy_validator = PolicyValidator()
    assert policy_validator.contains_lowercase('abc') is True
    assert policy_validator.contains_lowercase('dsafsa3') is True
    assert policy_validator.contains_lowercase('2fasf') is True
    assert policy_validator.contains_lowercase('!@#$$%') is False
    assert policy_validator.contains_lowercase('ABCD23234$') is False
    assert policy_validator.contains_lowercase('12345!5678') is False


def test_pass_has_uppercase():
    policy_validator = PolicyValidator()
    assert policy_validator.contains_uppercase('!@#$$%XXX') is True
    assert policy_validator.contains_uppercase('ABCD23234$') is True
    assert policy_validator.contains_uppercase('12345!5678A') is True
    assert policy_validator.contains_uppercase('abc') is False
    assert policy_validator.contains_uppercase('dsafsa3') is False
    assert policy_validator.contains_uppercase('2fasf') is False


def test_policy_validator():
    policy_validator = PolicyValidator()
    assert policy_validator.validate('12!@#$$%XiwXX') is True
    assert policy_validator.validate('ABCD23234$aukp') is True
    assert policy_validator.validate('q12345!5678A') is True
    assert policy_validator.validate('ab2%Ac') is False
    assert policy_validator.validate('$$@%safsa3') is False
    assert policy_validator.validate('fasf12ADFAASDF') is False


def test_same_hashing_results():
    leak_validator1 = HaveIBeenPwnedValidator()
    leak_validator2 = HaveIBeenPwnedValidator()
    assert leak_validator1.get_password_hash('Admin123') == leak_validator2.get_password_hash('Admin123')
    assert leak_validator1.get_password_hash('Admin123!') != leak_validator2.get_password_hash('Admin123')


def test_api_response_empty_hash():
    leak_validator = HaveIBeenPwnedValidator()
    try:
        leak_validator.get_api_response('')
    except Exception:
        assert True


def test_api_response():
    leak_validator = HaveIBeenPwnedValidator()
    assert type(leak_validator.get_api_response('A23SAD')) is list
    assert len(leak_validator.get_api_response('A23SAD')) > 0


def test_api_response_hash(requests_mock):
    data = '00264A0EA456B57A3FC7258B13F3D29B3C0:11\n00294015E5A8513C73396D18309F3FFF34A:1'
    requests_mock.get('https://api.pwnedpasswords.com/range/A94A8', text=data)
    assert len(HaveIBeenPwnedValidator().get_api_response('A94A8')[0].split(':')[0]) == 40 - 5
    assert int(HaveIBeenPwnedValidator().get_api_response('A94A8')[0].split(':')[1]) > 0


def test_not_leaked():
    leak_validator = HaveIBeenPwnedValidator()
    assert leak_validator.validate('Admin1234!') is False
    assert leak_validator.validate('DSAFasdf23bjghf^34#@') is True