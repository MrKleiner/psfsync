
class AuthFail(Exception):
	pass


class InvalidKey(AuthFail):
	pass


class WrongAuthMessageLength(AuthFail):
	pass


class CipherFailure(Exception):
	pass

