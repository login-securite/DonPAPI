# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

# Generic Errors
ERROR_SUCCESS                       = (0, "")
ERROR_MISSING_ARGUMENTS             = (1, "")
ERROR_USER_FILE_NOT_FOUND           = (2, "Users file does not exist")
ERROR_NO_USER_NO_LDAP               = (3, "Either provide ldap credentials or user(s)")
ERROR_THRESHOLD                     = (4, "Bad password count reached threshold")

# Neo4J Errors
ERROR_NEO4J_CREDENTIALS             = (100, "Neo4j credentials are not valid")
ERROR_NEO4J_SERVICE_UNAVAILABLE     = (101, "Neo4j is not available")
ERROR_NEO4J_NON_EXISTENT_NODE       = (102, "Node does not exist in database")
ERROR_NO_PATH                       = (103, "No admin path from this node")
ERROR_NEO4J_UNEXPECTED              = (199, "Unexpected error with Neo4J")

# Ldap Errors
ERROR_LDAP_CREDENTIALS              = (200, "Ldap credentials are not valid")
ERROR_LDAP_SERVICE_UNAVAILABLE      = (201, "Ldap is not available")
ERROR_LDAP_NO_CREDENTIALS           = (202, "No credentials provided")
ERROR_LDAP_NOT_FQDN_DOMAIN          = (203, "Invalid domain")
ERROR_LDAP_UNEXPECTED               = (299, "Unexpected error with Ldap")


ERROR_UNDEFINED                     = (-1, "Unknown error")


class RetCode:
    def __init__(self, error, exception=None):
        self.error_code = error[0]
        self.error_msg = error[1]
        self.error_exception = exception

    def success(self):
        return self.error_code == 0

    def __str__(self):
        return "{} : {}".format(self.error_code, self.error_msg)

    def __eq__(self, other):
        if isinstance(other, RetCode):
            return self.error_code == other.error_code
        elif isinstance(other, int):
            return self.error_code == other
        elif isinstance(other, tuple):
            return self.error_code == other[0]
        return NotImplemented

    def __ne__(self, other):
        x = self.__eq__(other)
        if x is not NotImplemented:
            return not x
        return NotImplemented

    def __hash__(self):
        return hash(tuple(sorted(self.__dict__.items())))