# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

try:
    from neo4j.v1 import GraphDatabase
except ImportError:
    from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

from lib.defines import *


class Neo4jConnection:
    class Options:
        def __init__(self, host, user, password, port, log, edge_blacklist=None):
            self.user = user
            self.password = password
            self.host = host
            self.port = port
            self.log = log
            self.edge_blacklist = edge_blacklist if edge_blacklist is not None else []

    def __init__(self, options):
        self.user = options.user
        self.password = options.password
        self.log = options.log
        self.edge_blacklist = options.edge_blacklist
        self._uri = "bolt://{}:{}".format(options.host, options.port)
        try:
            self._get_driver()
        except Exception as e:
            self.log.error("Failed to connect to Neo4J database")
            raise

    def set_as_owned(self, username, domain):
        user = self._format_username(username, domain)
        query = "MATCH (u:User {{name:\"{}\"}}) SET u.owned=True RETURN u.name AS name".format(user)
        result = self._run_query(query)
        if len(result.value()) > 0:
            return ERROR_SUCCESS
        else:
            return ERROR_NEO4J_NON_EXISTENT_NODE

    def bloodhound_analysis(self, username, domain):

        edges = [
            "MemberOf",
            "HasSession",
            "AdminTo",
            "AllExtendedRights",
            "AddMember",
            "ForceChangePassword",
            "GenericAll",
            "GenericWrite",
            "Owns",
            "WriteDacl",
            "WriteOwner",
            "CanRDP",
            "ExecuteDCOM",
            "AllowedToDelegate",
            "ReadLAPSPassword",
            "Contains",
            "GpLink",
            "AddAllowedToAct",
            "AllowedToAct",
            "SQLAdmin"
        ]
        # Remove blacklisted edges
        without_edges = [e.lower() for e in self.edge_blacklist]
        effective_edges = [edge for edge in edges if edge.lower() not in without_edges]

        user = self._format_username(username, domain)

        with self._driver.session() as session:
            with session.begin_transaction() as tx:
                query = """
                    MATCH (n:User {{name:\"{}\"}}),(m:Group),p=shortestPath((n)-[r:{}*1..]->(m))
                    WHERE m.objectsid ENDS WITH "-512" OR m.objectid ENDS WITH "-512" 
                    RETURN COUNT(p) AS pathNb
                    """.format(user, '|'.join(effective_edges))

                self.log.debug("Query : {}".format(query))
                result = tx.run(query)
        return ERROR_SUCCESS if result.value()[0] > 0 else ERROR_NO_PATH

    def clean(self):
        if self._driver is not None:
            self._driver.close()
        return ERROR_SUCCESS

    def _run_query(self, query):
        with self._driver.session() as session:
            with session.begin_transaction() as tx:
                return tx.run(query)

    def _get_driver(self):
        try:
            self._driver = GraphDatabase.driver(self._uri, auth=(self.user, self.password))
            return ERROR_SUCCESS
        except AuthError as e:
            self.log.error("Neo4j invalid credentials {}:{}".format(self.user, self.password))
            raise
        except ServiceUnavailable as e:
            self.log.error("Neo4j database unavailable at {}".format(self._uri))
            raise
        except Exception as e:
            self.log.error("An unexpected error occurred while connecting to Neo4J database {} ({}:{})".format(self._uri, self.user, self.password))
            raise

    @staticmethod
    def _format_username(user, domain):
        return (user + "@" + domain).upper()