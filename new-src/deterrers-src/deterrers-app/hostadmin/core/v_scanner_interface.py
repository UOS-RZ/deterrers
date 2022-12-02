from gvm.protocols.gmp import Gmp
from gvm.connections import SSHConnection
from gvm.transforms import EtreeCheckCommandTransform




class GmpVScannerInterface():
    """
    Interface to the Greenbone Vulnerability Scanner.
    Communication uses the python-gvm API package.
    """
    TIMEOUT = 20
    HOSTNAME = "hulk.rz.uni-osnabrueck.de"
    PORT = 22 # default

    username = ''
    password = ''

    def __init__(self, username, password):
        """
        Create a Gmp instance based on a TLS connection.
        """
        self.username = username
        self.password = password
        transform = EtreeCheckCommandTransform()

        connection = SSHConnection(
            hostname=self.HOSTNAME,
            port=self.PORT,
            timeout=self.TIMEOUT)
        self.gmp = Gmp(connection=connection, transform=transform)

    def __enter__(self):
        """
        Context manager that wraps around the Gmp context manager.

        Raises:
            err: In case an exception occurs during initialization it will be forwarded.

        Returns:
            GreenboneVScannerInterface: Returns self.
        """
        self.gmp = self.gmp.__enter__()
        try:
            # further initialization need to be enclosed here
            self.gmp.authenticate(self.username, self.password)
            
            return self
        except Exception as err:
            self.gmp.__exit__(None, None, None)
            raise err


    def __exit__(self, exc_type, exc_value, traceback):
        self.gmp.__exit__(exc_type, exc_value, traceback)

    def get_version(self):
        print(self.gmp.get_version())


if __name__ == "__main__":
    with GmpVScannerInterface() as interf:
        interf.get_version()