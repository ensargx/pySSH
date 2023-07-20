from pySSH.exceptions import WrongVersionException

class ClientBase:
    """
    It will act as a Client class base for the server
    User should inherit from this class
    When new Client object is created with the subclass of ClientBase,

    ClientBase will specify SSH configuration. i.e.
    PasswordLoginAllowed = False
    PubKeyLoginAllowed = True

    Also ClientBase will handle SSH information about clients for example:
    

    Example:

    class MyClient(Client):
        def __init__(self):
            super().__init__(self)

    """
    def __init__(self):
        """
        Everything SSH and client related will be handled here
        """
        print("initing ClientBase")
        self.username = None
        self.password = None
        self.pub_key = None        
        ...

    def __enter__(self):
        return self
    
    # When Client class is created and inherited, it will be passed to the server
    def __init_subclass__(cls):
        """
        when a subclass is created, it will be passed to the server, objects of subclasses will be created by the server
        when a subclass is created, client will pass the app object to the subclass and 

        Example:
        from psSSH import pySSH, ClientBase

        app = pySSH()

        @app.Client
        class MyClient(ClientBase):
            def __init__(self):
                super().__init__(self)
                self.name = super().username
        """
        print("initing subclass")
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        if isinstance(exc_val, WrongVersionException):
            self.server.close_conn(self, exc_type, exc_val, exc_tb)

    def recv(self):
        data = self.server.recv(self)

    def send(self, message):
        self.server.send(self, message)
        pass