ClientClass = None

class DefaultConfig:
    """
    This config used in server config
    """
    AllowUsers: list = ["root", "admin"]
    PubkeyAuthentication: bool = True

ConfigClass = DefaultConfig

def dec(cls: type):
    global ClientClass
    print(cls)
    print(cls.__name__)
    print(cls.__bases__)
    print(cls.__dict__)
    print("this is CLIENT, Client will have BASE attribute, client.Base.SSH_USERNAME")
    ClientClass = cls
    return cls

def conf_dec(cls: type):
    global ConfigClass
    print(cls)
    print(cls.__name__)
    print(cls.__bases__)
    print(cls.__dict__)
    print("this is CONFIG, Config will have BASE attribute, client.Config.SSH_USERNAME")
    ConfigClass = cls
    return cls


class ClientBase:
    SSH_USERNAME: str
    SSH_PASSWORD: str
    SSH_LOGIN_TYPE: str

    def __init__(self) -> None:
        print("init")
        print(self.__class__.__dict__)
        self.Config = ConfigClass()
        return

    # when a class is created with the ClientBase as the base class, this function will be called
    def __init_subclass__(cls, **kwargs):
        print("init_subclass")
        print(cls.__dict__)
        return super().__init_subclass__(**kwargs)

    def __setattr__(self, name, value):
        print("setattr")
        self.check_config(name, value)
        print(name)
        print(value)
        return super().__setattr__(name, value)
    
    def check_config(self, name, value):
        """
        This function will be called when a attribute is set, you can check the config here
        If and attribute is not allowed, you can raise an error here
        """

        if name == "SSH_USERNAME":
            # if Config has AllowUsers attribute, check if the username is in the list
            if hasattr(self.Config, "AllowUsers"):
                if value not in self.Config.AllowUsers:
                    raise ValueError("SSH_USERNAME is not allowed")    
        
        return        

@conf_dec
class Config:
    """
    This config used in server config
    """
    AllowUsers: list = ["username", "admin"]
    PubkeyAuthentication: bool = True



@dec
class Client:
    """
    This client will be called before 
    """
    def __init__(self, Base: ClientBase) -> None:
        self.Base = Base
        print("init Client")
        super().__init__()
        print("init Client end")

    def on_message(self, data):
        print(data)
        return

user_base = ClientBase()
user_base.SSH_USERNAME = "username"
user_base.SSH_PASSWORD = "Password"
user_base.SSH_LOGIN_TYPE = "password"
user = ClientClass(user_base)
print(user)
