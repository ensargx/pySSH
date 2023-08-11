class Base:
    def __init__(self) -> None:
        print("init Base")
        return
    
    def __init_subclass__(cls, **kwargs):
        print("init subclass")
        
    

class TestClass(Base):
    """
    asdsa
    """
    print("dad")
    def __init__(self,par=12) -> None:
        super(par=par).__init__(par=par)
        print("init TestClass")

    print("dad2")