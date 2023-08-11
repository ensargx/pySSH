class BasePacket:
    """
    This packet will be used to parse all packets
    
    Usage:

    from pyssh.ssh_packet import BasePacket
    
    class KEXINITPacket(BasePacket):
        pass
    
    kex_init_packet = KEXINITPacket()

    """

    # when a object is created whose class is inherited from BasePacket, this method will be called
    def __init__(self): 

        pass

    # when a object is created whose class is inherited from BasePacket, this method will be called
    def __new__(cls, *args, **kwargs):
            
            return super().__new__(cls)
    
    # when a object is created whose class is inherited from BasePacket, this method will be called
    def __call__(self, *args, **kwargs):
         
        return super().__call__(*args, **kwargs)
    
    # when a object is created whose class is inherited from BasePacket, this method will be called
    def __self__(self):
        pass

    # when a object is created whose class is inherited from BasePacket, this method will be called
    def __str__(self):
        pass



class VersionPacket:
    pass

class KEXINITPacket(BasePacket):
    

    def __self__(self):
        return b"abcd"
