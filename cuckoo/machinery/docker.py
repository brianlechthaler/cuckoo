import docker as vm
from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooMachineError

#initialize docker api client
def vminit():
    try:
        vmclient = vm.from_env()
    except dockerClientError:
        raise CuckooMachineError("FAIL: Error communicating with Docker Daemon (could not instantiate a client.) Ensure Docker is installed and your user has access.")    
vminit()

class Docker(Machinery):
    def start(self, label):
        try:
            
            revert(label)
            start(label)
            
        except SomethingBadHappens:
            raise CuckooMachineError("oops!")

    def stop(self, label):
        try:
            stop(label)
        except SomethingBadHappens:
            raise CuckooMachineError("oops!")
