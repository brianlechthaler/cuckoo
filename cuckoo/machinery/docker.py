import docker as vm
from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooMachineError

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
