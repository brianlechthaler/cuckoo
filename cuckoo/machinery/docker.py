import docker as vm
from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooMachineError

vmclient = vm.from_env()
isup = vmclient.ping()
if isup == True:
	print("connection to docker daemon successful")
elif isup == False:
	print("ERR:connection to docker daemon failed")

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

