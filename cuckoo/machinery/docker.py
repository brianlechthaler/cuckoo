import docker as vm
import random as rand
from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooMachineError

vmclient = vm.from_env()
isup = vmclient.ping()
if isup == True:
	print("connection to docker daemon successful")
elif isup == False:
	print("ERR:connection to docker daemon failed")

	
	
class Docker(Machinery):
	def agentStart():  
        	vmclient.containers.run("cuckooagent", "python /opt/agent.py", remove=True, detach=False, auto_remove=True, ports={'8000/tcp':8000}, name="cuckooMachinery", tty=True, network_mode="host")
        
        def start(self, label):
        	try:
	            	agentStart()
			revert(label)
        	    	start(label)
        	except SomethingBadHappens:
	            	raise CuckooMachineError("oops!")

    	def stop(self, label):
        	try:
            		stop(label)
        	except SomethingBadHappens:
            		raise CuckooMachineError("oops!")

