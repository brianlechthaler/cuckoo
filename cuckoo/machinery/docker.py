#Import Docker API
import docker

#Import necessary cuckoo components
from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooMachineError

class Docker(Machinery):
	def agentStart():  
		#Instantiate Docker API Client
		vmclient = docker.DockerClient(base_url='unix://var/run/docker.sock')
		#create container, start it, and run the agent inside it
		vmclient.containers.run("cuckooagent", "python /opt/agent.py", remove=True, detach=False, auto_remove=True, ports={'8000/tcp':8000}, name="cuckooMachinery", tty=True, network_mode="host")
        def agentStop():
		#Instantiate low-level api client
		lowlevelapi = vm.APIClient(base_url='unix://var/run/docker.sock')
		#Kill the container
		lowlevelapi.kill("cuckooMachinery")
        def start(self, label):
        	try:
	            	agentStart()
			revert(label)
        	    	start(label)
        	except SomethingBadHappens:
	            	raise CuckooMachineError("oops!")

    	def stop(self, label):
        	try:
            		agentStop()
			stop(label)
        	except SomethingBadHappens:
            		raise CuckooMachineError("oops!")

