import paramiko
import time

ssh = paramiko.SSHClient()
#ssh.load_system_host_keys()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('155.1.1.2', port=22, username='root', password='radware')

time.sleep(3)
print('connected')

for i in range(1, 10):
	time.sleep(2)
	stdin, stdout, stderr = ssh.exec_command("nmap -sS -Pn -p- 155.1.102.1-20  -T 5 -S 10.1.1.1 -e eth0 --min-parallelism 100")
	print("Thread "+str(i)+" running")
print("Attack is runninig")

def execute():
       stdin.write('xcommand SystemUnit Boot Action: Restart\n')
       print('success')

execute()
