#!/usr/bin/python


from __future__ import print_function
import json
from bcc import BPF
from ctypes import c_uint32
import time,threading
import collections
import os
import pwd
from datetime import datetime





# import grpc.examples.python.helloworld.greeter_client as client
import sys
import subprocess
import hashlib
import psutil
import re
# import grpc





sys.path.append('/usr/local/etc/filemonitor/cli.py')

import cli

BPF_C_PROG = "filemonitor.c"


filepath_folder="../miniapps_github/result/"
# filepath_folder="/media/volume/data/file"


# initialize global variables
def init():
    global BPF_C_PROG
    try:
        if(open("/usr/local/etc/filemonitor/filemonitor.c")):
            BPF_C_PROG = "/usr/local/etc/filemonitor/filemonitor.c"
    except:
        pass


def uid_to_username(uid):
    try:
        user_info = pwd.getpwuid(uid)
        username = user_info.pw_name
        return username
    except KeyError:
        return None
    
files_list=[]   
# update_inodemap function takes BPFHASH inodemap, config file as arguments
# reads config file, finds the inode and updates inodemap
def update_inodemap(inodemap, config_file):
    #if not config_file:
    #    raise FileNotFoundError

    #file = open(config_file, 'r')
    #filepaths = file.readlines()
    filepaths=[]
    
    
    folder_path=os.path.abspath(filepath_folder)
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            # print(file_path)
            filepaths.append(file_path)
            # files_list.append(filepaths)
            
    # Print the list of files
    # for file in files_list: 
    #     print(f"file: {file}\n")
        
    for filepath in filepaths:
        inode_id = get_inode_from_filepath(filepath.strip())
        # print(os.stat(filepath).st_ino, filepath)
        # print(filepath)
        # print(f"file path: {filepath}\n")
        
        if inode_id != "":
            inodemap[c_uint32(int(inode_id))] = c_uint32(int(inode_id))



mod_dict = collections.defaultdict(lambda: {
    filename:{
    'sessionid': None,
    'pid': None,
    'start_access': None,
    'end_access': None,
    'input_file_checksum': 0,
    'image_file_checksum': 0}
})
file_dict=collections.defaultdict(dict)
def updates_dict(filename):
    global mod_dict
    print("Before updates dict:",mod_dict)
    #if(filename in mod_dict):
    	#mod_dict.pop(filename)
    mod_dict.clear()
    print (" Updated on",time.ctime())
    
#check the mode of the file
# def check_mode(filename, mode,comm,pid,CPU,uid,timestamp):
	
#     global mod_dict
# 	#print(comm)
# 	#updates_dict()
# 	#print(mod_dict)
# 	#if(filename in mod_dict):
# 	#	print("test  ----####",mod_dict[filename]['program'])
	
#     username=uid_to_username(uid)
    
# 	#if((filename in mod_dict is None or filename[0] in mod_dict is None)):
#     if((filename not in mod_dict)):
        
#         mod_dict.update({filename:{'program':comm,'mode':mode,'pid':pid,'username':username,'timestamp':timestamp}})
#         #mod_dict[filename][comm][pid]=mode
        
#         print("track event")
#         # print(mod_dict)
#         return 1
#     else:
        
#         if(mod_dict[filename]['program']==comm and mod_dict[filename]['mode']==mode and mod_dict[filename]['pid']==pid and mod_dict[filename]['username']==username ):
#             # print ("No change")
#             return 0
#         # elif(mod_dict[filename]['timestamp']!=timestamp):
#         else: 
#             mod_dict.update({filename:{'program':comm,'mode':mode,'pid':pid,'username':username,'timestamp':timestamp}})
#             print ("change mode")
#             # print(mod_dict)
#             return 1
def update_timestamp(filename, sessionid,pid, start_access, end_access,image_file_checksum=0,input_file_checksum=0):
	
    global mod_dict
	#print(comm)
	#updates_dict()
	#print(mod_dict)
	#if(filename in mod_dict):
	#	print("test  ----####",mod_dict[filename]['program'])
    # if(mod_dict[filename]['image_file_checksum']==0):
    #     mod_dict[filename]['image_file_checksum']=image_file_checksum
    
    
	#if((filename in mod_dict is None or filename[0] in mod_dict is None)):
    if((filename not in mod_dict)):
        
        mod_dict.update({filename:{'sessionid':sessionid,'pid':pid, 'start_access':start_access,'end_access':end_access,'image_file_checksum': image_file_checksum,'input_file_checksum': input_file_checksum}})
        #mod_dict[filename][comm][pid]=mode
        
        print("track event")
        # print(mod_dict)
        return 1
    else:
        
        if(mod_dict[filename]['pid']==pid and mod_dict[filename]['end_access']!=end_access): 
            # print (mod_dict[filename]['start_access'],end_access)
            if(end_access-mod_dict[filename]['end_access']>=5):
                mod_dict.update({filename:{'sessionid':sessionid,'pid':pid,'start_access': mod_dict[filename]['start_access'],'end_access':end_access,'image_file_checksum': mod_dict[filename]['image_file_checksum'],'input_file_checksum': mod_dict[filename]['input_file_checksum']}})
                # print ("update end_access ")
                # print(mod_dict)
                return 1
            else: 
                # print ("No update end_access")
                return 0
def update_image_file_checksum(filename, sessionid,pid, start_access, end_access,image_file_checksum,input_file_checksum=0):
	
    global mod_dict
    if(image_file_checksum!=0): 
        print("image_file_checksum: ",image_file_checksum,"Update image file checksum")
        mod_dict.update({filename:{'sessionid':sessionid,'pid':pid,'start_access': mod_dict[filename]['start_access'],'end_access':end_access,'image_file_checksum': image_file_checksum,'input_file_checksum': mod_dict[filename]['input_file_checksum']}})
            
            
def update_input_file_checksum(filename, sessionid,pid, start_access, end_access,image_file_checksum,input_file_checksum=0):
	
    global mod_dict
    if(input_file_checksum!=0): 
        print
        mod_dict.update({filename:{'sessionid':sessionid,'pid':pid,'start_access': mod_dict[filename]['start_access'],'end_access':mod_dict[filename]['end_access'],'image_file_checksum': mod_dict[filename]['image_file_checksum'],'input_file_checksum': input_file_checksum}})
            
            
        

        
        
     	
            
def submitTransaction(filename, mode,sessionid,pid,username,timestamp1,timestamp2,cpu,operation,image_file_checksum,input_file_checksum=0):
    
    # cmd = 'node /home/exouser/fab/fabric-samples/fabcar/javascript/query.js'
    # cmd+=" "+"addRecord"
    # cmd+=" "+filename
    # cmd+=" "+mode
    # cmd+=" "+str(pid)
    # cmd+=" "+username
    # cmd+=" "+str(timestamp)
    # cmd+=" "+str(cpu)
    # cmd+=" "+operation
    str='{"filename":"'+filename+'",'
    str+='"mode":"'+mode+'",'
    sessionid_str="% s" % sessionid
    str+='"sessionid":"'+sessionid_str+'",'
    pid_str="% s" % pid
    str+='"pid":"'+pid_str+'",'
    str+='"username":"'+username+'",'
    timestamp_str1="% s" % timestamp1
    str+='"start_access":"'+timestamp_str1+'",'
    timestamp_str2="% s" % timestamp2
    str+='"end_access":"'+timestamp_str2+'",'
    image_file_checksum_str="% s" % image_file_checksum
    str+='"image_file_checksum":"'+image_file_checksum_str+'",'
    input_file_checksum_str="% s" % input_file_checksum
    str+='"input_file_checksum":"'+input_file_checksum_str+'",'
    cpu_str="% s" % cpu
    str+='"cpu":"'+cpu_str+'",'
    str+='"program_name":"'+operation+'"}'
    
    print(str)
    cmd='/bin/bash client_script.sh '+str 
    # print(cmd)
    # os.system('/bin/bash client_script.sh str')
    os.system(cmd)

    


def get_full_command_tree(pid):
    try:
        parent = psutil.Process(pid)
        # Get parent command line
        full_cmds = [' '.join(parent.cmdline())]

        # Recursively get children
        for child in parent.children(recursive=True):
            full_cmds.append(' '.join(child.cmdline()))

        return '\n'.join(full_cmds)
    except psutil.NoSuchProcess:
        return "Error: Process not found"
    except psutil.AccessDenied:
        return "Error: Permission denied"
    except Exception as e:
        return f"Error: {str(e)}"



def find_sif_files(text):
  """
  Finds filenames ending with '.sif' in a string.

  Args:
      text: The string to search within.

  Returns:
      A list of found '.sif' filenames, or an empty list if none are found.
  """
  pattern = r'[\w\-/\.]*\.sif' # Regex to match .sif files
  matches = re.findall(pattern, text)
  return matches


def find_input_files(text):
  """
  Finds filenames ending with '.bin' in a string.

  Args:
      text: The string to search within.

  Returns:
      A list of found '.bin' filenames, or an empty list if none are found.
  """
  pattern = r'[\w\-/\.]*\.bin' # Regex to match .sif files
  matches = re.findall(pattern, text)
  return matches
    
def is_process_active(pid):
    """Checks if a process with the given PID is currently active."""
    try:
        os.kill(pid, 0)  # Sends a signal 0, which doesn't kill the process
                         # but checks if it exists
        return True
    except OSError:
        return False   
    
def get_pid_by_name(process_name):
  """Gets the PID of a process by its name."""
  try:
    output = subprocess.check_output(["pgrep", process_name]).decode("utf-8").strip()
    if output:
      return int(output)
    else:
      return None
  except subprocess.CalledProcessError:
    return None


def get_process_origin_folder(pid):
    """
    Retrieves the origin folder (directory where the script was launched)
    for a given process ID.

    Args:
        pid: The process ID (integer).

    Returns:
        The path to the origin folder (string) or None if not found.
    """
    try:
        process = psutil.Process(pid)
        if process:  # Check if the process exists
            # Method 1: Using cwd() (current working directory)
            # This is often where the script was started, but might change.
            try:
                cwd = process.cwd()
                return cwd
            except psutil.AccessDenied:
                 pass # try the next method

            # Method 2:  Check the executable path
            try:
                 exe_path = process.exe()
                 return os.path.dirname(exe_path) # return the folder of the executable

            except psutil.AccessDenied:
                return None # if access denied, return None
    except psutil.NoSuchProcess:
        return None

    return None
def sha256_file(filename):
  """Computes the SHA256 checksum of a file."""
  hasher = hashlib.sha256()
  with open(filename, 'rb') as file:
    while True:
      chunk = file.read(4096)
      if not chunk:
        break
      hasher.update(chunk)
  return hasher.hexdigest()    
    
# start = 0
# main function reads args and attaches bpf program
# prints output of bpf events
def main():
    args = cli.parser.parse_args()
    noflags = cli.noflags(args)
    
    
    for root, dirs, files in os.walk(os.path.abspath(filepath_folder)):
        for file in files:
            cmd = 'node /home/exouser/fab/fabric-samples/fabcar/javascript/invoke.js'
            
            cmd+=" "+"addNewFile"
            cmd+=" "+file
            file_path = os.path.join(root, file)
            
            # Get file statistics
            file_stat = os.stat(file_path)
            creation_time = int(os.path.getctime(file_path))


            # Get the owner's user ID
            owner_uid = file_stat.st_uid

            # Use pwd module to get owner's information
            owner_info = pwd.getpwuid(owner_uid)

            # Extract owner's username
            owner_username = owner_info.pw_name
            cmd+=" "+owner_username
            # Get the creation time of the file
            # creation_time = time.ctime(file_stat.st_ctime)
            cmd+=" "+str(creation_time)
            print(cmd)
            # os.system(cmd)
    
    
    try:
        # initialize bpf program
        global BPF_C_PROG
        b = BPF(src_file = BPF_C_PROG)
        # process event
       
        # update inodemap
        update_inodemap(b["inodemap"], args.file)
        
        # attach probes
        if noflags or args.read:
            b.attach_kprobe(event="vfs_read", fn_name="trace_read")
        if noflags or args.write:
            b.attach_kprobe(event="vfs_write", fn_name="trace_write")
            
        if noflags or args.rename:
            b.attach_kprobe(event="vfs_rename", fn_name="trace_rename")
        if noflags or args.create:
            b.attach_kprobe(event="security_inode_create", fn_name="trace_create")
        if noflags or args.delete:
            b.attach_kprobe(event="vfs_unlink", fn_name="trace_delete")
        
        
        # header
        print("%-6s %-4s %-4s %-4s %-10s %-10s %-10s %-4s" % ("PID", "UID","SessionID", "CPU", "PROC", "FPATH", "COMM", "OPRN"))
        
       
        
        
        process_and_CPU=[]
        filename=""
        dict_filename={}
        
        
        def print_event(cpu, data, size):
            
            
            event = b["events"].event(data)
            global filename,mod_dict
            return_val=0
            if(event.otype.decode('utf-8', 'replace')=='WRITE'):
                # update inodemap
               update_inodemap(b["inodemap"], args.file)
            
            
            
            #print(event.fname.decode('utf-8', 'replace'),"\n",event.otype.decode('utf-8', 'replace'))
            if(event.fname.decode('utf-8', 'replace')[0]=='.'):
                dict_filename.update({event.fname.decode('utf-8', 'replace'):filename})
                filename=dict_filename[event.fname.decode('utf-8', 'replace')]
            else:
            	filename=event.fname.decode('utf-8', 'replace')
            
            
            #print(dict_filename)
            	
            #threading.Timer(30,updates_dict,args=(filename,)).start()
            #else:
             #   dict["event.fname.decode('utf-8', 'replace')"]=filename
            
            mode=event.otype.decode('utf-8', 'replace')
            curr_dt = datetime.now()
            
            # if(mod_dict[filename]['start_access'] is None):
            timestamp1 = int(round(curr_dt.timestamp()))
            timestamp2 = int(round(curr_dt.timestamp()))
            # 
            
            
            # if(event.otype.decode('utf-8', 'replace')!='RENAME'):
            #         return_val=check_mode(filename, mode,event.comm.decode('utf-8', 'replace'),event.pid,cpu,event.uid,timestamp)

            return_val=update_timestamp(filename, event.sessionid,event.pid, timestamp1, timestamp2)      
            # elif(cpu==1 and event.otype.decode('utf-8', 'replace')=='WRITE'):
            #     return_val=check_mode(filename, event.otype.decode('utf-8', 'replace'),event.comm.decode('utf-8', 'replace'),event.pid,cpu,event.uid,timestamp)
            # else:
            #     return_val=0    
            
            #print(return_val)
            #print("dict: ", dict["event.fname.decode('utf-8', 'replace')"])
            #count+=1
            #print ("count: ", count)
            #print("event: ", event.fname.decode('utf-8', 'replace'))
            #print("filename: ", filename)
            #if(empty(list[event.pid][event.uid])):
            #	list[event.pid][event.uid]=event.fname.decode('utf-8', 'replace');
            #print event.fname.decode('utf-8', 'replace')
         

            if(return_val==1):
                # global timestamp1,timestamp2
            	#print("%-6d %-4d %-4d %-32s %-32s %-32s %-4s" % (event.pid, event.uid, cpu,
                #event.pname.decode('utf-8', 'replace'), event.fname.decode('utf-8', 'replace'),
                #event.comm.decode('utf-8', 'replace'), event.otype.decode('utf-8', 'replace')))
                print("%-6d %-4d %-4d %-4d %-10s %-10s %-10s %-4s" % (event.pid, event.uid, event.sessionid, cpu,
                event.pname.decode('utf-8', 'replace'), filename,
                event.comm.decode('utf-8', 'replace'), event.otype.decode('utf-8', 'replace')))
                username1=uid_to_username(event.uid)
                mode1=event.otype.decode('utf-8', 'replace')
                curr_dt = datetime.now()
                # print("curr_dt: \n", curr_dt)
                # print("filename: \n", filename) 
                start_access = mod_dict[filename]['start_access'] 
                end_access = mod_dict[filename]['end_access'] 
                # print("start_access: \n", start_access)
                # print("end_access: \n", end_access)
                
             
                program_name=event.comm.decode('utf-8', 'replace')
                # os.system("echo 'test'")
                # if((event.sessionid) not in process_and_CPU):
                    # print("duplicate\n")
                pid=event.pid 
                if is_process_active(event.pid):      
                    command = get_full_command_tree(event.pid)
                    origin_folder=get_process_origin_folder(event.pid)
                    if origin_folder:
                        print(f"Process with PID {pid} originated from: {origin_folder}")
                    else:
                        print(f"Could not determine the origin folder for process with PID {pid}")
                    if(mod_dict[filename]['image_file_checksum']==0): 
                        print(f"Command for PID {event.pid}: {command}") 
                        found_files = find_sif_files(command)

                        if found_files:
                            print("Found .sif files:")
                            for file in found_files:
                                image_file=file
                        else:
                            print("No .sif files found.")
                        print("image_file: ", image_file)
                        
                        file_path = origin_folder+"/"+image_file # Replace with the actual path to your file
                        print(f"File path: {file_path}")
                        try:
                            image_file_checksum = sha256_file(file_path)
                            print(f"The SHA256 checksum of '{file_path}' is: {image_file_checksum}")
                            update_image_file_checksum(filename, event.sessionid,event.pid, start_access, end_access,image_file_checksum)
                            
                        except FileNotFoundError:
                            print(f"Error: File not found: {file_path}")
                    if(mod_dict[filename]['input_file_checksum']==0): 
                        # print(f"Command for PID {event.pid}: {command}") 
                        found_files = find_input_files(command)

                        if found_files:
                            print("Found .bin files:")
                            for file in found_files:
                                input_file=os.path.basename(file)
                        else:
                            input_file="No .bin files found."
                            print("No .bin files found.")
                        if(input_file=="No .bin files found."):
                            input_file_checksum="No"
                            update_input_file_checksum(filename, event.sessionid,event.pid, start_access, end_access,mod_dict[filename]['image_file_checksum'],input_file_checksum)
                        else:
                            # origin_folder=get_process_origin_folder(event.pid)
                            # if origin_folder:
                            #     print(f"Process with PID {pid} originated from: {origin_folder}")
                            # else:
                            #     print(f"Could not determine the origin folder for process with PID {pid}")
                            input_file_path = origin_folder+"/result/input/"+ input_file
                            # Replace with the actual path to your file
                            print(f"File path: {input_file_path}")
                            try:
                                input_file_checksum = sha256_file(input_file_path)
                                print(f"The SHA256 checksum of input '{input_file_path}' is: {input_file_checksum}")
                                update_input_file_checksum(filename, event.sessionid,event.pid, start_access, end_access,mod_dict[filename]['image_file_checksum'],input_file_checksum)
                                
                            except FileNotFoundError:
                                print(f"Error: File not found: {input_file_path}")
            
                if is_process_active(event.pid):
                    print(f"Process '{event.pid}' is active.")
                else:
                    print(f"Process '{event.pid}' is inactive.")
                    submitTransaction(filename, mode1,event.sessionid,event.pid,username1,start_access,end_access,cpu,program_name,mod_dict[filename]['image_file_checksum'],mod_dict[filename]['input_file_checksum']) 



        b["events"].open_perf_buffer(print_event)
        while 1:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit(0)
    except FileNotFoundError:
        print("Exception occured, Is filepath correct?")
    except Exception as e:
        print("Exception occured, Are you root? Is BPF installed?", e)

# get_inode_from_filepath takes a filepath as argument
# and returns inode associated with that file path
def get_inode_from_filepath(filepath):
  cmd = f'ls {filepath} 2>&1 1>/dev/null && ls -i {filepath}'
  cmd += ' | awk \'{print $1}\''
  try:
    output = subprocess.check_output(cmd, shell=True)
    output = output.decode()
    return output.split('\n')[0]
  except:
      return ""

# starts program
if __name__ == "__main__":
    init()
    main()
