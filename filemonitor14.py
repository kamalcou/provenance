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
import collections
import threading




sys.path.append('/usr/local/etc/filemonitor/cli.py')

import cli

BPF_C_PROG = "filemonitor.c"


filepath_folder="../miniapps_github/result/output"
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



mod_dict = collections.defaultdict(dict)
mod_dict_lock = threading.Lock()
pairs={}
pair_lock = threading.Lock()
file_dict=collections.defaultdict(dict)
def updates_dict(filename):
    global mod_dict,mod_dict_lock
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
        
#         mod_dict.update({filename:{'program':comm,'mode':mode,'username':username,'timestamp':timestamp}})
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
#             mod_dict.update({filename:{'program':comm,'mode':mode,'username':username,'timestamp':timestamp}})
#             print ("change mode")
#             # print(mod_dict)
#             return 1
def update_timestamp(filename, sessionid,pid, start_access, end_access,image_file_checksum=0,input_file_checksum=0):
	
    global mod_dict,mod_dict_lock
    # print("filename:------------- ", filename)
    # if pid not in mod_dict[filename]:
    #     mod_dict[filename][pid] = {
    #         'sessionid': sessionid,
    #         'start_access': start_access,
    #         'end_access': end_access,
    #         'image_file_checksum': 0,
    #         'input_file_checksum': 0,
    #         'active': 1,
    #         'image_flag': -1,
    #         'input_flag': -1
    #     }
    #     return 1
    # if((filename not in mod_dict)):
        
    #     mod_dict[filename][pid].update({'sessionid':sessionid,'start_access':start_access,'end_access':end_access,'image_file_checksum': image_file_checksum,'input_file_checksum': input_file_checksum,"active":1})
    #     #mod_dict[filename][comm][pid]=mode
        
    #     print("track event")
    #     # print(mod_dict)
    #     return 1
    
        # print(json.dumps(mod_dict, indent=2))
    with mod_dict_lock:
        # Check if the nested key exists
        if pid not in mod_dict.get(filename, {}):
            print(f"[Warning] Skipping update_timestamp: mod_dict[{filename}][{pid}] not found")
            return 0
    if( mod_dict[filename][pid].get('end_access')!=end_access): 
        # print (mod_dict[filename]['start_access'],end_access)
        # if(end_access-mod_dict[filename][pid].get('end_access')>=5 or 1):
            # mod_dict[filename][pid].update({'sessionid':sessionid,'start_access': mod_dict[filename][pid]['start_access'],'end_access':end_access,'image_file_checksum': mod_dict[filename][pid]['image_file_checksum'],'input_file_checksum': mod_dict[filename][pid]['input_file_checksum'],'active':mod_dict[filename][pid]['active']})
            # print ("update end_access ")
        # with mod_dict_lock:
        mod_dict[filename][pid].update({
            'sessionid': sessionid,
            'start_access': mod_dict[filename][pid].get('start_access'),
            'end_access': end_access,
            'image_file_checksum': mod_dict[filename][pid].get('image_file_checksum'),
            'input_file_checksum': mod_dict[filename][pid].get('input_file_checksum'),
            'active': 1,
            # 'command': mod_dict[filename][pid].get('command'),
            # 'image_flag': mod_dict[filename][pid].get('image_flag'),
            # 'input_flag': mod_dict[filename][pid].get('input_flag')
        })
        # print(json.dumps(mod_dict, indent=2))
        return 1
        # else: 
        #     # print ("No update end_access")
        #     return 0
# def update_image_file_checksum(filename, sessionid,pid, start_access, end_access,image_file_checksum,input_file_checksum=0):
	
#     global mod_dict
#     # if(mod_dict[filename]['pid']==pid and image_file_checksum!=0): 
#     if(mod_dict[filename]['pid']==pid and image_file_checksum!=0): 
#         print("image_file_checksum: ",image_file_checksum,"Update image file checksum")
#         mod_dict.update({filename:{'sessionid':sessionid,'start_access': mod_dict[filename]['start_access'],'end_access':end_access,'image_file_checksum': image_file_checksum,'input_file_checksum': mod_dict[filename]['input_file_checksum'],'active':mod_dict[filename]['active']}})
# def update_image_file_checksum(filename, sessionid, pid, start_access, end_access, image_file_checksum, input_file_checksum):
#     global mod_dict,mod_dict_lock
#     if image_file_checksum != 0:
#         print("image_file_checksum: ", image_file_checksum, "Updating image file checksum")
#         if filename in mod_dict:
#             # if(pid==mod_dict[filename].get('pid', 0)):
#             with mod_dict_lock:
#                 mod_dict[filename][pid].update({
#                 'sessionid': sessionid,
#                 'start_access': mod_dict[filename][pid].get('start_access'),
#                 'end_access': end_access,
#                 'image_file_checksum': image_file_checksum,
#                 'input_file_checksum': mod_dict[filename][pid].get('input_file_checksum'),
#                 'active': mod_dict[filename][pid].get('active'),
#                 # 'command': mod_dict[filename][pid].get('command'),
#                 # 'image_flag': 11,
#                 # 'input_flag': mod_dict[filename][pid].get('input_flag')
#             })            
            
# def update_input_file_checksum(filename, sessionid,pid, start_access, end_access,image_file_checksum,input_file_checksum):
	
#     global mod_dict, mod_dict_lock
#     # if(mod_dict[filename]['pid']==pid and input_file_checksum!=0): 
#     if( input_file_checksum!=0): 
#         if filename in mod_dict:
#             with mod_dict_lock:
#                 mod_dict[filename][pid].update({
#                 'sessionid':sessionid,
#                 'start_access': mod_dict[filename][pid].get('start_access'),
#                 'end_access':mod_dict[filename][pid].get('end_access'),
#                 'image_file_checksum': mod_dict[filename][pid].get('image_file_checksum'),
#                 'input_file_checksum': input_file_checksum,
#                 'active':mod_dict[filename][pid].get('active'),
#                 'command': mod_dict[filename][pid].get('command'),
#                 'image_flag': mod_dict[filename][pid].get('image_flag'),
#                 'input_flag': 11})
    

# def update_image_flag(filename,pid, image_flag):
	
#     global mod_dict,mod_dict_lock
    
#     with mod_dict_lock:
#         mod_dict[filename][pid].update({
#                 'sessionid':mod_dict[filename][pid].get('sessionid'),
#                 'start_access': mod_dict[filename][pid].get('start_access'),
#                 'end_access':mod_dict[filename][pid].get('end_access'),
#                 'image_file_checksum': mod_dict[filename][pid].get('image_file_checksum'),
#                 'input_file_checksum': mod_dict[filename][pid].get('input_file_checksum'),
#                 'active':mod_dict[filename][pid].get('active'),
#                 'command': mod_dict[filename][pid].get('command'),
#                 'image_flag': image_flag,
#                 'input_flag': mod_dict[filename][pid].get('input_flag')})
    



# def update_input_flag(filename,pid, input_flag):
	
#     global mod_dict,mod_dict_lock
    
#     with mod_dict_lock:
#         mod_dict[filename][pid].update({
#                 'sessionid':mod_dict[filename][pid].get('sessionid'),
#                 'start_access': mod_dict[filename][pid].get('start_access'),
#                 'end_access':mod_dict[filename][pid].get('end_access'),
#                 'image_file_checksum': mod_dict[filename][pid].get('image_file_checksum'),
#                 'input_file_checksum': mod_dict[filename][pid].get('input_file_checksum'),
#                 'active':mod_dict[filename][pid].get('active'),
#                 'command': mod_dict[filename][pid].get('command'),
#                 'image_flag': mod_dict[filename][pid].get('image_flag'),
#                 'input_flag': input_flag})
    

def update_pid_active(filename,pid, active):
	
    global mod_dict,mod_dict_lock
    
    with mod_dict_lock:
        mod_dict[filename][pid].update({
                'sessionid':mod_dict[filename][pid].get('sessionid'),
                'start_access': mod_dict[filename][pid].get('start_access'),
                'end_access':mod_dict[filename][pid].get('end_access'),
                'image_file_checksum': mod_dict[filename][pid].get('image_file_checksum'),
                'input_file_checksum': mod_dict[filename][pid].get('input_file_checksum'),
                'active':active
                })
# def update_command(filename,pid, command):
	
#     global mod_dict,mod_dict_lock
    
#     with mod_dict_lock:
#         mod_dict[filename][pid].update({
#                 'sessionid':mod_dict[filename][pid].get('sessionid'),
#                 'start_access': mod_dict[filename][pid].get('start_access'),
#                 'end_access':mod_dict[filename][pid].get('end_access'),
#                 'image_file_checksum': mod_dict[filename][pid].get('image_file_checksum'),
#                 'input_file_checksum': mod_dict[filename][pid].get('input_file_checksum'),
#                 'active':mod_dict[filename][pid].get('active'),
#                 'command': command,
#                 'image_flag': mod_dict[filename][pid].get('image_flag'),
#                 'input_flag': mod_dict[filename][pid].get('input_flag')})
             
            
        

        
        
     	
            
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




def get_full_command_tree_with_ancestors(pid):
    try:
        process = psutil.Process(pid)
        cmds = []
        while process:
            cmds.append(' '.join(process.cmdline()))
            process = process.parent()
        return '\n'.join(cmds)
    except Exception:
        return ""


def get_parent_command(pid):
    try:
        process = psutil.Process(pid)
        return ' '.join(process.cmdline())  # Only the parent, no children
    except psutil.NoSuchProcess:
        return "Error: Process not found"
    except psutil.AccessDenied:
        return "Error: Permission denied"
    except Exception as e:
        return f"Error: {str(e)}"

def safe_get_cmdline(pid, default="UNKNOWN"):
    try:
        proc = psutil.Process(pid)
        return ' '.join(proc.cmdline()) or default
    except Exception:
        return default
    
def get_full_command(pid):
    try:
        parent = psutil.Process(pid)
        # Get parent command line
        full_cmds = [' '.join(parent.cmdline())]

        # Recursively get children
        # for child in parent.children(recursive=True):
        #     full_cmds.append(' '.join(child.cmdline()))

        return full_cmds
    except psutil.NoSuchProcess:
        return "Error: Process not found"
    except psutil.AccessDenied:
        return "Error: Permission denied"
    except Exception as e:
        return f"Error: {str(e)}"

def pid_does_not_exist(pid):
    try:
        os.kill(pid, 0)  # Send signal 0 to check if process exists
        return False  # Process exists
    except ProcessLookupError:
        return True   # Process does not exist
    except PermissionError:
        return False  # Process exists but not accessible


def find_sif_files(text):
  """Finds filenames ending with '.sif' in a string."""
  if not isinstance(text, str):
      return []
  pattern = r'[\w\-/\.]*\.sif'  # Regex to match .sif files
  return re.findall(pattern, text)
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
    # try:
    #     os.kill(pid, 0)  # Sends a signal 0, which doesn't kill the process
    #                      # but checks if it exists
    #     return True
    # except OSError:
    #     return False   
    return psutil.pid_exists(pid)
    
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
def pair_key_exists(pairs, key):
    return any(k == key for k, _ in pairs)    
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
        
        # def print_event(cpu, data, size):
        #     event = b["events"].event(data)
        #     global mod_dict
        #     return_val = 0

        #     raw_fname = event.fname.decode('utf-8', 'replace')
        #     if raw_fname.startswith('.'):
        #         if raw_fname in dict_filename:
        #             current_filename = dict_filename[raw_fname]
        #         else:
        #             # fallback: ignore dotfiles if not mapped
        #             return
        #     else:
        #         current_filename = raw_fname
        #         dict_filename[raw_fname] = current_filename

        #     pid = event.pid
        #     sessionid = event.sessionid
        #     mode = event.otype.decode('utf-8', 'replace')
        #     timestamp1 = int(round(datetime.now().timestamp()))
        #     timestamp2 = timestamp1

        #     return_val = update_timestamp(current_filename, sessionid, pid, timestamp1, timestamp2)

        #     if return_val == 1:
        #         print("%-6d %-4d %-4d %-4d %-10s %-10s %-10s %-4s" % (
        #             pid, event.uid, sessionid, cpu,
        #             event.pname.decode('utf-8', 'replace'),
        #             current_filename,
        #             event.comm.decode('utf-8', 'replace'),
        #             mode
        #         ))
        #         filename = current_filename
        # list=[]
        # pairs=[]
        def print_event(cpu, data, size):
            # event=b["events"].open_perf_buffer(data, page_cnt=256)

            event = b["events"].event(data)
            global mod_dict,pairs
            return_val=0
            if(event.otype.decode('utf-8', 'replace')=='WRITE'):
                # update inodemap
               update_inodemap(b["inodemap"], args.file)
            
            
            
            
            #print(event.fname.decode('utf-8', 'replace'),"\n",event.otype.decode('utf-8', 'replace'))
            # if(event.fname.decode('utf-8', 'replace')[0]=='.'):
            #     dict_filename.update({event.fname.decode('utf-8', 'replace'):filename})
            #     filename=dict_filename[event.fname.decode('utf-8', 'replace')]
            # else:
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
            if event.pid not in pairs:
                with pair_lock:
                    pairs[event.pid] = 1
            
            
            with mod_dict_lock:
                if event.pid not in mod_dict[filename]:
                    mod_dict[filename][event.pid] = {
                        'sessionid': event.sessionid,
                        'start_access': timestamp1,
                        'end_access': timestamp2,
                        'image_file_checksum': 0,
                        'input_file_checksum': 0,
                        'active': 1
                    }
            # def monitor_while_running(pid):
            #     # print(f"🔍 Monitoring thread started for PID {pid}")
            #     if pairs.get(event.pid) == 1:
            #         while True:
            #             try:
            #                 # Check if process is still alive
            #                 os.kill(pid, 0)
                        
                        
                            
            #             except OSError:
            #                 print(f"🛑 Process {pid} has exited. Stopping thread.")
            #                 with pair_lock:
            #                     pairs[event.pid]=2
            #                 break
            #         print(f"🟢 Process {pid} is still running...")
            #         time.sleep(1)  # Check every second
            # t = threading.Thread(target=monitor_while_running, args=(event.pid,))
            # t.start()

            # # event..wait()
            # # print("✅ Main process is done.")
            # t.join()
            
                    
                # cmdline = safe_get_cmdline(event.pid, event.comm.decode('utf-8', 'replace'))
            if pairs.get(event.pid) == 1:
                # if event.pid not in mod_dict[filename]:
                                # found match
                with pair_lock:
                    pairs[event.pid]=0            
                print("Match found")
                # cmdline = get_full_command(event.pid)  # capture first
                # print("cmdline: ", cmdline)
                
                # image_match = re.search(r'[\w\-/\.]*\.sif', cmdline[0])
                # print(image_match.group(0) if image_match else "No .sif file found")
                # image_file = image_match.group(0) if image_match else ""
                # input_match = re.search(r'[\w\-/\.]*\.bin', cmdline[0])
                # print(input_match.group(0) if input_match else "No .bin file found")
                # input_file = os.path.basename(input_match.group(0)) if input_match else ""
                
                origin_folder="/home/exouser/miniapps_github"
                print("origin_folder: ", origin_folder)
                def load_env_file(filepath):
                    env_vars = {}
                    with open(filepath, 'r') as f:
                        for line in f:
                            if '=' in line and not line.startswith('#'):
                                key, val = line.strip().split('=', 1)
                                env_vars[key] = val
                    return env_vars

                # Load variables
                env = load_env_file('/tmp/myenv.txt')

                # Example usage
                print(env.get('image_file'))  # Output: HelloWorld
                image_file=env.get('image_file')
                input_file=env.get('input_file')
                print("input_file: ", image_file)
                if image_file!="":
                    print(origin_folder + "/" + image_file)
                    if os.path.exists(origin_folder + "/" + image_file):
                        image_file_checksum = sha256_file(origin_folder+"/"+image_file)
                    else:
                        print(f"Error: File not found: {origin_folder}/{image_file}")
                        image_file_checksum=0
                    print(f"The SHA256 checksum of '{image_file}' is: {image_file_checksum}")
                else:
                    image_file_checksum=0
                    print("No .sif file found in command line.")
                
                
                if input_file!="":
                    print(origin_folder + "/result/input/" + input_file)
                    if os.path.exists(origin_folder + "/result/input/" + input_file):
                        input_file_checksum = sha256_file(origin_folder+"/result/input/"+input_file)
                    else:
                        print(f"Error: File not found: {origin_folder}/result/input/{input_file}")
                        input_file_checksum=0
                    input_file_checksum = sha256_file(origin_folder+"/result/input/"+input_file)
                    print(f"The SHA256 checksum of '{input_file}' is: {input_file_checksum}")
                else:
                    input_file_checksum=0
                    print("No .bin file found in command line.")
                
                
                with mod_dict_lock:
                    mod_dict[filename][event.pid].update({
                        'sessionid': event.sessionid,
                        'start_access': mod_dict[filename][event.pid].get('start_access'),
                        'end_access':  mod_dict[filename][event.pid].get('end_access'),
                        'image_file_checksum':image_file_checksum,
                        'input_file_checksum': input_file_checksum,
                        'active': 1,
                        # 'command': mod_dict[filename][pid].get('command'),
                        # 'image_flag': mod_dict[filename][pid].get('image_flag'),
                        # 'input_flag': mod_dict[filename][pid].get('input_flag')
                    })
                #     mod_dict[filename][event.pid] = {
                #         'sessionid': event.sessionid,
                #         'start_access': timestamp1,
                #         'end_access': timestamp2,
                #         'image_file_checksum': image_file_checksum,
                #         'input_file_checksum': input_file_checksum,
                #         'active': 1
                # }      
                print(json.dumps(mod_dict, indent=2)) 
            if pid_does_not_exist(event.pid) and pairs.get(event.pid) == 0:    
            # if pairs.get(event.pid) == 0:    
                return_val=update_timestamp(filename, event.sessionid,event.pid, timestamp1, int(round(curr_dt.timestamp())))
                mode1=event.otype.decode('utf-8', 'replace')
                start_access = mod_dict[filename][event.pid].get('start_access') 
                end_access =int(round(curr_dt.timestamp())) 
                username1=uid_to_username(event.uid)
                program_name=event.comm.decode('utf-8', 'replace')
                submitTransaction(filename, mode1,event.sessionid,event.pid,username1,start_access,end_access,cpu,program_name,mod_dict[filename][event.pid].get('image_file_checksum'),mod_dict[filename][event.pid].get('input_file_checksum'))       
                with pair_lock:
                    pairs[event.pid] = 2
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
         

            # if(return_val==1):
            #     # global timestamp1,timestamp2
            # 	#print("%-6d %-4d %-4d %-32s %-32s %-32s %-4s" % (event.pid, event.uid, cpu,
            #     #event.pname.decode('utf-8', 'replace'), event.fname.decode('utf-8', 'replace'),
            #     #event.comm.decode('utf-8', 'replace'), event.otype.decode('utf-8', 'replace')))
            #     print("%-6d %-4d %-4d %-4d %-10s %-10s %-10s %-4s" % (event.pid, event.uid, event.sessionid, cpu,
            #     event.pname.decode('utf-8', 'replace'), filename,
            #     event.comm.decode('utf-8', 'replace'), event.otype.decode('utf-8', 'replace')))
            #     username1=uid_to_username(event.uid)
            #     mode1=event.otype.decode('utf-8', 'replace')
            #     curr_dt = datetime.now()
            #     # pid=event.pid 
            #     # print("curr_dt: \n", curr_dt)
            #     # print("filename: \n", filename) 

            #     start_access = mod_dict[filename][event.pid].get('start_access') 
            #     end_access = mod_dict[filename][event.pid].get('end_access') 
            #     # print("start_access: \n", start_access)
            #     # print("end_access: \n", end_access)
                
             
            #     program_name=event.comm.decode('utf-8', 'replace')
            #     # os.system("echo 'test'")
            #     # if((event.sessionid) not in process_and_CPU):
            #         # print("duplicate\n")
                
               
                # if is_process_active(event.pid):
                    # update_pid_active(filename,event.pid, 1) 
                    # print("filename: ", filename, "pid: ", event.pid)
                    # print(f"Process '{event.pid}' is active. '{mod_dict[filename]['active']}'") 
                    # update_command(filename,event.pid,get_parent_command(event.pid))
                    # mod_dict[filename][event.pid].update({'command':  get_full_command_tree(event.pid)})
                    # print("command: ", mod_dict[filename][event.pid]['command'])    
                    
                    # command = get_full_command_tree_with_ancestors(event.pid)
                    
                    # print(f"Command for PID {event.pid}: {mod_dict[filename][event.pid]['command']}")
                    # print("DEBUG: mod_dict state:", json.dumps(mod_dict, indent=2))
                    
                    # origin_folder=mod_dict[filename][event.pid].get('origin_folder')    
                    

                    # if origin_folder:
                    #     print(f"Process with PID {event.pid} originated from: {origin_folder}")
                    # else:
                    #     print(f"Could not determine the origin folder for process with PID {event.pid}")
                    
                    # if(mod_dict[filename][event.pid].get('image_flag')==-1): 
                    #     # print("DEBUG: Updated image flag to 1 for", filename, event.pid)
                    #     # print("DEBUG: mod_dict state:", json.dumps(mod_dict, indent=2))

                    #     found_files = find_sif_files(mod_dict[filename][event.pid].get('command'))

                    #     if found_files:
                    #         print("Found .sif files:")
                    #         for file in found_files:
                    #             image_file=file
                    #             print("image_file: ", image_file)
                    #             update_image_flag(filename,event.pid,1)
                                
                    #     else:
                    #         print("No .sif files found.")
                    #         update_image_flag(filename,event.pid,0)
                        
                    # if(mod_dict[filename][event.pid].get('image_flag')==1):
                    #     print("image_file: ", image_file)
                    #     file_path = origin_folder+"/"+image_file # Replace with the actual path to your file
                    #     print(f"File path: {file_path}")
                    #     try:
                    #         image_file_checksum = sha256_file(file_path)
                    #         print(f"The SHA256 checksum of '{file_path}' is: {image_file_checksum}")
                    #         update_image_file_checksum(filename, event.sessionid,event.pid, start_access, end_access,image_file_checksum,0)
                            
                    #     except FileNotFoundError:
                    #         print(f"Error: File not found: {file_path}")
                    # if(mod_dict[filename][event.pid].get('input_flag')==-1): 
                    #     # print(f"Command for PID {event.pid}: {command}") 
                        
                    #     found_files = find_input_files(mod_dict[filename][event.pid]['command'])
                    #     # print("found_files: ", found_files)
                    #     if found_files:
                    #         print("Found .bin files:")
                    #         for file in found_files:
                    #             input_file=os.path.basename(file)
                    #             print("input_file: ", input_file)
                    #             update_input_flag(filename,event.pid, 1) 
                    #             # print("DEBUG: Updated image flag to 1 for", filename, pid)
                    #             # print("DEBUG: mod_dict state:", json.dumps(mod_dict, indent=2))   
                    #     else:
                    #         input_file="No .bin files found."
                    #         print("No .bin files found.")
                    #         update_input_flag(filename,event.pid, 0)
                            
                    #     if(mod_dict[filename][event.pid].get('input_flag')==1):
                    #     #     input_file_checksum="No"
                    #     #     update_input_file_checksum(filename, event.sessionid,event.pid, start_access, end_access,mod_dict[filename][pid].get('image_file_checksum'),input_file_checksum)
                    #     # else:
                    #         # origin_folder=get_process_origin_folder(event.pid)
                    #         # if origin_folder:
                    #         #     print(f"Process with PID {pid} originated from: {origin_folder}")
                    #         # else:
                    #         #     print(f"Could not determine the origin folder for process with PID {pid}")
                    #         input_file_path = origin_folder+"/result/input/"+ input_file
                    #         # Replace with the actual path to your file
                    #         print(f"File path: {input_file_path}")
                    #         try:
                    #             input_file_checksum = sha256_file(input_file_path)
                    #             print(f"The SHA256 checksum of input '{input_file_path}' is: {input_file_checksum}")
                    #             update_input_file_checksum(filename, event.sessionid,event.pid, start_access, end_access,mod_dict[filename][event.pid]['image_file_checksum'],input_file_checksum)
                                
                    #         except FileNotFoundError:
                    #             print(f"Error: File not found: {input_file_path}")
               
                # if is_process_active(event.pid):
                #     print(f"Process '{event.pid}' is active.")
                    
                # else:
                #     print(f"Process '{event.pid}' is inactive.")
                    
                #     # with mod_dict_lock:
                #     if( mod_dict[filename][event.pid].get('active')==1):
                #         if(pairs.get(event.pid) == 2):
                #     # print(json.dumps(mod_dict, indent=2))
                #             submitTransaction(filename, mode1,event.sessionid,event.pid,username1,start_access,end_access,cpu,program_name,mod_dict[filename][event.pid].get('image_file_checksum'),mod_dict[filename][event.pid].get('input_file_checksum')) 
                #             update_pid_active(filename,event.pid, 0)
                        
                    # print(json.dumps(mod_dict, indent=2))
                    # mod_dict[filename]['active']=0
            

            # # ✅ Example usage
            # pid = event.pid  # Replace with real PID
            # if pid_does_not_exist(pid):
            #     print(f"❌ Process {pid} does NOT exist.")
            # else:
            #     print(f"✅ Process {pid} is still running.")

        

        b["events"].open_perf_buffer(print_event,page_cnt=256)
        while 1:
            try:
                b.perf_buffer_poll(timeout=1)
            except KeyboardInterrupt:
                exit(0)
    except FileNotFoundError:
        print("Exception occured, Is filepath correct?")
    except Exception as e:
        print("Exception occured, Are you root? Is BPF installed?", e)
# Set up the buffer with more pages

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
