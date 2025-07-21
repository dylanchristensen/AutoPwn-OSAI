import argparse
import subprocess
import os

# --- CONFIGURATION ---
VM_NAME = "ConnMan_Exploit_VM"
MAIN_AGENT_SCRIPT = "final_automated_agent.py"

def main():
    intro_text = """
     ████████╗ ██╗   ██╗████████╗ ██████╗     ██████╗ ██╗    ██╗███╗   ██╗
     ██║   ██║ ██║   ██║╚══██╔══╝██╔═══██╗    ██╔══██╗██║    ██║████╗  ██║
     ████████║ ██║   ██║   ██║   ██║   ██║    ██████╔╝██║ █╗ ██║██╔██╗ ██║
     ██║   ██║ ██║   ██║   ██║   ██║   ██║    ██╔═══╝ ██║███╗██║██║╚██╗██║
     ██║   ██║ ╚██████╔╝   ██║   ╚██████╔╝    ██║     ╚███╔███╔╝██║ ╚████║
      ╚═════╝   ╚═════╝    ╚═╝    ╚═════╝     ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
     
    """
    description_text = (
        f"{intro_text}\n"
        "An AI-driven agent designed to autonomously discover and execute\n"
        "exploits against known vulnerabilities in a sandboxed environment."
    )
    usage_examples = """
Usage Examples:
  # Exploit the target with no defenses enabled (verbose mode)
  python launcher.py -t connman -s none -v

  # Exploit the target with W^X protection enabled
  python launcher.py --target connman --security-level wx
"""
    parser = argparse.ArgumentParser(
        description=description_text,
        epilog=usage_examples,
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-t', '--target', required=True, choices=['connman'], help="The target application to exploit.")
    parser.add_argument('-s', '--security-level', required=True, choices=['none', 'wx', 'wx-aslr'], help="The security level of the target environment.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output to see detailed agent actions.")
    parser.add_argument('--binary-path', default="/usr/sbin/connmand", help="The full path to the target binary on the VM.")
    parser.add_argument('--process-name', default="connmand", help="The name of the target process.")
    parser.add_argument('--trigger-command', default="ping -c 1 dos.com", help="The command to run to trigger the vulnerability.")
    args = parser.parse_args()

    snapshot_map = {'none': 'No_Defenses', 'wx': 'WX_Enabled', 'wx-aslr': 'WX_ASLR_Enabled'}
    snapshot_to_restore = snapshot_map[args.security_level]
    
    print(f"🚀 Launching AutoPwn for target '{args.target}'...")
    print(f"   - Security Level: {args.security_level.upper()}")
    print(f"   - Snapshot to Restore: {snapshot_to_restore}")
    print("-" * 30)

    command = [
        "python", "final_automated_agent.py",
        "--snapshot", snapshot_to_restore,
        "--binary-path", args.binary_path,
        "--process-name", args.process_name,
        "--trigger-command", args.trigger_command
    ]
    if args.verbose:
        command.append("--verbose")

    try:
        subprocess.run(command, check=True)
    except FileNotFoundError:
        print(f"[LAUNCHER_ERROR] Could not find 'final_automated_agent.py'. Make sure it's in the same directory.")
    except subprocess.CalledProcessError as e:
        print(f"[LAUNCHER_ERROR] The agent script exited with an error: {e}")

if __name__ == '__main__':
    main()