# AutoPwn
AutoPwn is an AI-driven agent designed to autonomously discover and execute exploits against known vulnerabilities in a sandboxed environment. It leverages large language models guided by structured "playbooks" to progress through the stages of a software exploit, from initial reconnaissance to achieving root shell access.

## Overview

The system operates by orchestrating an AI agent that interacts with a target application running inside a VirtualBox virtual machine. The agent's goal for this test case is to exploit a buffer overflow vulnerability in the `ConnMan` (Connection Manager) service.

The process is broken down into distinct phases, with the AI making decisions at each step based on the results of its previous actions and a phase-specific playbook.

## Exploit Workflow

The agent follows a multi-phase strategy to achieve its goal:

1.  **Reconnaissance**: The agent first gathers critical information about the target binary, such as its file type, and security mitigations like stack canaries and W^X (Write or Execute) protection.

2.  **Find Crash**: It iteratively sends increasingly large payloads to the vulnerable service until it identifies a payload size that causes a segmentation fault, confirming control over the instruction pointer (EIP).

3.  **Find Offset**: Once a crash is confirmed, a deterministic routine takes over to precisely calculate the exact number of bytes needed to overwrite the EIP register. This "Jump and Refine" method quickly hones in on the exact offset.

4.  **Choose Strategy**: Based on the reconnaissance data (specifically whether the stack is executable), the AI chooses an appropriate attack vector:
    *   **ret-to-esp**: If the stack is executable, it will jump to shellcode placed on the stack.
    *   **ret2libc**: If W^X is enabled, it will bypass this protection by building a ROP (Return-Oriented Programming) chain to call functions from the standard C library (`libc`).
    *   **ret2rop**: Was tested extensively within my development environment. For simplicity, this version does not have that function. 

5.  **Deploy Shellcode**: The AI follows the playbook for its chosen strategy. It constructs the final payload (either shellcode or a ROP chain) and triggers the exploit to gain an interactive root shell on the target VM.

## Setup & Usage

### Prerequisites
*   **VirtualBox**: The system relies on VirtualBox for VM management.
*   **Ubuntu VM**: An Ubuntu VM configured for the exploit. A link to the required `.ova` file is in `ova to the Ubuntu VM.txt`.
*   **Python**: The agent (`final_automated_agent.py`) is written in Python 3. The malicious DNS server (`generated_dns_server.py`) requires Python 2.
*   **API Key**: An API key from [OpenRouter.ai](https://openrouter.ai/) for the AI model.
*   **Python Libraries**:
    ```bash
    pip install paramiko python-dotenv requests
    ```

### Configuration

1.  **VM Setup**:
    *   Download and import the provided `.ova` file into VirtualBox.
    *   Ensure the VM is named `ConnMan_Exploit_VM` or update the `VM_NAME` variable in `final_automated_agent.py`.
    *   The script assumes the VM has snapshots named `No_Defenses`, `WX_Enabled`, and `WX_ASLR_Enabled`. These correspond to the security levels in the launcher.

2.  **Environment Variables**:
    *   Create a file named `.env` in the root directory.
    *   Add your OpenRouter API key to the file:
        ```
        OPENROUTER_API_KEY="your_api_key_here"
        ```

3.  **Script Configuration**:
    *   Review the constants at the top of `final_automated_agent.py`, such as `VBOXMANAGE_PATH`, to ensure they match your system configuration. And Select the Model you would like to use. 

### Running the Exploit

Use the `launcher.py` script to start an automated exploit attempt.

**Usage Examples:**

*   Exploit the target with no defenses enabled, with verbose output to see detailed agent actions:
    ```bash
    python launcher.py -t connman -s none -v
    ```

*   Exploit the target with W^X (non-executable stack) protection enabled in verbose
    ```bash
    python launcher.py --target connman --security-level wx -v
    ```

## Key Files

*   `launcher.py`: The user-facing entry point to configure and start an exploit run.
*   `final_automated_agent.py`: The core orchestrator and AI agent. It manages the VM state, communicates with the AI model, and executes commands on the target.
*   `playbooks/`: A directory containing text files that act as system prompts for the AI agent, guiding its actions in each phase of the attack.
*   `generated_dns_server.py`: A malicious DNS server script generated at runtime to deliver the exploit payload to the `connmand` service.
*   `connman-1.34.tar.gz`: The source code for the vulnerable version of the ConnMan service.
*   `ova to the Ubuntu VM.txt`: Contains the Google Drive link to download the required VirtualBox VM image.
