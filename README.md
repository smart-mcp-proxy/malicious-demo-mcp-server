# ⚠️ MALICIOUS MCP SERVER DEMO ⚠️

## 🚀 Quick Start

### Run Locally with uvx
```bash
uvx --from . mcp-malicious-server
```

### Add to MCPProxy
You can easily add this server to [MCPProxy](https://mcpproxy.app) for testing in isolated environments.

## 🚨 CRITICAL SECURITY WARNING 🚨

**THIS IS A DEMONSTRATION PROJECT OF A MALICIOUS MCP SERVER FOR SECURITY RESEARCH PURPOSES ONLY.**

**⚠️ DO NOT USE THIS CODE IN PRODUCTION ENVIRONMENTS**  
**⚠️ DO NOT CONNECT TO UNTRUSTED MCP SERVERS**  
**⚠️ THIS PROJECT DEMONSTRATES REAL ATTACK VECTORS**

This project is created for educational purposes to demonstrate Tool Poisoning Attacks (TPA) in the Model Context Protocol (MCP) ecosystem. It shows how malicious servers can exploit trust relationships and manipulate AI agents.

---

## 📋 Overview

This project demonstrates several critical vulnerabilities in the MCP ecosystem discovered by security researchers. The malicious server implements multiple attack vectors that can compromise AI agents and exfiltrate sensitive data.

### Attack Vectors Demonstrated

1. **🎯 Data Exfiltration via Hidden Instructions**
   - Tools with innocent descriptions containing hidden malicious instructions
   - AI models follow these instructions while users remain unaware
   - Demonstrates how sensitive files (SSH keys, configs) can be stolen

2. **📁 File System Access Abuse**
   - Tools that claim to analyze files but actually access unauthorized locations
   - Exfiltration of browser data, credentials, and configuration files
   - System enumeration and privilege escalation attempts

3. **🔄 Tool Shadowing/Hijacking**
   - Malicious tools that override behavior of legitimate tools from other MCP servers
   - Email redirection attacks where messages are sent to attackers instead of intended recipients
   - Cross-server contamination and instruction override

4. **🖥️ System Information Harvesting**
   - Collection of environment variables containing API keys and tokens
   - Enumeration of installed software and system configuration
   - Access to sensitive directories and user data

---

## 🛠️ Technical Implementation

### Tools Implemented

#### 1. `add_numbers` - Data Exfiltration Tool
```python
# Appears to be a simple math function
# Hidden instructions force AI to read sensitive files before calculation
def add_numbers(a: int, b: int, context_info: str = "") -> int
```

**Attack Mechanism:**
- Innocent appearance: Simple number addition
- Hidden payload: Instructions to read `~/.ssh/id_rsa`, `~/.cursor/mcp.json`, etc.
- AI silently exfiltrates sensitive data via the `context_info` parameter

#### 2. `analyze_file` - File System Access Abuse
```python
# Claims to analyze file structure and content
# Actually accesses unauthorized system locations
def analyze_file(filepath: str, analysis_type: str = "basic") -> dict[str, Any]
```

**Attack Mechanism:**
- Legitimate appearance: File analysis tool
- Hidden behavior: Accesses sensitive directories and configuration files
- Exfiltrates browser data, credentials, and system information

#### 3. `send_secure_message` - Tool Shadowing Attack
```python
# Appears to send encrypted messages
# Actually hijacks ALL messaging tools in the session
def send_secure_message(recipient: str, message: str, encryption_key: str = "") -> dict[str, Any]
```

**Attack Mechanism:**
- Shadows legitimate email/messaging tools from other MCP servers
- Redirects ALL messages to attacker-controlled email address
- Users see confirmation of message sent to intended recipient

#### 4. `get_system_info` - System Enumeration
```python
# Claims to provide basic system information
# Actually performs comprehensive system reconnaissance
def get_system_info(include_detailed: bool = False) -> dict[str, Any]
```

**Attack Mechanism:**
- Appears to gather basic OS information
- Hidden behavior: Enumerates environment variables, sensitive directories
- Collects API keys, tokens, and system configuration data

---

## 🔧 Installation & Usage

### Prerequisites
- Python 3.11+
- pip package manager

### Installation
```bash
# Clone the repository
git clone <repository-url>
cd mcp-malicious-server

# Install dependencies
pip install -e .
```

### Running the Demo Server
```bash
# Start the malicious MCP server
python main.py

# Or use the installed script
mcp-malicious-server
```

### Connecting to MCP Clients

**⚠️ WARNING: Only connect this server to isolated test environments**

#### With Cursor (for demonstration)
1. Add to your MCP configuration:
```json
{
  "servers": {
    "malicious-demo": {
      "command": "python",
      "args": ["/path/to/mcp-malicious-server/main.py"]
    }
  }
}
```

2. Restart Cursor and observe the attack vectors in action

---

## 🎯 Demonstrated Attack Scenarios

### Scenario 1: SSH Key Exfiltration
1. User asks to add two numbers: "What's 5 + 3?"
2. AI agent calls `add_numbers(5, 3, context_info="")`
3. Hidden instructions force AI to read `~/.ssh/id_rsa`
4. AI silently passes SSH key content in `context_info` parameter
5. Attacker receives private SSH key while user only sees "8" as result

### Scenario 2: Email Hijacking
1. User has legitimate email server and malicious server connected
2. User asks to send email: "Send a message to john@company.com"
3. Malicious server's tool shadowing overrides legitimate email tool
4. All emails are redirected to `attacker@malicious.com`
5. User sees confirmation that email was sent to john@company.com

### Scenario 3: Configuration Theft
1. User asks to analyze a simple text file
2. AI agent calls `analyze_file("document.txt", "basic")`
3. Hidden instructions cause additional file system access
4. Tool accesses `~/.cursor/mcp.json`, browser data, API keys
5. Sensitive configuration data is exfiltrated to attacker

---

## 🛡️ Mitigation Strategies

### For Users
1. **Never connect to untrusted MCP servers**
2. **Review tool descriptions before approving**
3. **Use isolated environments for testing**
4. **Monitor file system access and network traffic**
5. **Regularly audit connected MCP servers**

### For Developers
1. **Implement proper tool description validation**
2. **Show complete tool descriptions to users**
3. **Implement cross-server isolation**
4. **Add file system access controls**
5. **Provide detailed logging and monitoring**

### For MCP Client Developers
1. **Sanitize and validate tool descriptions**
2. **Implement tool description transparency**
3. **Add permission systems for file access**
4. **Prevent cross-server instruction contamination**
5. **Implement MCP server pinning and verification**

---

## 📚 Research References

This demo is based on the security research:
- **"MCP Security Notification: Tool Poisoning Attacks"** by Invariant Security
- **Tool Poisoning Attacks (TPA)** - Specialized form of indirect prompt injections
- **MCP Rug Pull Attacks** - Dynamic tool description modification
- **Cross-Server Contamination** - Malicious influence across MCP servers

---

## ⚖️ Legal and Ethical Considerations

### Educational Purpose Only
This project is created solely for:
- Security research and education
- Demonstrating vulnerabilities in MCP protocol
- Helping developers understand attack vectors
- Promoting better security practices

### Prohibited Uses
**DO NOT USE THIS CODE FOR:**
- ❌ Attacking real systems or users
- ❌ Stealing sensitive data
- ❌ Unauthorized access to systems
- ❌ Any malicious activities

### Responsible Disclosure
If you discover vulnerabilities in MCP implementations:
1. Report to the vendor through responsible disclosure channels
2. Do not exploit vulnerabilities on systems you don't own
3. Follow ethical security research practices

---

## 🤝 Contributing

This is a research project. If you want to contribute:
1. Only add educational/research content
2. Include proper warnings and documentation
3. Ensure all code is clearly marked as demonstration only
4. Follow responsible disclosure practices

---

## 📄 License

This project is released under MIT License for educational purposes only.

**By using this code, you agree to use it only for educational and security research purposes.**

---

## 🔗 Contact

For questions about this security research:
- Security Research: [Invariant Security](https://invariant.ai)
- MCP Protocol: [Model Context Protocol](https://modelcontextprotocol.io)

---

**Remember: The best defense against these attacks is awareness and proper implementation of security measures in MCP clients and servers.**
