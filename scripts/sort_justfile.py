#!/usr/bin/env python3
"""
Sort all commands in justfile alphabetically while preserving structure.
"""

import re
from typing import List, Tuple

def parse_justfile(content: str) -> Tuple[str, List[Tuple[str, str]]]:
    """Parse justfile into header and commands."""
    lines = content.split('\n')
    
    # Find where commands start (after the header section)
    command_start = 0
    for i, line in enumerate(lines):
        if line.strip().startswith('# ============') and 'SYSTEM MANAGEMENT' in lines[i] if i < len(lines) else '':
            command_start = i
            break
    
    # Extract header (everything before commands)
    header_lines = lines[:command_start]
    header = '\n'.join(header_lines)
    
    # Extract commands
    commands = []
    current_command = []
    command_name = None
    in_command = False
    
    for i in range(command_start, len(lines)):
        line = lines[i]
        
        # Check if this is a command definition
        if re.match(r'^[a-z][a-z0-9-]*.*:', line) and not line.startswith(' ') and not line.startswith('\t'):
            # Save previous command if exists
            if command_name and current_command:
                commands.append((command_name, '\n'.join(current_command)))
            
            # Start new command
            command_name = line.split(':')[0].split()[0]
            current_command = [line]
            in_command = True
        elif in_command:
            # Continue collecting command lines
            # Stop at next command or empty line followed by comment/command
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                if line == '' and (next_line.startswith('#') or re.match(r'^[a-z][a-z0-9-]*.*:', next_line)):
                    # End of command
                    if command_name and current_command:
                        commands.append((command_name, '\n'.join(current_command)))
                    command_name = None
                    current_command = []
                    in_command = False
                else:
                    current_command.append(line)
            else:
                current_command.append(line)
    
    # Save last command if exists
    if command_name and current_command:
        # Remove trailing empty lines from last command
        while current_command and current_command[-1] == '':
            current_command.pop()
        commands.append((command_name, '\n'.join(current_command)))
    
    return header, commands

def group_commands(commands: List[Tuple[str, str]]) -> dict:
    """Group commands by category."""
    groups = {
        'Certificate Management': [],
        'Configuration Management': [],
        'Docker Service Management': [],
        'External Service Management': [],
        'Logging and Monitoring': [],
        'OAuth Management': [],
        'Port Management': [],
        'Protected Resource Management': [],
        'Proxy Management': [],
        'Route Management': [],
        'System Management': [],
        'Testing': [],
        'Token Management': [],
        'Utility': [],
    }
    
    for name, content in commands:
        if name.startswith('cert-'):
            groups['Certificate Management'].append((name, content))
        elif name.startswith('config-'):
            groups['Configuration Management'].append((name, content))
        elif name.startswith('service-port'):
            groups['Port Management'].append((name, content))
        elif name.startswith('service-') and not any(x in name for x in ['list-external', 'show-external', 'register', 'unregister', 'update-external']):
            groups['Docker Service Management'].append((name, content))
        elif name.startswith('service-') and any(x in name for x in ['list-external', 'show-external', 'register', 'unregister', 'update-external', 'register-oauth', 'list-all']):
            groups['External Service Management'].append((name, content))
        elif name.startswith('logs-'):
            groups['Logging and Monitoring'].append((name, content))
        elif name.startswith('logs'):
            groups['Logging and Monitoring'].append((name, content))
        elif name.startswith('oauth-'):
            groups['OAuth Management'].append((name, content))
        elif name.startswith('proxy-resource'):
            groups['Protected Resource Management'].append((name, content))
        elif name.startswith('proxy-'):
            groups['Proxy Management'].append((name, content))
        elif name.startswith('route-'):
            groups['Route Management'].append((name, content))
        elif name.startswith('token-'):
            groups['Token Management'].append((name, content))
        elif name.startswith('test'):
            groups['Testing'].append((name, content))
        elif name in ['up', 'down', 'restart', 'rebuild', 'shell', 'redis-cli', 'health', 'help']:
            groups['System Management'].append((name, content))
        else:
            groups['Utility'].append((name, content))
    
    # Sort commands within each group
    for group in groups:
        groups[group].sort(key=lambda x: x[0])
    
    return groups

def main():
    # Read the justfile
    with open('/home/atrawog/AI/atrawog/mcp-http-proxy/justfile', 'r') as f:
        content = f.read()
    
    # Parse the file
    header, commands = parse_justfile(content)
    
    # Group and sort commands
    grouped_commands = group_commands(commands)
    
    # Build the output
    output = [header.rstrip()]
    
    # Add each group
    for group_name, cmds in sorted(grouped_commands.items()):
        if not cmds:
            continue
            
        output.append('')
        output.append('# ' + '=' * 76)
        output.append(f'# {group_name.upper()}')
        output.append('# ' + '=' * 76)
        
        for i, (name, content) in enumerate(cmds):
            if i > 0:
                output.append('')
            output.append(content)
    
    # Write the sorted justfile
    with open('/home/atrawog/AI/atrawog/mcp-http-proxy/justfile.sorted', 'w') as f:
        f.write('\n'.join(output))
    
    print("Sorted justfile written to justfile.sorted")
    print("\nTo apply the changes, run:")
    print("  mv justfile justfile.backup")
    print("  mv justfile.sorted justfile")

if __name__ == '__main__':
    main()