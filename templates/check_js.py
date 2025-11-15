#!/usr/bin/env python3
import re
import sys

def extract_and_check_js(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract JavaScript code between script tags
    script_pattern = r'<script[^>]*>(.*?)</script>'
    scripts = re.findall(script_pattern, content, re.DOTALL)
    
    print(f"Found {len(scripts)} script blocks")
    
    for i, script in enumerate(scripts):
        print(f"\n--- Checking script block {i+1} ---")
        
        # Remove HTML comments and basic cleanup
        cleaned_script = re.sub(r'<!--.*?-->', '', script, flags=re.DOTALL)
        
        # Look for basic JavaScript syntax issues
        lines = cleaned_script.split('\n')
        try_stack = []
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Track try statements
            if stripped.startswith('try') or stripped == 'try':
                try_stack.append(line_num)
            # Look for catch or finally
            elif 'catch' in stripped or 'finally' in stripped:
                if try_stack:
                    try_stack.pop()
                else:
                    print(f"  Line {line_num}: Unmatched catch/finally: {stripped}")
        
        # Report unmatched try statements
        for try_line in try_stack:
            context_lines = []
            start = max(0, try_line - 4)
            end = min(len(lines), try_line + 3)
            for j in range(start, end):
                marker = ">>> " if j == try_line - 1 else "    "
                context_lines.append(f"{marker}{j+1}: {lines[j].rstrip()}")
            
            print(f"  Line {try_line}: Unmatched try statement")
            print("  Context:")
            for ctx in context_lines:
                print(f"    {ctx}")
        
        if not try_stack:
            print("  No unmatched try statements found in this block")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        extract_and_check_js(sys.argv[1])
    else:
        extract_and_check_js("enhanced_archive.html")