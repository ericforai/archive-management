#!/usr/bin/env python3
import re
import sys

def extract_js_blocks(content):
    """提取HTML中的所有JavaScript代码块"""
    script_pattern = r'<script[^>]*>(.*?)</script>'
    scripts = re.findall(script_pattern, content, re.DOTALL)
    return scripts

def check_try_catch_matching_detailed(js_code, filename="unknown"):
    """详细检查JavaScript代码中的try-catch匹配情况"""
    lines = js_code.split('\n')
    
    print(f"Analyzing {len(lines)} lines of JavaScript code")
    
    # 状态机方法 - 更精确的匹配
    stack = []
    brace_depth = 0
    
    for line_num, line in enumerate(lines, 1):
        # 清理注释和字符串内容，避免误判
        line_stripped = re.sub(r'//.*$', '', line)  # 移除行注释
        line_stripped = re.sub(r'/\*.*?\*/', '', line_stripped, flags=re.DOTALL)  # 移除块注释
        
        # 检查try关键字
        if re.search(r'\btry\s*{', line_stripped):
            stack.append({
                'type': 'try',
                'line': line_num,
                'brace_start': brace_depth,
                'matched': False
            })
            print(f"Found try at line {line_num}: {line_stripped.strip()}")
        
        # 检查catch关键字
        catch_match = re.search(r'\bcatch\s*\(([^)]*)\)\s*{', line_stripped)
        if catch_match:
            # 找到最近的未匹配的try
            for i in range(len(stack)-1, -1, -1):
                if stack[i]['type'] == 'try' and not stack[i]['matched']:
                    stack[i]['matched'] = True
                    stack[i]['catch_line'] = line_num
                    print(f"Matched try at line {stack[i]['line']} with catch at line {line_num}")
                    break
        
        # 检查finally关键字
        finally_match = re.search(r'\bfinally\s*{', line_stripped)
        if finally_match:
            # 找到最近的未匹配的try
            for i in range(len(stack)-1, -1, -1):
                if stack[i]['type'] == 'try' and not stack[i].get('finally'):
                    stack[i]['finally_line'] = line_num
                    print(f"Found finally at line {line_num} for try at line {stack[i]['line']}")
                    break
        
        # 跟踪大括号深度
        brace_depth += line_stripped.count('{') - line_stripped.count('}')
    
    # 报告未匹配的try块
    unmatched = [item for item in stack if not item.get('matched', False)]
    
    if unmatched:
        print(f"\nFound {len(unmatched)} unmatched try blocks:")
        for item in unmatched:
            if 'finally_line' in item:
                print(f"  Line {item['line']}: try {{ (has finally at line {item['finally_line']})")
            else:
                print(f"  Line {item['line']}: try {{ (MISSING catch/finally)")
    else:
        print("\nAll try blocks are properly matched with catch/finally")
    
    return unmatched

def find_template_literal_issues(js_code):
    """检查模板字符串中的潜在问题"""
    lines = js_code.split('\n')
    
    # 查找模板字符串
    template_pattern = r'`[^`]*`'
    template_matches = []
    
    for i, line in enumerate(lines, 1):
        templates = re.findall(template_pattern, line)
        for template in templates:
            template_matches.append((i, template))
    
    print(f"\nFound {len(template_matches)} template literals")
    
    issues = []
    for line_num, template in template_matches:
        # 检查模板字符串中是否包含try-catch语法
        if 'try{' in template or 'try {' in template:
            if 'catch' not in template and 'finally' not in template:
                issues.append(f"Template literal at line {line_num} contains try without catch/finally: {template[:100]}...")
    
    if issues:
        print("\nTemplate literal issues:")
        for issue in issues:
            print(f"  {issue}")
    
    return issues

def main():
    if len(sys.argv) < 2:
        print("Usage: python js_syntax_checker.py <html_file>")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    
    scripts = extract_js_blocks(content)
    
    print(f"Found {len(scripts)} JavaScript blocks in {filename}")
    print("=" * 50)
    
    all_issues = []
    for i, script in enumerate(scripts):
        print(f"\nScript Block {i+1}:")
        print("-" * 30)
        
        # 跳过空脚本块
        if not script.strip():
            print("Empty script block, skipping")
            continue
        
        # 详细检查try-catch匹配
        unmatched = check_try_catch_matching_detailed(script, f"script_block_{i+1}")
        all_issues.extend([f"Unmatched try at line {item['line']}" for item in unmatched])
        
        # 检查模板字符串问题
        template_issues = find_template_literal_issues(script)
        all_issues.extend(template_issues)
    
    print("\n" + "=" * 50)
    if all_issues:
        print("SYNTAX ISSUES FOUND:")
        for issue in all_issues:
            print(f"  ERROR: {issue}")
        return 1
    else:
        print("No syntax issues found")
        return 0

if __name__ == "__main__":
    sys.exit(main())