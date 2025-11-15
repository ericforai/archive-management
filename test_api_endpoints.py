#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
电子会计档案系统 - API端点综合测试脚本
测试所有实现的API端点功能
"""
import requests
import json
import sys
from datetime import datetime, timedelta

# 配置信息
BASE_URL = "http://127.0.0.1:5001"
API_PREFIX = "/api/enhanced"

class Colors:
    """终端颜色代码"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def print_colored(text, color):
    """打印彩色文本"""
    print(f"{color}{text}{Colors.RESET}")

def log_test(test_name, status, message=""):
    """记录测试结果"""
    if status == "PASS":
        print_colored(f"✅ {test_name}: {status}", Colors.GREEN)
    elif status == "FAIL":
        print_colored(f"❌ {test_name}: {status}", Colors.RED)
    elif status == "WARN":
        print_colored(f"⚠️  {test_name}: {status}", Colors.YELLOW)
    else:
        print_colored(f"ℹ️  {test_name}: {status}", Colors.BLUE)
    
    if message:
        print(f"   {message}")

def test_api_endpoint(endpoint, method="GET", data=None, expected_status=200):
    """测试API端点"""
    url = f"{BASE_URL}{API_PREFIX}{endpoint}"
    
    try:
        if method.upper() == "GET":
            response = requests.get(url)
        elif method.upper() == "POST":
            response = requests.post(url, json=data)
        elif method.upper() == "PUT":
            response = requests.put(url, json=data)
        elif method.upper() == "DELETE":
            response = requests.delete(url)
        else:
            return False, f"不支持的HTTP方法: {method}"
        
        success = response.status_code == expected_status
        
        if success:
            try:
                json_data = response.json()
                return True, f"状态码: {response.status_code}, 响应: {json_data}"
            except:
                return True, f"状态码: {response.status_code}, 响应: {response.text[:100]}"
        else:
            return False, f"状态码: {response.status_code}, 响应: {response.text[:200]}"
            
    except requests.exceptions.RequestException as e:
        return False, f"连接错误: {str(e)}"

def test_basic_endpoints():
    """测试基本端点"""
    print_colored("\n=== 测试基本端点 ===", Colors.BLUE)
    
    endpoints = [
        ("/archives", "GET"),
        ("/statistics", "GET"),
        ("/workflows", "GET"),
        ("/lifecycle-records", "GET"),
        ("/audit", "GET"),
        ("/audit/statistics", "GET"),
        ("/audit/integrity", "GET"),
        ("/audit/export", "GET")
    ]
    
    results = []
    for endpoint, method in endpoints:
        success, message = test_api_endpoint(endpoint, method)
        status = "PASS" if success else "FAIL"
        results.append((endpoint, status, message))
        log_test(f"{method} {endpoint}", status, message)
    
    return results

def test_advanced_endpoints():
    """测试高级功能端点"""
    print_colored("\n=== 测试高级功能端点 ===", Colors.BLUE)
    
    # 测试带参数的GET请求
    test_cases = [
        ("/archives?page=1&per_page=10", "GET"),
        ("/archives?search=档案", "GET"),
        ("/archives?category_id=1", "GET"),
        ("/archives?status=active", "GET"),
        ("/statistics?days=7", "GET"),
        ("/audit?operation_type=list_archives", "GET"),
    ]
    
    results = []
    for endpoint, method in test_cases:
        success, message = test_api_endpoint(endpoint, method)
        status = "PASS" if success else "FAIL"
        results.append((endpoint, status, message))
        log_test(f"{method} {endpoint}", status, message)
    
    return results

def test_json_responses():
    """测试JSON响应格式"""
    print_colored("\n=== 测试JSON响应格式 ===", Colors.BLUE)
    
    endpoints = [
        "/archives",
        "/statistics", 
        "/workflows",
        "/lifecycle-records",
        "/audit",
        "/audit/statistics"
    ]
    
    results = []
    for endpoint in endpoints:
        url = f"{BASE_URL}{API_PREFIX}{endpoint}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    # 检查是否有必需的字段
                    if isinstance(json_data, dict) and 'success' in json_data:
                        status = "PASS"
                        message = f"JSON格式正确，包含success字段"
                    else:
                        status = "WARN" 
                        message = f"JSON格式正确但缺少success字段"
                except:
                    status = "FAIL"
                    message = f"无法解析JSON响应"
            else:
                status = "FAIL"
                message = f"HTTP状态码: {response.status_code}"
        except Exception as e:
            status = "FAIL"
            message = f"请求失败: {str(e)}"
        
        results.append((endpoint, status, message))
        log_test(f"JSON格式检查: {endpoint}", status, message)
    
    return results

def test_error_handling():
    """测试错误处理"""
    print_colored("\n=== 测试错误处理 ===", Colors.BLUE)
    
    # 测试无效端点
    success, message = test_api_endpoint("/invalid_endpoint", "GET")
    log_test("无效端点测试", "PASS" if not success else "WARN", message)
    
    # 测试POST方法（模拟创建操作）
    test_data = {
        "title": "测试档案",
        "category_id": 1,
        "description": "API测试创建的档案"
    }
    
    success, message = test_api_endpoint("/archives", "POST", test_data, expected_status=400)
    log_test("POST创建测试（无认证）", "PASS" if not success else "WARN", message)
    
    return True

def main():
    """主测试函数"""
    print_colored("🧪 电子会计档案系统 - API端点测试开始", Colors.BLUE)
    print_colored(f"测试目标: {BASE_URL}", Colors.BLUE)
    print_colored(f"API前缀: {API_PREFIX}", Colors.BLUE)
    print_colored(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Colors.BLUE)
    
    # 检查服务器是否响应
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        if response.status_code != 200:
            print_colored("❌ 服务器似乎未正常响应", Colors.RED)
            return False
    except Exception as e:
        print_colored(f"❌ 无法连接到服务器: {str(e)}", Colors.RED)
        return False
    
    print_colored("✅ 服务器连接正常", Colors.GREEN)
    
    # 执行所有测试
    all_results = []
    
    # 1. 基本端点测试
    basic_results = test_basic_endpoints()
    all_results.extend(basic_results)
    
    # 2. 高级功能测试
    advanced_results = test_advanced_endpoints()
    all_results.extend(advanced_results)
    
    # 3. JSON响应格式测试
    json_results = test_json_responses()
    all_results.extend(json_results)
    
    # 4. 错误处理测试
    test_error_handling()
    
    # 统计结果
    print_colored("\n=== 测试总结 ===", Colors.BLUE)
    total_tests = len(all_results)
    passed_tests = len([r for r in all_results if r[1] == "PASS"])
    failed_tests = len([r for r in all_results if r[1] == "FAIL"])
    warning_tests = len([r for r in all_results if r[1] == "WARN"])
    
    print_colored(f"总测试数: {total_tests}", Colors.BLUE)
    print_colored(f"通过: {passed_tests}", Colors.GREEN)
    print_colored(f"警告: {warning_tests}", Colors.YELLOW)
    print_colored(f"失败: {failed_tests}", Colors.RED)
    
    if failed_tests == 0:
        print_colored("🎉 所有核心API端点测试通过！", Colors.GREEN)
    else:
        print_colored(f"⚠️  {failed_tests} 个测试失败，请检查实现", Colors.YELLOW)
    
    return failed_tests == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)