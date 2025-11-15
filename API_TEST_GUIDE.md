# 电子会计档案管理系统API测试指南

## 概述

本项目基于DA/T 94-2022标准实现了完整的电子会计档案管理系统RESTful API。测试脚本`test_api.py`用于验证API端点的完整性和正确性。

## API端点列表

### 核心API端点

1. **基础服务**
   - GET `/api/v1/health` - API健康检查
   - GET `/api/v1/info` - API信息

2. **档案库管理** `/api/v1`
   - POST `/api/v1/libraries` - 创建档案库
   - GET `/api/v1/libraries` - 获取档案库列表
   - GET `/api/v1/libraries/{id}` - 获取档案库详情
   - PUT `/api/v1/libraries/{id}` - 更新档案库
   - DELETE `/api/v1/libraries/{id}` - 删除档案库
   - POST `/api/v1/libraries/{id}/store` - 存储档案
   - GET `/api/v1/libraries/{id}/retrieve` - 检索档案

3. **智能检索** `/api/v1/search`
   - POST `/api/v1/search` - 综合搜索
   - POST `/api/v1/search/fulltext` - 全文搜索
   - POST `/api/v1/search/metadata` - 元数据搜索
   - POST `/api/v1/search/semantic` - 语义搜索

4. **完整性验证** `/api/v1/integrity`
   - POST `/api/v1/integrity/verify` - 验证档案完整性
   - POST `/api/v1/integrity/audit` - 执行完整性审计

5. **档案管理** `/api/v1/management`
   - POST `/api/v1/management/backup` - 创建备份
   - POST `/api/v1/management/restore` - 恢复备份
   - POST `/api/v1/management/archive` - 归档档案

6. **审计日志** `/api/v1/audit`
   - GET `/api/v1/audit/logs` - 获取审计日志
   - GET `/api/v1/audit/statistics` - 获取审计统计
   - GET `/api/v1/audit/export` - 导出审计日志

7. **元数据管理** `/api/v1/metadata`
   - GET `/api/v1/metadata/templates` - 获取元数据模板
   - POST `/api/v1/metadata/validate` - 验证元数据
   - POST `/api/v1/metadata/standardize` - 标准化元数据

8. **安全服务** `/api/v1/security`
   - POST `/api/v1/security/login` - 用户登录
   - POST `/api/v1/security/logout` - 用户登出
   - POST `/api/v1/security/verify` - 验证令牌
   - GET `/api/v1/security/permissions` - 检查权限

9. **档案分类** `/api/v1/classification`
   - POST `/api/v1/classification/auto` - 自动分类
   - POST `/api/v1/classification/train` - 训练模型
   - GET `/api/v1/classification/suggest` - 获取分类建议

10. **档案采集** `/api/v1/collection`
    - POST `/api/v1/collection/upload` - 上传档案
    - GET `/api/v1/collection/categories` - 获取档案分类
    - POST `/api/v1/collection/validate` - 预验证数据

## 使用测试脚本

### 前置条件

1. 确保Python环境已安装所需的依赖包：
   ```bash
   pip install requests flask flask-sqlalchemy flask-jwt-extended
   ```

2. 启动电子会计档案管理系统服务：
   ```bash
   python app.py
   ```
   服务默认运行在 http://localhost:5000

### 运行测试

1. **默认测试**（使用默认服务器地址）：
   ```bash
   python test_api.py
   ```

2. **自定义服务器地址测试**：
   ```bash
   python test_api.py http://your-server:port
   ```

### 测试流程

测试脚本会自动执行以下测试：

1. **基础端点测试**
   - API健康检查
   - API信息获取

2. **用户认证测试**
   - 用户登录（使用默认管理员账户：admin/admin123）

3. **功能API测试**
   - 档案库管理API
   - 智能检索API
   - 元数据管理API
   - 审计日志API
   - 档案分类API
   - 档案采集API

### 测试报告

测试完成后，脚本会生成以下输出：

1. **控制台输出**：实时显示每个测试用例的执行结果
2. **测试报告文件**：保存为`api_test_report.json`，包含详细的测试结果

### 测试报告格式

```json
{
  "test_summary": {
    "total_tests": 10,
    "passed": 8,
    "failed": 2,
    "success_rate": "80.0%"
  },
  "test_details": [
    {
      "test_name": "API健康检查",
      "success": true,
      "message": "API服务正常",
      "timestamp": "2024-01-01T00:00:00",
      "response_data": {}
    }
  ],
  "timestamp": "2024-01-01T00:00:00"
}
```

## 注意事项

1. **默认管理员账户**
   - 用户名：admin
   - 密码：admin123
   - 邮箱：admin@archive.com
   - 角色：admin

2. **认证令牌**
   - 测试使用JWT令牌进行API认证
   - 令牌默认有效期为24小时

3. **CORS配置**
   - API支持跨域请求
   - 允许所有来源的GET、POST、PUT、DELETE请求

4. **数据库初始化**
   - 应用启动时会自动创建数据库表
   - 自动创建默认管理员用户

## 常见问题

### Q: 测试失败，提示连接超时
**A**: 请检查电子会计档案管理系统是否正常运行，确保服务器在指定地址可访问。

### Q: 用户登录失败
**A**: 请检查默认管理员账户是否已创建，或手动创建管理员用户。

### Q: 某些API测试失败
**A**: 请检查对应的服务模块是否已正确实现和注册。

### Q: 测试脚本无法运行
**A**: 请确保已安装所有必要的Python依赖包，特别是`requests`库。

## 技术规格

- **标准**：基于DA/T 94-2022标准
- **协议**：HTTP/HTTPS
- **格式**：JSON
- **认证**：JWT Bearer Token
- **数据库**：SQLAlchemy ORM
- **Web框架**：Flask
- **测试框架**：Python unittest + requests