#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单的数据库创建脚本
"""
import sqlite3
import os
from pathlib import Path

def create_database():
    """创建SQLite数据库和基础表"""
    
    # 确保目录存在
    db_dir = Path('instance')
    db_dir.mkdir(exist_ok=True)
    
    # 数据库文件路径
    db_path = db_dir / 'electronic_archive.db'
    
    print(f'🔧 创建数据库: {db_path}')
    
    try:
        # 连接数据库（这会自动创建文件）
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # 创建用户表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(128) NOT NULL,
                full_name VARCHAR(120),
                role VARCHAR(20) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 创建档案表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS archives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title VARCHAR(200) NOT NULL,
                description TEXT,
                category VARCHAR(100),
                file_path VARCHAR(500),
                file_type VARCHAR(50),
                file_size INTEGER,
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        ''')
        
        # 创建审计日志表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action VARCHAR(100) NOT NULL,
                target_type VARCHAR(50),
                target_id INTEGER,
                details TEXT,
                ip_address VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # 创建借阅记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS borrow_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                archive_id INTEGER,
                borrower_name VARCHAR(120),
                borrower_id VARCHAR(50),
                borrow_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                return_date TIMESTAMP,
                status VARCHAR(20) DEFAULT 'borrowed',
                notes TEXT,
                FOREIGN KEY (archive_id) REFERENCES archives (id)
            )
        ''')
        
        # 创建系统配置表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_key VARCHAR(100) UNIQUE NOT NULL,
                config_value TEXT,
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 插入默认管理员用户
        import hashlib
        admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
        
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, email, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 'admin@example.com', admin_password, 'System Administrator', 'admin'))
        
        # 插入默认配置
        default_configs = [
            ('system_name', '电子会计档案管理系统', '系统名称'),
            ('max_file_size', '104857600', '最大文件上传大小(字节)'),
            ('session_timeout', '3600', '会话超时时间(秒)'),
        ]
        
        for key, value, desc in default_configs:
            cursor.execute('''
                INSERT OR IGNORE INTO system_config (config_key, config_value, description)
                VALUES (?, ?, ?)
            ''', (key, value, desc))
        
        # 提交更改
        conn.commit()
        
        # 检查表是否创建成功
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print('✅ 数据库创建成功!')
        print(f'📋 创建了 {len(tables)} 个表:')
        for table in tables:
            print(f'  - {table[0]}')
        
        print(f'📁 数据库文件: {db_path}')
        print(f'📏 数据库大小: {db_path.stat().st_size} 字节')
        
        # 关闭连接
        conn.close()
        
        return True
        
    except Exception as e:
        print(f'❌ 数据库创建失败: {e}')
        return False

if __name__ == '__main__':
    print('=' * 60)
    print('🎯 电子会计档案管理系统 - 数据库初始化')
    print('=' * 60)
    
    if create_database():
        print('✅ 数据库初始化完成')
    else:
        print('❌ 数据库初始化失败')