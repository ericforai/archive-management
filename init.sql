-- 电子会计档案管理系统数据库初始化脚本

-- 创建数据库扩展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- 创建枚举类型
CREATE TYPE user_role AS ENUM ('admin', 'archivist', 'accountant', 'auditor', 'user');
CREATE TYPE retention_period AS ENUM ('permanent', '30_years', '10_years', '5_years', '3_years');
CREATE TYPE archive_status AS ENUM ('draft', 'archived', 'disposed', 'transferred');
CREATE TYPE operation_type AS ENUM ('create', 'view', 'download', 'print', 'modify', 'delete', 'transfer', 'dispose');

-- 创建用户表
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role user_role NOT NULL DEFAULT 'user',
    department VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建组织机构表
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(200) NOT NULL,
    code VARCHAR(50) UNIQUE NOT NULL,
    parent_id UUID REFERENCES organizations(id),
    level INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建档案分类表
CREATE TABLE archive_categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    parent_id UUID REFERENCES archive_categories(id),
    level INTEGER NOT NULL DEFAULT 1,
    retention_period retention_period NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建电子档案主表
CREATE TABLE electronic_archives (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    archive_no VARCHAR(100) UNIQUE NOT NULL,  -- 档号
    title VARCHAR(500) NOT NULL,  -- 题名
    category_id UUID NOT NULL REFERENCES archive_categories(id),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    created_by UUID NOT NULL REFERENCES users(id),
    file_count INTEGER DEFAULT 0,
    total_size BIGINT DEFAULT 0,  -- 字节
    retention_period retention_period NOT NULL,
    status archive_status DEFAULT 'draft',
    created_date DATE NOT NULL,
    archive_date DATE,  -- 归档日期
    disposal_date DATE,  -- 处置日期
    description TEXT,
    keywords TEXT,  -- 关键词，用逗号分隔
    confidentiality_level INTEGER DEFAULT 1,  -- 密级 1-公开 2-内部 3-秘密 4-机密 5-绝密
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建档案文件表
CREATE TABLE archive_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    archive_id UUID NOT NULL REFERENCES electronic_archives(id) ON DELETE CASCADE,
    file_name VARCHAR(500) NOT NULL,
    original_name VARCHAR(500) NOT NULL,
    file_path VARCHAR(1000) NOT NULL,
    file_type VARCHAR(50) NOT NULL,  -- 文件类型：pdf, doc, xls, jpg等
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64) NOT NULL,  -- SHA256哈希值
    mime_type VARCHAR(100),
    sort_order INTEGER DEFAULT 0,
    is_main BOOLEAN DEFAULT FALSE,  -- 是否为主文件
    ocr_text TEXT,  -- OCR识别文本
    metadata JSONB,  -- 元数据
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建元数据表
CREATE TABLE archive_metadata (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    archive_id UUID NOT NULL REFERENCES electronic_archives(id) ON DELETE CASCADE,
    metadata_key VARCHAR(100) NOT NULL,
    metadata_value TEXT,
    metadata_type VARCHAR(50) DEFAULT 'text',  -- text, number, date, boolean
    is_indexed BOOLEAN DEFAULT FALSE,  -- 是否建立索引
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(archive_id, metadata_key)
);

-- 创建审计日志表
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id),
    operation_type operation_type NOT NULL,
    resource_type VARCHAR(50) NOT NULL,  -- archive, file, metadata等
    resource_id UUID NOT NULL,
    operation_details JSONB,
    ip_address INET,
    user_agent TEXT,
    result VARCHAR(20) DEFAULT 'success',  -- success, failure
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建权限表
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id),
    resource_type VARCHAR(50) NOT NULL,  -- archive, category等
    resource_id UUID,  -- 具体的资源ID，NULL表示对所有此类资源
    operation VARCHAR(20) NOT NULL,  -- read, write, delete, admin
    granted_by UUID NOT NULL REFERENCES users(id),
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    UNIQUE(user_id, resource_type, resource_id, operation)
);

-- 创建生命周期记录表
CREATE TABLE lifecycle_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    archive_id UUID NOT NULL REFERENCES electronic_archives(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,  -- created, archived, transferred, disposed, migrated
    event_date DATE NOT NULL,
    description TEXT,
    operator_id UUID NOT NULL REFERENCES users(id),
    metadata JSONB,  -- 事件相关的元数据
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建固化记录表（区块链存证）
CREATE TABLE integrity_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    archive_id UUID NOT NULL REFERENCES electronic_archives(id),
    file_id UUID REFERENCES archive_files(id),
    operation_type VARCHAR(50) NOT NULL,  -- created, modified, archived
    hash_value VARCHAR(64) NOT NULL,
    digital_signature TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verification_status VARCHAR(20) DEFAULT 'verified',  -- verified, failed, pending
    verification_details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建存储介质管理表
CREATE TABLE storage_media (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(200) NOT NULL,
    type VARCHAR(50) NOT NULL,  -- disk, tape, cloud等
    location VARCHAR(200),
    capacity BIGINT NOT NULL,  -- 总容量（字节）
    used_space BIGINT DEFAULT 0,  -- 已使用空间
    status VARCHAR(20) DEFAULT 'active',  -- active, inactive, damaged
    health_status VARCHAR(20) DEFAULT 'good',  -- good, warning, error
    last_check_date DATE,
    next_check_date DATE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建索引
CREATE INDEX idx_electronic_archives_archive_no ON electronic_archives(archive_no);
CREATE INDEX idx_electronic_archives_category ON electronic_archives(category_id);
CREATE INDEX idx_electronic_archives_created_date ON electronic_archives(created_date);
CREATE INDEX idx_electronic_archives_status ON electronic_archives(status);
CREATE INDEX idx_archive_files_archive_id ON archive_files(archive_id);
CREATE INDEX idx_archive_files_hash ON archive_files(file_hash);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_metadata_archive_id ON archive_metadata(archive_id);
CREATE INDEX idx_metadata_key ON archive_metadata(metadata_key);
CREATE INDEX idx_integrity_records_archive ON integrity_records(archive_id);

-- 创建全文搜索索引
CREATE INDEX idx_archive_fulltext ON electronic_archives USING gin(to_tsvector('chinese', title || ' ' || COALESCE(description, '') || ' ' || COALESCE(keywords, '')));
CREATE INDEX idx_file_ocr_text ON archive_files USING gin(to_tsvector('chinese', COALESCE(ocr_text, '')));

-- 插入基础数据

-- 创建默认管理员用户
INSERT INTO users (username, email, password_hash, full_name, role, department) VALUES 
('admin', 'admin@archive.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeKhJ7hL8X8X3H8mW', '系统管理员', 'admin', '信息技术部');

-- 创建基础分类
INSERT INTO archive_categories (code, name, retention_period, description) VALUES 
('01', '会计凭证', '30_years', '原始凭证、记账凭证等'),
('02', '会计账簿', '30_years', '总账、明细账、日记账等'),
('03', '财务报告', 'permanent', '资产负债表、利润表、现金流量表等'),
('04', '其他会计资料', '10_years', '其他会计资料'),
('05', '税务资料', '10_years', '纳税申报表、税务登记证等');

-- 创建默认组织
INSERT INTO organizations (name, code, level) VALUES 
('总部', 'HQ', 1);

-- 创建默认存储介质
INSERT INTO storage_media (name, type, location, capacity, status) VALUES 
('主存储阵列', 'disk', '数据中心A区', 1073741824000, 'active'),  -- 1TB
('备份存储', 'disk', '数据中心B区', 2147483648000, 'active'),   -- 2TB
('云存储', 'cloud', '阿里云OSS', 10995116277760, 'active');     -- 10TB