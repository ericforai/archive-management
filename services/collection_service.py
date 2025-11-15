"""
电子档案采集中心服务 - 实现OCR/自动解析功能
基于DA/T 94-2022附录E要求的采集中心模块
"""
import os
import uuid
import hashlib
import mimetypes
from datetime import datetime, date
from flask import current_app
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from models.archive import ElectronicArchive, ArchiveFile, ArchiveMetadata
from models.user import User
from models.audit import AuditLog, IntegrityRecord
from models import db
from utils.audit_logger import AuditLogger
from utils.integrity_checker import IntegrityChecker
from utils.file_processor import FileProcessor
from utils.ocr_processor import OCRProcessor

class ArchiveCollectionService:
    """电子档案采集中心服务"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.integrity_checker = IntegrityChecker()
        self.file_processor = FileProcessor()
        self.ocr_processor = OCRProcessor()
    
    def collect_archive_from_system(self, system_data, user_id):
        """
        从业务系统接收电子会计资料
        
        Args:
            system_data: 来自业务系统的数据包，包含元数据和文件
            user_id: 操作用户ID
            
        Returns:
            dict: 采集结果
        """
        try:
            # 1. 验证数据包
            validation_result = self._validate_incoming_data(system_data)
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error': f'数据包验证失败: {validation_result["message"]}',
                    'error_code': 'VALIDATION_FAILED'
                }
            
            # 2. 重复识别检测
            duplicate_check = self._check_for_duplicates(system_data)
            if duplicate_check['is_duplicate']:
                return {
                    'success': False,
                    'error': f'检测到重复档案: {duplicate_check["existing_archive_id"]}',
                    'error_code': 'DUPLICATE_DETECTED',
                    'warning': '已存在相同档案，建议检查是否重复归档'
                }
            
            # 3. 格式转换
            converted_files = self._convert_file_formats(system_data.get('files', []))
            
            # 4. 创建电子档案记录
            archive = self._create_archive_record(system_data, user_id)
            
            # 5. 保存文件
            saved_files = self._save_files(archive.id, converted_files, system_data.get('files', []))
            
            # 6. 处理元数据
            metadata = self._process_metadata(archive.id, system_data.get('metadata', {}))
            
            # 7. OCR处理
            ocr_results = self._perform_ocr(saved_files)
            
            # 8. 创建完整性记录
            integrity_records = self._create_integrity_records(archive, saved_files)
            
            # 9. 记录审计日志
            self.audit_logger.log_operation(
                user_id=user_id,
                operation_type='create',
                resource_type='archive',
                resource_id=archive.id,
                operation_details={
                    'archive_no': archive.archive_no,
                    'title': archive.title,
                    'file_count': len(saved_files),
                    'total_size': sum(f.file_size for f in saved_files)
                }
            )
            
            db.session.commit()
            
            return {
                'success': True,
                'archive_id': archive.id,
                'archive_no': archive.archive_no,
                'files_saved': len(saved_files),
                'ocr_results': ocr_results,
                'integrity_records': len(integrity_records),
                'message': '电子档案采集成功'
            }
            
        except Exception as e:
            db.session.rollback()
            return {
                'success': False,
                'error': f'采集过程发生错误: {str(e)}',
                'error_code': 'COLLECTION_ERROR'
            }
    
    def _validate_incoming_data(self, system_data):
        """验证输入数据"""
        required_fields = ['title', 'category_id', 'created_date', 'files']
        
        for field in required_fields:
            if field not in system_data:
                return {'valid': False, 'message': f'缺少必需字段: {field}'}
        
        if not system_data['files']:
            return {'valid': False, 'message': '缺少文件数据'}
        
        # 验证文件
        for file_info in system_data['files']:
            if 'content' not in file_info:
                return {'valid': False, 'message': '文件缺少内容数据'}
        
        return {'valid': True, 'message': '数据验证通过'}
    
    def _check_for_duplicates(self, system_data):
        """检查重复档案"""
        # 基于文件哈希值检查
        for file_info in system_data.get('files', []):
            if 'content' in file_info:
                file_hash = hashlib.sha256(file_info['content']).hexdigest()
                
                existing_file = ArchiveFile.query.filter_by(file_hash=file_hash).first()
                if existing_file:
                    return {
                        'is_duplicate': True,
                        'existing_archive_id': existing_file.archive_id,
                        'existing_file_id': existing_file.id
                    }
        
        return {'is_duplicate': False}
    
    def _convert_file_formats(self, files):
        """转换文件格式为长期保存格式"""
        converted_files = []
        
        for file_info in files:
            if 'content' in file_info:
                content = file_info['content']
                original_format = file_info.get('file_type', 'unknown')
                
                # 转换逻辑
                if original_format.lower() in ['doc', 'docx']:
                    # 转换为PDF/A
                    converted_content = self.file_processor.convert_to_pdfa(content)
                    file_info['converted_content'] = converted_content
                    file_info['converted_format'] = 'pdf'
                elif original_format.lower() in ['xls', 'xlsx']:
                    # 转换为PDF/A或保持原始格式
                    converted_content = self.file_processor.convert_to_pdfa(content)
                    file_info['converted_content'] = converted_content
                    file_info['converted_format'] = 'pdf'
                else:
                    # 其他格式保持不变
                    file_info['converted_content'] = content
                    file_info['converted_format'] = original_format
                
                converted_files.append(file_info)
        
        return converted_files
    
    def _create_archive_record(self, system_data, user_id):
        """创建档案记录"""
        # 生成唯一编号
        archive_no = self._generate_archive_no(system_data.get('category_id'))
        
        archive = ElectronicArchive(
            archive_no=archive_no,
            title=system_data['title'],
            category_id=system_data['category_id'],
            organization_id=system_data.get('organization_id'),
            created_by=user_id,
            created_date=datetime.strptime(system_data['created_date'], '%Y-%m-%d').date(),
            description=system_data.get('description'),
            keywords=system_data.get('keywords'),
            retention_period=system_data.get('retention_period', '10_years'),
            confidentiality_level=system_data.get('confidentiality_level', 1)
        )
        
        db.session.add(archive)
        db.session.flush()  # 获取ID但不提交
        
        return archive
    
    def _generate_archive_no(self, category_id):
        """生成唯一档案编号"""
        from models.archive import ArchiveCategory
        
        # 获取分类信息
        category = ArchiveCategory.query.get(category_id)
        if not category:
            category_code = 'UNKNOWN'
        else:
            category_code = category.code
        
        # 生成编号格式：分类代码 + 年份 + 流水号
        year = datetime.now().year
        prefix = f"{category_code}{year}"
        
        # 查找同类型的最大流水号
        existing_archives = ElectronicArchive.query.filter(
            ElectronicArchive.archive_no.like(f"{prefix}%")
        ).order_by(ElectronicArchive.archive_no.desc()).first()
        
        if existing_archives:
            # 提取流水号
            try:
                last_sequence = int(existing_archives.archive_no[-4:])
                sequence = last_sequence + 1
            except ValueError:
                sequence = 1
        else:
            sequence = 1
        
        return f"{prefix}{sequence:04d}"
    
    def _save_files(self, archive_id, converted_files, original_files):
        """保存文件到存储"""
        saved_files = []
        
        for i, (converted_file, original_file) in enumerate(zip(converted_files, original_files)):
            # 生成文件路径
            file_uuid = str(uuid.uuid4())
            file_extension = converted_file.get('converted_format', 'bin')
            file_name = f"{file_uuid}.{file_extension}"
            file_path = os.path.join(current_app.config['ARCHIVE_STORAGE'], file_name)
            
            # 确保目录存在
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # 保存文件
            with open(file_path, 'wb') as f:
                f.write(converted_file['converted_content'])
            
            # 计算文件哈希
            file_hash = hashlib.sha256(converted_file['converted_content']).hexdigest()
            
            # 获取MIME类型
            mime_type, _ = mimetypes.guess_type(file_name)
            
            # 创建文件记录
            archive_file = ArchiveFile(
                archive_id=archive_id,
                file_name=file_name,
                original_name=original_file.get('file_name', f'file_{i}'),
                file_path=file_path,
                file_type=converted_file.get('converted_format', 'bin'),
                file_size=len(converted_file['converted_content']),
                file_hash=file_hash,
                mime_type=mime_type,
                sort_order=i,
                is_main=(i == 0),  # 第一个文件为主文件
                original_format=original_file.get('file_type', 'unknown')
            )
            
            db.session.add(archive_file)
            saved_files.append(archive_file)
        
        # 更新档案文件数量和总大小
        archive = ElectronicArchive.query.get(archive_id)
        archive.file_count = len(saved_files)
        archive.total_size = sum(f.file_size for f in saved_files)
        
        return saved_files
    
    def _process_metadata(self, archive_id, metadata_dict):
        """处理元数据"""
        metadata_records = []
        
        for key, value in metadata_dict.items():
            metadata = ArchiveMetadata(
                archive_id=archive_id,
                metadata_key=key,
                metadata_value=str(value),
                metadata_type=self._determine_metadata_type(value),
                is_indexed=True
            )
            db.session.add(metadata)
            metadata_records.append(metadata)
        
        return metadata_records
    
    def _determine_metadata_type(self, value):
        """确定元数据类型"""
        if isinstance(value, bool):
            return 'boolean'
        elif isinstance(value, (int, float)):
            return 'number'
        elif isinstance(value, date):
            return 'date'
        else:
            return 'text'
    
    def _perform_ocr(self, saved_files):
        """执行OCR处理"""
        ocr_results = []
        
        for file in saved_files:
            if file.needs_ocr():
                try:
                    # 执行OCR
                    ocr_text, confidence = self.ocr_processor.extract_text(file.file_path)
                    
                    # 更新文件记录
                    file.ocr_text = ocr_text
                    file.ocr_confidence = confidence
                    file.ocr_processed_at = datetime.utcnow()
                    
                    ocr_results.append({
                        'file_id': file.id,
                        'file_name': file.original_name,
                        'ocr_text_length': len(ocr_text),
                        'confidence': confidence
                    })
                    
                except Exception as e:
                    ocr_results.append({
                        'file_id': file.id,
                        'file_name': file.original_name,
                        'error': str(e),
                        'confidence': 0
                    })
        
        return ocr_results
    
    def _create_integrity_records(self, archive, files):
        """创建完整性记录"""
        integrity_records = []
        
        # 为档案创建完整性记录
        archive_integrity = IntegrityRecord(
            archive_id=archive.id,
            operation_type='created',
            hash_value=archive.integrity_hash or hashlib.sha256(f"{archive.id}{archive.created_at}".encode()).hexdigest(),
            timestamp=datetime.utcnow()
        )
        db.session.add(archive_integrity)
        integrity_records.append(archive_integrity)
        
        # 为每个文件创建完整性记录
        for file in files:
            file_integrity = IntegrityRecord(
                file_id=file.id,
                operation_type='created',
                hash_value=file.file_hash,
                timestamp=datetime.utcnow()
            )
            db.session.add(file_integrity)
            integrity_records.append(file_integrity)
        
        return integrity_records