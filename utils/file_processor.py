"""
文件处理工具 - 格式转换、压缩、加密等
"""
import os
import hashlib
import tempfile
import subprocess
from PIL import Image
from PyPDF2 import PdfReader, PdfWriter
import pypandoc
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)

class FileProcessor:
    """文件处理工具类"""
    
    def __init__(self):
        self.supported_conversions = {
            'doc': ['pdf', 'txt'],
            'docx': ['pdf', 'txt'],
            'xls': ['pdf', 'csv'],
            'xlsx': ['pdf', 'csv'],
            'ppt': ['pdf'],
            'pptx': ['pdf'],
            'jpg': ['pdf'],
            'jpeg': ['pdf'],
            'png': ['pdf'],
            'bmp': ['pdf'],
            'tiff': ['pdf'],
            'txt': ['pdf']
        }
    
    def convert_to_pdfa(self, file_content, source_format=None):
        """
        将文件转换为PDF/A格式（长期保存标准）
        
        Args:
            file_content: 文件二进制内容
            source_format: 源文件格式
            
        Returns:
            bytes: PDF/A格式的文件内容
        """
        try:
            with tempfile.NamedTemporaryFile(mode='wb', suffix=f'.{source_format or "tmp"}') as temp_input:
                temp_input.write(file_content)
                temp_input.flush()
                
                # 使用pypandoc进行转换
                output = pypandoc.convert_file(
                    temp_input.name,
                    'pdf',
                    outputfile=temp_input.name + '.pdf',
                    extra_args=['--pdf-engine=xelatex']
                )
                
                # 读取转换后的内容
                with open(temp_input.name + '.pdf', 'rb') as f:
                    pdf_content = f.read()
                
                # 转换为PDF/A格式
                pdfa_content = self._convert_to_pdfa_standard(pdf_content)
                
                return pdfa_content
                
        except Exception as e:
            logger.error(f"转换为PDF/A失败: {str(e)}")
            # 如果转换失败，返回原始内容
            return file_content
    
    def _convert_to_pdfa_standard(self, pdf_content):
        """转换为PDF/A标准"""
        try:
            # 创建临时文件处理PDF
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf') as temp_pdf:
                temp_pdf.write(pdf_content)
                temp_pdf.flush()
                
                # 使用PyPDF2添加PDF/A标记
                reader = PdfReader(temp_pdf.name)
                writer = PdfWriter()
                
                # 复制所有页面
                for page in reader.pages:
                    writer.add_page(page)
                
                # 添加PDF/A元数据
                writer.add_metadata({
                    '/Title': '电子档案',
                    '/Creator': '电子会计档案管理系统',
                    '/Producer': '电子会计档案管理系统',
                    '/CreationDate': f"D:{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    '/ModDate': f"D:{datetime.now().strftime('%Y%m%d%H%M%S')}"
                })
                
                # 输出到新的PDF
                with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf') as output_pdf:
                    writer.write(output_pdf)
                    output_pdf.flush()
                    
                    # 读取转换后的内容
                    with open(output_pdf.name, 'rb') as f:
                        return f.read()
                        
        except Exception as e:
            logger.error(f"PDF/A标准转换失败: {str(e)}")
            return pdf_content
    
    def compress_file(self, file_content, compression_level=6):
        """
        压缩文件内容
        
        Args:
            file_content: 原始文件内容
            compression_level: 压缩级别 (1-9)
            
        Returns:
            bytes: 压缩后的文件内容
        """
        import zlib
        
        try:
            compressed = zlib.compress(file_content, level=compression_level)
            return compressed
        except Exception as e:
            logger.error(f"文件压缩失败: {str(e)}")
            return file_content
    
    def decompress_file(self, compressed_content):
        """
        解压文件内容
        
        Args:
            compressed_content: 压缩后的文件内容
            
        Returns:
            bytes: 解压后的文件内容
        """
        import zlib
        
        try:
            decompressed = zlib.decompress(compressed_content)
            return decompressed
        except Exception as e:
            logger.error(f"文件解压失败: {str(e)}")
            return compressed_content
    
    def encrypt_file(self, file_content, password=None):
        """
        加密文件内容
        
        Args:
            file_content: 原始文件内容
            password: 加密密码（可选）
            
        Returns:
            dict: 包含加密内容和密钥的字典
        """
        try:
            # 生成密钥
            if password:
                # 基于密码生成密钥
                key = hashlib.sha256(password.encode()).digest()[:32]
                key = key.ljust(32, b'0')[:32]
            else:
                # 生成随机密钥
                key = Fernet.generate_key()
            
            # 创建加密器
            fernet = Fernet(key)
            
            # 加密内容
            encrypted_content = fernet.encrypt(file_content)
            
            return {
                'encrypted_content': encrypted_content,
                'encryption_key': key.decode() if isinstance(key, bytes) else key,
                'algorithm': 'Fernet'
            }
            
        except Exception as e:
            logger.error(f"文件加密失败: {str(e)}")
            return {
                'encrypted_content': file_content,
                'encryption_key': None,
                'algorithm': None,
                'error': str(e)
            }
    
    def decrypt_file(self, encrypted_content, encryption_key):
        """
        解密文件内容
        
        Args:
            encrypted_content: 加密后的文件内容
            encryption_key: 解密密钥
            
        Returns:
            bytes: 解密后的文件内容
        """
        try:
            # 确保密钥是字节类型
            if isinstance(encryption_key, str):
                encryption_key = encryption_key.encode()
            
            # 创建解密器
            fernet = Fernet(encryption_key)
            
            # 解密内容
            decrypted_content = fernet.decrypt(encrypted_content)
            
            return decrypted_content
            
        except Exception as e:
            logger.error(f"文件解密失败: {str(e)}")
            return encrypted_content
    
    def calculate_file_hash(self, file_content, algorithm='sha256'):
        """
        计算文件哈希值
        
        Args:
            file_content: 文件内容
            algorithm: 哈希算法 (md5, sha1, sha256, sha512)
            
        Returns:
            str: 哈希值
        """
        try:
            if algorithm == 'md5':
                return hashlib.md5(file_content).hexdigest()
            elif algorithm == 'sha1':
                return hashlib.sha1(file_content).hexdigest()
            elif algorithm == 'sha256':
                return hashlib.sha256(file_content).hexdigest()
            elif algorithm == 'sha512':
                return hashlib.sha512(file_content).hexdigest()
            else:
                return hashlib.sha256(file_content).hexdigest()
                
        except Exception as e:
            logger.error(f"计算文件哈希失败: {str(e)}")
            return None
    
    def get_file_info(self, file_content, file_name=None):
        """
        获取文件信息
        
        Args:
            file_content: 文件内容
            file_name: 文件名（可选）
            
        Returns:
            dict: 文件信息
        """
        try:
            info = {
                'size': len(file_content),
                'hash_sha256': self.calculate_file_hash(file_content, 'sha256'),
                'hash_md5': self.calculate_file_hash(file_content, 'md5'),
                'mime_type': None,
                'format': None
            }
            
            # 获取MIME类型
            if file_name:
                info['mime_type'], _ = mimetypes.guess_type(file_name)
                info['format'] = file_name.split('.')[-1].lower() if '.' in file_name else 'unknown'
            
            return info
            
        except Exception as e:
            logger.error(f"获取文件信息失败: {str(e)}")
            return {
                'size': len(file_content),
                'error': str(e)
            }