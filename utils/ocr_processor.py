"""
OCR处理工具 - 文本提取、图像处理
基于DA/T 94-2022标准的OCR处理要求
"""
import os
import logging
from PIL import Image, ImageEnhance
import pytesseract
from pdf2image import convert_from_path
import cv2
import numpy as np
from scipy import ndimage
import re
from datetime import datetime

logger = logging.getLogger(__name__)

class OCRProcessor:
    """OCR处理工具类"""
    
    def __init__(self):
        self.supported_image_formats = ['.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.tif']
        self.supported_pdf_formats = ['.pdf']
        
        # OCR配置
        self.ocr_configs = {
            'chinese': '--oem 3 --psm 6 -l chi_sim',
            'english': '--oem 3 --psm 6 -l eng',
            'mixed': '--oem 3 --psm 6 -l chi_sim+eng'
        }
    
    def extract_text(self, file_path, language='mixed', preprocessing=True):
        """
        从文件中提取文本
        
        Args:
            file_path: 文件路径
            language: OCR语言 (chinese, english, mixed)
            preprocessing: 是否进行图像预处理
            
        Returns:
            tuple: (提取的文本, 置信度)
        """
        try:
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext in self.supported_image_formats:
                return self._extract_from_image(file_path, language, preprocessing)
            elif file_ext in self.supported_pdf_formats:
                return self._extract_from_pdf(file_path, language, preprocessing)
            else:
                return '', 0.0
                
        except Exception as e:
            logger.error(f"文本提取失败: {str(e)}")
            return '', 0.0
    
    def _extract_from_image(self, image_path, language, preprocessing):
        """
        从图像文件提取文本
        
        Args:
            image_path: 图像文件路径
            language: OCR语言
            preprocessing: 是否预处理
            
        Returns:
            tuple: (文本, 置信度)
        """
        try:
            # 读取图像
            image = Image.open(image_path)
            
            # 图像预处理
            if preprocessing:
                processed_image = self._preprocess_image(image)
            else:
                processed_image = image
            
            # 执行OCR
            ocr_config = self.ocr_configs.get(language, self.ocr_configs['mixed'])
            
            # 获取文本和置信度
            text = pytesseract.image_to_string(processed_image, config=ocr_config)
            confidence = self._get_ocr_confidence(processed_image, ocr_config)
            
            # 清理文本
            cleaned_text = self._clean_ocr_text(text)
            
            return cleaned_text, confidence
            
        except Exception as e:
            logger.error(f"图像OCR失败: {str(e)}")
            return '', 0.0
    
    def _extract_from_pdf(self, pdf_path, language, preprocessing):
        """
        从PDF文件提取文本
        
        Args:
            pdf_path: PDF文件路径
            language: OCR语言
            preprocessing: 是否预处理
            
        Returns:
            tuple: (文本, 置信度)
        """
        try:
            # 将PDF转换为图像
            images = convert_from_path(pdf_path, dpi=300)
            
            all_text = []
            total_confidence = 0
            processed_pages = 0
            
            for i, image in enumerate(images):
                try:
                    # 图像预处理
                    if preprocessing:
                        processed_image = self._preprocess_image(image)
                    else:
                        processed_image = image
                    
                    # 执行OCR
                    ocr_config = self.ocr_configs.get(language, self.ocr_configs['mixed'])
                    text = pytesseract.image_to_string(processed_image, config=ocr_config)
                    confidence = self._get_ocr_confidence(processed_image, ocr_config)
                    
                    # 清理文本
                    cleaned_text = self._clean_ocr_text(text)
                    all_text.append(f"[第{i+1}页]\n{cleaned_text}")
                    
                    if confidence > 0:
                        total_confidence += confidence
                        processed_pages += 1
                    
                except Exception as e:
                    logger.error(f"PDF第{i+1}页OCR失败: {str(e)}")
                    continue
            
            # 计算平均置信度
            avg_confidence = total_confidence / processed_pages if processed_pages > 0 else 0.0
            
            return '\n'.join(all_text), avg_confidence
            
        except Exception as e:
            logger.error(f"PDF OCR失败: {str(e)}")
            return '', 0.0
    
    def _preprocess_image(self, image):
        """
        图像预处理
        
        Args:
            image: PIL图像对象
            
        Returns:
            PIL.Image: 处理后的图像
        """
        try:
            # 转换为灰度图
            if image.mode != 'L':
                image = image.convert('L')
            
            # 转换为numpy数组
            img_array = np.array(image)
            
            # 去噪
            img_array = cv2.medianBlur(img_array, 3)
            
            # 二值化
            _, img_array = cv2.threshold(img_array, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            
            # 转换为PIL图像
            processed_image = Image.fromarray(img_array)
            
            # 增强对比度
            enhancer = ImageEnhance.Contrast(processed_image)
            processed_image = enhancer.enhance(1.2)
            
            return processed_image
            
        except Exception as e:
            logger.error(f"图像预处理失败: {str(e)}")
            return image
    
    def _get_ocr_confidence(self, image, config):
        """
        获取OCR置信度
        
        Args:
            image: PIL图像对象
            config: OCR配置
            
        Returns:
            float: 置信度 (0-100)
        """
        try:
            # 使用pytesseract获取置信度数据
            data = pytesseract.image_to_data(image, config=config, output_type=pytesseract.Output.DICT)
            
            # 计算平均置信度
            confidences = [int(conf) for conf in data['conf'] if int(conf) > 0]
            
            if confidences:
                avg_confidence = sum(confidences) / len(confidences)
                return avg_confidence
            else:
                return 0.0
                
        except Exception as e:
            logger.error(f"获取OCR置信度失败: {str(e)}")
            return 0.0
    
    def _clean_ocr_text(self, text):
        """
        清理OCR文本
        
        Args:
            text: 原始OCR文本
            
        Returns:
            str: 清理后的文本
        """
        try:
            # 移除多余的空白字符
            text = re.sub(r'\s+', ' ', text)
            
            # 移除行首行尾空白
            text = text.strip()
            
            # 修复常见的OCR错误
            replacements = {
                '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
                '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
                '，': ',', '。': '.', '：': ':', '；': ';', '（': '(', '）': ')',
                '【': '[', '】': ']', '《': '<', '》': '>'
            }
            
            for old, new in replacements.items():
                text = text.replace(old, new)
            
            # 移除过短的行
            lines = text.split('\n')
            cleaned_lines = [line for line in lines if len(line.strip()) > 2]
            
            return '\n'.join(cleaned_lines)
            
        except Exception as e:
            logger.error(f"文本清理失败: {str(e)}")
            return text
    
    def extract_key_fields(self, text):
        """
        提取关键字段（如日期、金额、编号等）
        
        Args:
            text: OCR文本
            
        Returns:
            dict: 提取的关键字段
        """
        try:
            extracted_fields = {}
            
            # 提取日期
            date_patterns = [
                r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})',
                r'(\d{4}年\d{1,2}月\d{1,2}日)',
                r'(\d{1,2}[-/]\d{1,2}[-/]\d{4})'
            ]
            
            for pattern in date_patterns:
                matches = re.findall(pattern, text)
                if matches:
                    extracted_fields['dates'] = matches
                    break
            
            # 提取金额
            amount_pattern = r'([￥¥]?\s*[\d,]+\.?\d{0,2})'
            amounts = re.findall(amount_pattern, text)
            if amounts:
                extracted_fields['amounts'] = amounts
            
            # 提取编号
            id_pattern = r'([A-Z0-9]{8,20})'
            ids = re.findall(id_pattern, text)
            if ids:
                extracted_fields['ids'] = ids
            
            # 提取手机号
            phone_pattern = r'(1[3-9]\d{9})'
            phones = re.findall(phone_pattern, text)
            if phones:
                extracted_fields['phones'] = phones
            
            # 提取邮箱
            email_pattern = r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
            emails = re.findall(email_pattern, text)
            if emails:
                extracted_fields['emails'] = emails
            
            return extracted_fields
            
        except Exception as e:
            logger.error(f"提取关键字段失败: {str(e)}")
            return {}
    
    def enhance_image_quality(self, image_path, output_path):
        """
        增强图像质量
        
        Args:
            image_path: 输入图像路径
            output_path: 输出图像路径
            
        Returns:
            bool: 是否成功
        """
        try:
            # 读取图像
            image = Image.open(image_path)
            
            # 转换为灰度图
            if image.mode != 'L':
                image = image.convert('L')
            
            # 转换到numpy数组
            img_array = np.array(image)
            
            # 高斯去噪
            img_array = cv2.GaussianBlur(img_array, (5, 5), 0)
            
            # 自适应阈值
            img_array = cv2.adaptiveThreshold(
                img_array, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
            )
            
            # 形态学操作去除噪声
            kernel = np.ones((1, 1), np.uint8)
            img_array = cv2.morphologyEx(img_array, cv2.MORPH_CLOSE, kernel)
            
            # 转换回PIL图像
            enhanced_image = Image.fromarray(img_array)
            
            # 保存增强后的图像
            enhanced_image.save(output_path, 'PNG', optimize=True)
            
            return True
            
        except Exception as e:
            logger.error(f"图像增强失败: {str(e)}")
            return False