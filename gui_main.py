import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                             QTextEdit, QProgressBar, QRadioButton, QButtonGroup,
                             QGroupBox, QTableWidget, QTableWidgetItem, QTabWidget,
                             QHeaderView, QMessageBox, QSplitter)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QColor, QPalette

# Import các module backend
from scanner import hash_scanner, pe_analyzer
from api import virustotal_api
from database.db_manager import DatabaseManager


class ScanThread(QThread):
    """
    Thread riêng để quét file, tránh đơ giao diện
    """
    # Signals để giao tiếp với GUI
    progress_update = pyqtSignal(int, str)  # (progress_value, status_message)
    scan_complete = pyqtSignal(dict)  # Gửi kết quả scan
    error_occurred = pyqtSignal(str)  # Gửi thông báo lỗi
    
    def __init__(self, filepath, scan_mode, db_handler):
        super().__init__()
        self.filepath = filepath
        self.scan_mode = scan_mode
        self.db_handler = db_handler
        
    def run(self):
        """Hàm chạy khi thread được start()"""
        try:
            report = {
                "filepath": self.filepath,
                "filename": os.path.basename(self.filepath),
                "is_safe": True,
                "detections": {}
            }
            
            # 1. HASH CALCULATION (20%)
            self.progress_update.emit(10, "Đang tính toán Hash...")
            hashes = hash_scanner.get_file_hashes(self.filepath)
            
            if hashes['status'] != 'success':
                self.error_occurred.emit(f"Lỗi tính Hash: {hashes['message']}")
                return
            
            report['detections']['hash'] = hashes
            self.progress_update.emit(20, "Hash tính toán hoàn tất")
            
            # 2. LOCAL DATABASE CHECK (40%)
            self.progress_update.emit(30, "Đang tra cứu Database cục bộ...")
            local_detection = self.db_handler.search_signature(hashes['md5'])
            
            if local_detection:
                report['is_safe'] = False
                report['detections']['local_db'] = {
                    "detected": True, 
                    "malware_name": local_detection
                }
                self.progress_update.emit(40, f"⚠️ Phát hiện: {local_detection}")
            else:
                report['detections']['local_db'] = {"detected": False}
                self.progress_update.emit(40, "Database cục bộ: Sạch")
            
            # 3. VIRUSTOTAL CHECK (60%)
            self.progress_update.emit(50, "Đang tra cứu VirusTotal...")
            vt_report = virustotal_api.get_vt_report(hashes['sha256'])
            report['detections']['virustotal'] = vt_report
            
            if vt_report['status'] == 'success':
                if vt_report['verdict'] == 'MALICIOUS':
                    report['is_safe'] = False
                    self.progress_update.emit(60, f"⚠️ VT: {vt_report['detected_by']}/{vt_report['total_scanners']} phát hiện")
                else:
                    self.progress_update.emit(60, "VirusTotal: Sạch")
            else:
                self.progress_update.emit(60, f"VirusTotal: {vt_report.get('message', 'Lỗi')}")
            
            # 4. PE ANALYSIS (Deep Scan only) (80%)
            if self.scan_mode == 'deep':
                self.progress_update.emit(70, "Đang phân tích PE Header...")
                pe_info = pe_analyzer.analyze_pe_header(self.filepath)
                report['detections']['pe_analysis'] = pe_info
                self.progress_update.emit(80, "Phân tích PE hoàn tất")
            else:
                self.progress_update.emit(80, "Bỏ qua phân tích PE (Quick Scan)")
            
            # 5. COMPLETE (100%)
            self.progress_update.emit(100, "Quét hoàn tất!")
            self.scan_complete.emit(report)
            
        except Exception as e:
            self.error_occurred.emit(f"Lỗi nghiêm trọng: {str(e)}")


class BatchScanThread(QThread):
    """
    Thread riêng để quét hàng loạt nhiều file trong thư mục (Quick Scan only)
    """
    # Signals
    progress_update = pyqtSignal(int, str, int, int)  # (progress%, message, current_file, total_files)
    file_scanned = pyqtSignal(dict)  # Gửi kết quả từng file
    batch_complete = pyqtSignal(dict)  # Gửi tổng kết
    error_occurred = pyqtSignal(str)
    
    def __init__(self, root_path, db_handler):
        super().__init__()
        self.root_path = root_path
        self.db_handler = db_handler
        self.is_running = True
        
    def stop(self):
        """Dừng quét"""
        self.is_running = False
    
    def run(self):
        """Quét toàn bộ thư mục bằng Quick Scan"""
        try:
            # Thu thập danh sách file
            self.progress_update.emit(0, "Đang thu thập danh sách file...", 0, 0)
            files_to_scan = []
            
            for root, dirs, files in os.walk(self.root_path):
                if not self.is_running:
                    break
                    
                for file in files:
                    if not self.is_running:
                        break
                    
                    file_path = os.path.join(root, file)
                    # Chỉ quét file thực thi (có thể mở rộng thêm)
                    _, ext = os.path.splitext(file)
                    if ext.lower() in ['.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.js']:
                        files_to_scan.append(file_path)
            
            if not self.is_running:
                return
            
            total_files = len(files_to_scan)
            if total_files == 0:
                self.error_occurred.emit("Không tìm thấy file nào để quét!")
                return
                
            self.progress_update.emit(5, f"Tìm thấy {total_files} file cần quét", 0, total_files)
            
            # Quét từng file bằng Quick Scan
            safe_files = []
            malicious_files = []
            
            for idx, filepath in enumerate(files_to_scan, 1):
                if not self.is_running:
                    break
                
                try:
                    # Quick scan: chỉ hash + DB cục bộ
                    result = self._quick_scan_file(filepath)
                    
                    if result['is_safe']:
                        safe_files.append(result)
                    else:
                        malicious_files.append(result)
                    
                    # Gửi signal cập nhật
                    self.file_scanned.emit(result)
                    
                    # Cập nhật progress
                    progress = int((idx / total_files) * 95) + 5
                    self.progress_update.emit(
                        progress,
                        f"Đang quét: {os.path.basename(filepath)}",
                        idx,
                        total_files
                    )
                    
                except Exception as e:
                    # Bỏ qua file lỗi, coi như an toàn
                    safe_files.append({
                        "filepath": filepath,
                        "filename": os.path.basename(filepath),
                        "is_safe": True,
                        "error": str(e)
                    })
                    continue
            
            # Hoàn thành
            summary = {
                "total_scanned": len(files_to_scan),
                "safe_files": safe_files,
                "malicious_files": malicious_files,
                "total_safe": len(safe_files),
                "total_malicious": len(malicious_files)
            }
            
            self.progress_update.emit(100, "Quét hoàn tất!", total_files, total_files)
            self.batch_complete.emit(summary)
            
        except Exception as e:
            self.error_occurred.emit(f"Lỗi batch scan: {str(e)}")
    
    def _quick_scan_file(self, filepath):
        """Quick scan một file (chỉ hash + DB cục bộ)"""
        result = {
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "is_safe": True,
            "threat_name": None,
            "detection_method": None
        }
        
        try:
            # Tính hash
            hashes = hash_scanner.get_file_hashes(filepath)
            if hashes['status'] != 'success':
                result['is_safe'] = True  # Bỏ qua file lỗi
                return result
            
            # Kiểm tra DB cục bộ
            local_detection = self.db_handler.search_signature(hashes['md5'])
            if local_detection:
                result['is_safe'] = False
                result['threat_name'] = local_detection
                result['detection_method'] = 'Local Database'
            
            result['md5'] = hashes['md5']
            result['sha256'] = hashes['sha256']
            
        except:
            pass
        
        return result


class PyMalScanGUI(QMainWindow):
    """
    Giao diện chính của PyMalScan-Lite
    """
    
    def __init__(self):
        super().__init__()
        
        # Khởi tạo Database
        self.db_handler = DatabaseManager()
        self.scan_thread = None
        self.batch_scan_thread = None
        self.current_report = None
        self.batch_results = None
        
        self.init_ui()
        
    def init_ui(self):
        """Khởi tạo giao diện"""
        
        self.setWindowTitle("PyMalScan-Lite - Malware Scanner v1.0")
        self.setGeometry(100, 100, 1200, 800)
        
        # Widget trung tâm
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout chính
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # ===== HEADER =====
        header = self._create_header()
        main_layout.addWidget(header)
        
        # ===== FILE SELECTION =====
        file_section = self._create_file_selection()
        main_layout.addWidget(file_section)
        
        # ===== SCAN OPTIONS =====
        options_section = self._create_scan_options()
        main_layout.addWidget(options_section)
        
        # ===== PROGRESS BAR =====
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Sẵn sàng quét...")
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)
        
        # ===== RESULTS SECTION =====
        results_section = self._create_results_section()
        main_layout.addWidget(results_section, stretch=1)
        
        # ===== CONTROL BUTTONS =====
        control_section = self._create_control_buttons()
        main_layout.addWidget(control_section)
        
        # Áp dụng stylesheet
        self._apply_stylesheet()
        
    def _create_header(self):
        """Tạo phần header"""
        header = QGroupBox()
        layout = QVBoxLayout()
        
        title = QLabel("🛡️ PyMalScan-Lite")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 24, QFont.Bold))
        
        subtitle = QLabel("Static Malware Analysis Tool | Python & PyQt5")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setFont(QFont("Arial", 10))
        subtitle.setStyleSheet("color: gray;")
        
        layout.addWidget(title)
        layout.addWidget(subtitle)
        header.setLayout(layout)
        
        return header
    
    def _create_file_selection(self):
        """Tạo phần chọn file"""
        group = QGroupBox("📁 Chọn File/Thư mục")
        layout = QVBoxLayout()
        
        # Hàng 1: File selection
        file_row = QHBoxLayout()
        
        self.file_path_label = QLabel("Chưa chọn file...")
        self.file_path_label.setStyleSheet("padding: 5px; background-color: #f0f0f0; border-radius: 3px;")
        
        self.browse_btn = QPushButton("📂 Browse File")
        self.browse_btn.setFixedWidth(120)
        self.browse_btn.clicked.connect(self.browse_file)
        
        file_row.addWidget(self.file_path_label, stretch=1)
        file_row.addWidget(self.browse_btn)
        
        # Hàng 2: Folder selection
        folder_row = QHBoxLayout()
        
        self.browse_folder_btn = QPushButton("📁 Quét Folder")
        self.browse_folder_btn.setFixedWidth(120)
        self.browse_folder_btn.clicked.connect(self.browse_folder)
        
        folder_row.addWidget(QLabel("Quét hàng loạt:"))
        folder_row.addWidget(self.browse_folder_btn)
        folder_row.addStretch()
        
        layout.addLayout(file_row)
        layout.addLayout(folder_row)
        group.setLayout(layout)
        
        return group
    
    def _create_scan_options(self):
        """Tạo phần tùy chọn quét"""
        group = QGroupBox("⚙️ Tùy chọn Quét")
        layout = QHBoxLayout()
        
        self.scan_mode_group = QButtonGroup()
        
        self.quick_scan_radio = QRadioButton("⚡ Quick Scan (Hash + API)")
        self.quick_scan_radio.setChecked(True)
        
        self.deep_scan_radio = QRadioButton("🔍 Deep Scan (Full Analysis)")
        
        self.scan_mode_group.addButton(self.quick_scan_radio)
        self.scan_mode_group.addButton(self.deep_scan_radio)
        
        layout.addWidget(self.quick_scan_radio)
        layout.addWidget(self.deep_scan_radio)
        layout.addStretch()
        
        group.setLayout(layout)
        return group
    
    def _create_results_section(self):
        """Tạo phần hiển thị kết quả với tabs"""
        self.results_tabs = QTabWidget()
        
        # Tab 1: Summary
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.results_tabs.addTab(self.summary_text, "📋 Tổng quan")
        
        # Tab 2: Hash Info
        self.hash_table = QTableWidget()
        self.hash_table.setColumnCount(2)
        self.hash_table.setHorizontalHeaderLabels(["Thuộc tính", "Giá trị"])
        self.hash_table.horizontalHeader().setStretchLastSection(True)
        self.results_tabs.addTab(self.hash_table, "🔑 Hash")
        
        # Tab 3: PE Analysis (Deep Scan)
        self.pe_text = QTextEdit()
        self.pe_text.setReadOnly(True)
        self.pe_text.setFont(QFont("Courier", 9))
        self.results_tabs.addTab(self.pe_text, "🔬 PE Analysis")
        
        # Tab 4: Imports/Exports
        self.imports_text = QTextEdit()
        self.imports_text.setReadOnly(True)
        self.imports_text.setFont(QFont("Courier", 9))
        self.results_tabs.addTab(self.imports_text, "📦 Imports/Exports")
        
        # Tab 5: Security Warnings
        self.security_text = QTextEdit()
        self.security_text.setReadOnly(True)
        self.security_text.setFont(QFont("Courier", 10))
        self.results_tabs.addTab(self.security_text, "⚠️ Security Warnings")
        
        # Tab 6: VirusTotal
        self.vt_text = QTextEdit()
        self.vt_text.setReadOnly(True)
        self.results_tabs.addTab(self.vt_text, "🌐 VirusTotal")
        
        # Tab 7: Batch Scan Results
        self.batch_results_widget = self._create_batch_results_widget()
        self.results_tabs.addTab(self.batch_results_widget, "📊 Batch Scan")
        
        return self.results_tabs
    
    def _create_batch_results_widget(self):
        """Tạo widget hiển thị kết quả batch scan"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Summary labels
        summary_layout = QHBoxLayout()
        
        self.batch_total_label = QLabel("Tổng: 0 file")
        self.batch_total_label.setStyleSheet("font-size: 14pt; font-weight: bold;")
        
        self.batch_safe_label = QLabel("✅ An toàn: 0")
        self.batch_safe_label.setStyleSheet("font-size: 12pt; color: green;")
        
        self.batch_malicious_label = QLabel("🚨 Nguy hiểm: 0")
        self.batch_malicious_label.setStyleSheet("font-size: 12pt; color: red; cursor: pointer;")
        self.batch_malicious_label.mousePressEvent = self.show_malicious_files
        
        summary_layout.addWidget(self.batch_total_label)
        summary_layout.addWidget(self.batch_safe_label)
        summary_layout.addWidget(self.batch_malicious_label)
        summary_layout.addStretch()
        
        # Table cho malicious files
        self.batch_malicious_table = QTableWidget()
        self.batch_malicious_table.setColumnCount(3)
        self.batch_malicious_table.setHorizontalHeaderLabels(["File Name", "Path", "Threat"])
        self.batch_malicious_table.horizontalHeader().setStretchLastSection(True)
        self.batch_malicious_table.setVisible(False)
        self.batch_malicious_table.cellDoubleClicked.connect(self.show_batch_file_detail)
        
        layout.addLayout(summary_layout)
        layout.addWidget(self.batch_malicious_table)
        
        widget.setLayout(layout)
        return widget
    
    def _create_control_buttons(self):
        """Tạo các nút điều khiển"""
        widget = QWidget()
        layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("🚀 BẮT ĐẦU QUÉT")
        self.scan_btn.setFixedHeight(50)
        self.scan_btn.setFont(QFont("Arial", 12, QFont.Bold))
        self.scan_btn.clicked.connect(self.start_scan)
        
        self.export_btn = QPushButton("💾 Xuất Báo cáo")
        self.export_btn.setFixedHeight(50)
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_report)
        
        self.clear_btn = QPushButton("🗑️ Xóa")
        self.clear_btn.setFixedHeight(50)
        self.clear_btn.clicked.connect(self.clear_results)
        
        layout.addWidget(self.scan_btn, stretch=2)
        layout.addWidget(self.export_btn, stretch=1)
        layout.addWidget(self.clear_btn, stretch=1)
        
        widget.setLayout(layout)
        return widget
    
    def _apply_stylesheet(self):
        """Áp dụng CSS cho giao diện"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
            QProgressBar {
                border: 2px solid #cccccc;
                border-radius: 5px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
            }
            QRadioButton {
                spacing: 5px;
            }
            QRadioButton::indicator {
                width: 18px;
                height: 18px;
            }
            QTextEdit, QTableWidget {
                border: 1px solid #cccccc;
                border-radius: 3px;
                background-color: white;
            }
        """)
    
    # ===== EVENT HANDLERS =====
    
    def browse_file(self):
        """Mở hộp thoại chọn file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Chọn file cần quét",
            "",
            "All Files (*);;Executable Files (*.exe *.dll);;Script Files (*.js *.vbs *.ps1)"
        )
        
        if file_path:
            self.file_path_label.setText(file_path)
            self.scan_btn.setEnabled(True)
    
    def browse_folder(self):
        """Mở hộp thoại chọn thư mục để quét hàng loạt"""
        folder_path = QFileDialog.getExistingDirectory(
            self,
            "Chọn thư mục cần quét",
            ""
        )
        
        if folder_path:
            reply = QMessageBox.question(
                self,
                "Xác nhận",
                f"Bạn có muốn quét toàn bộ thư mục:\n{folder_path}\n\n"
                f"⚠️ Quá trình này có thể mất nhiều thời gian!\n"
                f"⚠️ Chỉ quét file: .exe, .dll, .sys, .scr, .com, .bat, .cmd, .ps1, .vbs, .js\n"
                f"⚠️ Sử dụng Quick Scan (Hash + Database cục bộ)",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.start_batch_scan(folder_path)
    
    def start_batch_scan(self, root_path):
        """Bắt đầu quét hàng loạt folder"""
        # Kiểm tra đường dẫn tồn tại
        if not os.path.exists(root_path):
            QMessageBox.warning(self, "Cảnh báo", f"Đường dẫn không tồn tại:\n{root_path}")
            return
        
        # Disable buttons
        self.scan_btn.setEnabled(False)
        self.browse_btn.setEnabled(False)
        self.browse_folder_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        
        # Reset UI
        self.progress_bar.setValue(0)
        self.file_path_label.setText(f"Đang quét folder: {root_path}")
        
        # Switch to Batch Scan tab
        self.results_tabs.setCurrentIndex(6)  # Tab Batch Scan
        
        # Reset batch results
        self.batch_total_label.setText("Đang thu thập file...")
        self.batch_safe_label.setText("✅ An toàn: 0")
        self.batch_malicious_label.setText("🚨 Nguy hiểm: 0")
        self.batch_malicious_table.setVisible(False)
        self.batch_malicious_table.setRowCount(0)
        
        # Tạo và chạy batch thread
        self.batch_scan_thread = BatchScanThread(root_path, self.db_handler)
        self.batch_scan_thread.progress_update.connect(self.update_batch_progress)
        self.batch_scan_thread.file_scanned.connect(self.on_file_scanned)
        self.batch_scan_thread.batch_complete.connect(self.on_batch_complete)
        self.batch_scan_thread.error_occurred.connect(self.handle_error)
        self.batch_scan_thread.start()
    
    def update_batch_progress(self, progress, message, current, total):
        """Cập nhật tiến trình batch scan"""
        self.progress_bar.setValue(progress)
        if total > 0:
            self.status_label.setText(f"{message} ({current}/{total})")
        else:
            self.status_label.setText(message)
    
    def on_file_scanned(self, result):
        """Xử lý khi quét xong 1 file (có thể dùng để cập nhật real-time)"""
        # Có thể cập nhật số liệu real-time ở đây nếu cần
        pass
    
    def on_batch_complete(self, summary):
        """Xử lý khi batch scan hoàn thành"""
        self.batch_results = summary
        
        # Cập nhật labels
        self.batch_total_label.setText(f"Tổng: {summary['total_scanned']} file")
        self.batch_safe_label.setText(f"✅ An toàn: {summary['total_safe']}")
        
        malicious_count = summary['total_malicious']
        self.batch_malicious_label.setText(f"🚨 Nguy hiểm: {malicious_count}")
        
        if malicious_count > 0:
            # Tô đỏ và làm nổi bật
            self.batch_malicious_label.setStyleSheet(
                "font-size: 14pt; font-weight: bold; color: red; "
                "background-color: #ffe5e5; padding: 5px; border-radius: 3px; cursor: pointer;"
            )
        else:
            self.batch_malicious_label.setStyleSheet("font-size: 12pt; color: green;")
        
        # Enable buttons
        self.scan_btn.setEnabled(True)
        self.browse_btn.setEnabled(True)
        self.browse_folder_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        
        # Hiển thị thông báo
        if malicious_count > 0:
            QMessageBox.warning(
                self,
                "⚠️ Phát hiện mã độc!",
                f"Quét hoàn tất!\n\n"
                f"📊 Tổng số file: {summary['total_scanned']}\n"
                f"✅ An toàn: {summary['total_safe']}\n"
                f"🚨 Nguy hiểm: {malicious_count}\n\n"
                f"Click vào 'Nguy hiểm: {malicious_count}' để xem chi tiết!"
            )
        else:
            QMessageBox.information(
                self,
                "✅ An toàn",
                f"Quét hoàn tất!\n\n"
                f"📊 Tổng số file: {summary['total_scanned']}\n"
                f"✅ Tất cả file đều an toàn!"
            )
    
    def show_malicious_files(self, event):
        """Hiển thị danh sách file nguy hiểm khi click vào label"""
        if not self.batch_results or self.batch_results['total_malicious'] == 0:
            return
        
        # Toggle visibility
        is_visible = self.batch_malicious_table.isVisible()
        self.batch_malicious_table.setVisible(not is_visible)
        
        if not is_visible:
            # Populate table
            malicious_files = self.batch_results['malicious_files']
            self.batch_malicious_table.setRowCount(len(malicious_files))
            
            for row, file_info in enumerate(malicious_files):
                # File name
                filename_item = QTableWidgetItem(file_info['filename'])
                filename_item.setForeground(QColor(220, 53, 69))  # Red
                
                # Path
                path_item = QTableWidgetItem(file_info['filepath'])
                
                # Threat name
                threat_item = QTableWidgetItem(file_info.get('threat_name', 'Unknown'))
                threat_item.setForeground(QColor(220, 53, 69))
                
                self.batch_malicious_table.setItem(row, 0, filename_item)
                self.batch_malicious_table.setItem(row, 1, path_item)
                self.batch_malicious_table.setItem(row, 2, threat_item)
            
            # Resize columns
            self.batch_malicious_table.resizeColumnsToContents()
    
    def show_batch_file_detail(self, row, column):
        """Hiển thị chi tiết file khi double click vào file nguy hiểm"""
        if not self.batch_results:
            return
        
        malicious_files = self.batch_results['malicious_files']
        if row >= len(malicious_files):
            return
        
        file_info = malicious_files[row]
        filepath = file_info['filepath']
        
        # Chuyển sang single scan mode và quét lại file này với Quick Scan
        self.file_path_label.setText(filepath)
        
        # Switch back to Summary tab
        self.results_tabs.setCurrentIndex(0)
        
        # Thực hiện quick scan cho file này
        self.quick_scan_radio.setChecked(True)
        self.start_scan()
    
    def start_scan(self):
        """Bắt đầu quét file"""
        file_path = self.file_path_label.text()
        
        if file_path == "Chưa chọn file..." or not os.path.exists(file_path):
            QMessageBox.warning(self, "Cảnh báo", "Vui lòng chọn file hợp lệ!")
            return
        
        # Xác định chế độ quét
        scan_mode = 'deep' if self.deep_scan_radio.isChecked() else 'quick'
        
        # Vô hiệu hóa nút
        self.scan_btn.setEnabled(False)
        self.browse_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        
        # Reset progress
        self.progress_bar.setValue(0)
        self.clear_results()
        
        # Tạo và chạy thread
        self.scan_thread = ScanThread(file_path, scan_mode, self.db_handler)
        self.scan_thread.progress_update.connect(self.update_progress)
        self.scan_thread.scan_complete.connect(self.display_results)
        self.scan_thread.error_occurred.connect(self.handle_error)
        self.scan_thread.start()
    
    def update_progress(self, value, message):
        """Cập nhật thanh tiến trình"""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
    
    def display_results(self, report):
        """Hiển thị kết quả quét"""
        self.current_report = report
        
        # Tab 1: Summary
        self._display_summary(report)
        
        # Tab 2: Hash
        self._display_hash_info(report)
        
        # Tab 3: PE Analysis
        if 'pe_analysis' in report['detections']:
            self._display_pe_analysis(report['detections']['pe_analysis'])
            self._display_imports_exports(report['detections']['pe_analysis'])
            self._display_security_warnings(report['detections']['pe_analysis'])
        
        # Tab 4: Imports/Exports (hiển thị riêng)
        # Đã được xử lý trong _display_imports_exports
        
        # Tab 5: Security Warnings (hiển thị riêng)
        # Đã được xử lý trong _display_security_warnings
        
        # Tab 6: VirusTotal
        self._display_virustotal(report['detections'].get('virustotal', {}))
        
        # Kích hoạt nút
        self.scan_btn.setEnabled(True)
        self.browse_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        
        # Hiển thị thông báo
        if not report['is_safe']:
            QMessageBox.warning(
                self, 
                "⚠️ Cảnh báo", 
                "File có khả năng NGUY HIỂM!\nVui lòng xem chi tiết trong các tab."
            )
        else:
            QMessageBox.information(
                self,
                "✅ An toàn",
                "File được đánh giá là AN TOÀN."
            )
    
    def _display_summary(self, report):
        """Hiển thị tổng quan"""
        summary = f"""
<h2>📊 KẾT QUẢ QUÉT</h2>
<hr>
<p><b>File:</b> {report['filename']}</p>
<p><b>Đường dẫn:</b> {report['filepath']}</p>
<p><b>Trạng thái:</b> <span style='color: {"red" if not report["is_safe"] else "green"}; font-weight: bold;'>
{"🚨 NGUY HIỂM" if not report["is_safe"] else "✅ AN TOÀN"}</span></p>

<h3>🔍 Chi tiết phát hiện:</h3>
<ul>
"""
        
        # Local DB
        local = report['detections'].get('local_db', {})
        if local.get('detected'):
            summary += f"<li><b>Database cục bộ:</b> <span style='color: red;'>⚠️ {local['malware_name']}</span></li>"
        else:
            summary += "<li><b>Database cục bộ:</b> <span style='color: green;'>✓ Sạch</span></li>"
        
        # VirusTotal
        vt = report['detections'].get('virustotal', {})
        if vt.get('status') == 'success':
            if vt.get('verdict') == 'MALICIOUS':
                summary += f"<li><b>VirusTotal:</b> <span style='color: red;'>⚠️ {vt['detected_by']}/{vt['total_scanners']} phát hiện</span></li>"
            else:
                summary += f"<li><b>VirusTotal:</b> <span style='color: green;'>✓ {vt['detected_by']}/{vt['total_scanners']}</span></li>"
        
        summary += "</ul>"
        
        self.summary_text.setHtml(summary)
    
    def _display_hash_info(self, report):
        """Hiển thị thông tin hash"""
        hashes = report['detections'].get('hash', {})
        
        self.hash_table.setRowCount(3)
        self.hash_table.setItem(0, 0, QTableWidgetItem("MD5"))
        self.hash_table.setItem(0, 1, QTableWidgetItem(hashes.get('md5', 'N/A')))
        self.hash_table.setItem(1, 0, QTableWidgetItem("SHA256"))
        self.hash_table.setItem(1, 1, QTableWidgetItem(hashes.get('sha256', 'N/A')))
        self.hash_table.setItem(2, 0, QTableWidgetItem("File"))
        self.hash_table.setItem(2, 1, QTableWidgetItem(report['filename']))
    
    def _display_pe_analysis(self, pe_info):
        """Hiển thị phân tích PE"""
        if not pe_info.get('is_pe'):
            self.pe_text.setText("Không phải file PE (Windows Executable)")
            return
        
        text = "╔══════════════════════════════════════════════════════════════╗\n"
        text += "║               PE HEADER ANALYSIS - DEEP SCAN                 ║\n"
        text += "╚══════════════════════════════════════════════════════════════╝\n\n"
        
        # File Header
        fh = pe_info.get('file_header', {})
        text += "┌─ FILE HEADER\n"
        text += f"│  Machine:            {fh.get('machine', 'N/A')}\n"
        text += f"│  Compilation Time:   {fh.get('compilation_timestamp', 'N/A')}\n"
        text += f"│  Sections:           {fh.get('number_of_sections', 'N/A')}\n"
        text += f"│  Characteristics:    {', '.join(fh.get('characteristics', []))}\n\n"
        
        # Optional Header
        oh = pe_info.get('optional_header', {})
        text += "┌─ OPTIONAL HEADER\n"
        text += f"│  Entry Point:        {oh.get('address_of_entry_point', 'N/A')}\n"
        text += f"│  Image Base:         {oh.get('image_base', 'N/A')}\n"
        text += f"│  Subsystem:          {oh.get('subsystem', 'N/A')}\n"
        text += f"│  DLL Characteristics: {', '.join(oh.get('dll_characteristics', []))}\n\n"
        
        # Sections với cảnh báo entropy
        text += "┌─ SECTIONS\n"
        sections = pe_info.get('sections', [])
        if sections:
            text += f"│  {'Name':<12} {'VirtAddr':<12} {'VirtSize':<12} {'RawSize':<12} {'Entropy':<8}\n"
            text += f"│  {'-'*12} {'-'*12} {'-'*12} {'-'*12} {'-'*8}\n"
            for sec in sections[:10]:
                entropy = sec['entropy']
                entropy_str = f"{entropy:.2f}"
                
                # Thêm cảnh báo nếu entropy cao
                warning = ""
                if entropy > 7.0:
                    warning = " ⚠️ High entropy detected (>7.0) - Possibly packed/encrypted"
                
                text += f"│  {sec['name']:<12} {sec['virtual_address']:<12} {sec['virtual_size']:<12} {sec['raw_size']:<12} {entropy_str:<8}\n"
                if warning:
                    text += f"│      {warning}\n"
        
        text += "\n"
        
        # Imports summary (chi tiết ở tab riêng)
        imports = pe_info.get('imports', [])
        if imports:
            text += "┌─ IMPORTS SUMMARY\n"
            text += f"│  Total DLLs: {len(imports)}\n"
            text += f"│  Top 3 DLLs:\n"
            for idx, imp in enumerate(imports[:3], 1):
                text += f"│    {idx}. {imp['dll']} ({imp['total_functions']} functions)\n"
            
            if len(imports) > 3:
                text += f"│  ... and {len(imports) - 3} more DLLs\n"
            
            text += "│\n"
            text += "│  ℹ️  See 'Imports/Exports' tab for full details\n"
        
        text += "\n"
        
        # SECURITY WARNINGS - Phần quan trọng nhất!
        text += "┌─ SECURITY WARNINGS\n"
        warnings = self._generate_security_warnings(pe_info)
        
        if warnings:
            for warning in warnings:
                text += f"│  {warning}\n"
        else:
            text += "│  ✓ No obvious security warnings detected.\n"
        
        self.pe_text.setText(text)
    
    def _generate_security_warnings(self, pe_info):
        """Tạo danh sách cảnh báo bảo mật"""
        warnings = []
        
        # 1. Kiểm tra ASLR
        dll_chars = pe_info.get('optional_header', {}).get('dll_characteristics', [])
        if not any('DYNAMIC_BASE' in c or 'ASLR' in c for c in dll_chars):
            warnings.append("⚠️ ASLR not enabled - vulnerable to memory attacks")
        
        # 2. Kiểm tra DEP/NX
        if not any('NX_COMPAT' in c or 'DEP' in c for c in dll_chars):
            warnings.append("⚠️ DEP/NX not enabled - vulnerable to code execution")
        
        # 3. Kiểm tra các DLL nguy hiểm (network capability)
        dangerous_dlls = {
            'ws2_32.dll': 'Network capability',
            'wininet.dll': 'Network capability', 
            'urlmon.dll': 'Network capability',
            'wsock32.dll': 'Network capability'
        }
        
        imports = pe_info.get('imports', [])
        for imp in imports:
            dll_name = imp['dll'].lower()
            if dll_name in dangerous_dlls:
                warnings.append(f"⚠️ Imports suspicious DLL: {imp['dll']} ({dangerous_dlls[dll_name]})")
        
        # 4. Kiểm tra số lượng imports bất thường
        if len(imports) > 50:
            warnings.append(f"⚠️ Unusual number of imported DLLs: {len(imports)} (>50)")
        
        # 5. Kiểm tra sections với entropy cao
        sections = pe_info.get('sections', [])
        high_entropy_sections = [s for s in sections if s['entropy'] > 7.0]
        
        if len(high_entropy_sections) >= 2:
            warnings.append(f"⚠️ Multiple high-entropy sections detected (possible packer/crypter)")
        
        # 6. Kiểm tra packed
        packed_status = pe_info.get('basic_properties', {}).get('packed', 'No')
        if 'Yes' in packed_status or 'Possibly' in packed_status:
            warnings.append(f"⚠️ File appears to be packed: {packed_status}")
        
        return warnings
    
    def _display_security_warnings(self, pe_info):
        """Hiển thị Security Warnings trong tab riêng với format đẹp"""
        if not pe_info.get('is_pe'):
            self.security_text.setHtml("<p><b>Không phải file PE - Không có cảnh báo bảo mật</b></p>")
            return
        
        warnings = self._generate_security_warnings(pe_info)
        
        html = """
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; }
            .header { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white; 
                padding: 15px; 
                border-radius: 8px;
                margin-bottom: 20px;
                text-align: center;
            }
            .warning-box {
                background-color: #fff3cd;
                border-left: 5px solid #ffc107;
                padding: 12px;
                margin: 10px 0;
                border-radius: 5px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .warning-icon {
                color: #ff9800;
                font-size: 18px;
                font-weight: bold;
            }
            .safe-box {
                background-color: #d4edda;
                border-left: 5px solid #28a745;
                padding: 12px;
                margin: 10px 0;
                border-radius: 5px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .info-box {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                padding: 10px;
                margin: 15px 0;
                border-radius: 5px;
            }
            .section-title {
                color: #495057;
                font-size: 14px;
                font-weight: bold;
                margin-top: 15px;
                margin-bottom: 10px;
                border-bottom: 2px solid #007bff;
                padding-bottom: 5px;
            }
            .entropy-warning {
                background-color: #ffe5e5;
                border-left: 5px solid #dc3545;
                padding: 8px;
                margin: 5px 0;
                font-size: 12px;
                border-radius: 3px;
            }
        </style>
        
        <div class="header">
            <h2>🔒 SECURITY ANALYSIS REPORT</h2>
        </div>
        """
        
        if warnings:
            html += f'<div class="info-box"><b>⚠️ {len(warnings)} Security Warning(s) Detected</b></div>'
            
            # Phân loại warnings
            critical_warnings = [w for w in warnings if 'ASLR' in w or 'DEP' in w or 'packed' in w.lower()]
            medium_warnings = [w for w in warnings if 'DLL' in w or 'entropy' in w.lower()]
            info_warnings = [w for w in warnings if w not in critical_warnings and w not in medium_warnings]
            
            # Critical warnings
            if critical_warnings:
                html += '<div class="section-title">🚨 CRITICAL WARNINGS</div>'
                for warning in critical_warnings:
                    clean_warning = warning.replace('⚠️', '').strip()
                    html += f'<div class="warning-box"><span class="warning-icon">⚠️</span> {clean_warning}</div>'
            
            # Medium warnings
            if medium_warnings:
                html += '<div class="section-title">⚠️ MEDIUM WARNINGS</div>'
                for warning in medium_warnings:
                    clean_warning = warning.replace('⚠️', '').strip()
                    html += f'<div class="warning-box"><span class="warning-icon">⚠️</span> {clean_warning}</div>'
            
            # Info warnings
            if info_warnings:
                html += '<div class="section-title">ℹ️ INFORMATIONAL</div>'
                for warning in info_warnings:
                    clean_warning = warning.replace('⚠️', '').strip()
                    html += f'<div class="warning-box"><span class="warning-icon">ℹ️</span> {clean_warning}</div>'
            
            # Entropy details
            sections = pe_info.get('sections', [])
            high_entropy = [s for s in sections if s['entropy'] > 7.0]
            
            if high_entropy:
                html += '<div class="section-title">📊 HIGH ENTROPY SECTIONS DETAIL</div>'
                for sec in high_entropy:
                    html += f'''
                    <div class="entropy-warning">
                        <b>{sec['name']}</b>: Entropy = <b>{sec['entropy']:.2f}</b> (>7.0)<br>
                        Virtual Size: {sec['virtual_size']:,} bytes | Raw Size: {sec['raw_size']:,} bytes
                    </div>
                    '''
        else:
            html += '<div class="safe-box">✅ <b>No security warnings detected.</b> File appears to follow standard security practices.</div>'
        
        # Recommendations
        html += '<div class="section-title">💡 RECOMMENDATIONS</div>'
        html += '<div class="info-box">'
        
        if warnings:
            html += '<ul style="margin: 5px 0; padding-left: 20px;">'
            if any('ASLR' in w for w in warnings):
                html += '<li>Enable ASLR (Address Space Layout Randomization) during compilation</li>'
            if any('DEP' in w for w in warnings):
                html += '<li>Enable DEP/NX (Data Execution Prevention) protection</li>'
            if any('entropy' in w.lower() for w in warnings):
                html += '<li>High entropy may indicate packing/encryption - further analysis recommended</li>'
            if any('DLL' in w for w in warnings):
                html += '<li>Review imported DLLs for legitimacy and necessity</li>'
            html += '</ul>'
        else:
            html += '<p>✓ File follows good security practices. Continue with standard malware analysis procedures.</p>'
        
        html += '</div>'
        
        self.security_text.setHtml(html)
    
    def _is_dangerous_function(self, func_name, dll_name=''):
        """Kiểm tra function có nguy hiểm không"""
        func_lower = func_name.lower()
        dll_lower = dll_name.lower()
        
        # Danh sách các functions nguy hiểm
        dangerous_functions = {
            # Network functions
            'socket', 'connect', 'send', 'recv', 'wsasend', 'wsarecv',
            'internetconnect', 'httpsendrequest', 'internetopen', 'internetopenurl',
            'urlopen', 'internetreadfile', 'internetwritefile',
            # Process manipulation
            'createprocess', 'createprocessa', 'createprocessw',
            'createremotethread', 'writeprocessmemory', 'readprocessmemory',
            'virtualallocex', 'virtualprotectex', 'openprocess',
            # Registry manipulation
            'regsetvalue', 'regsetvalueex', 'regcreatekey', 'regcreatekeyex',
            'regdeletekey', 'regdeletevalue',
            # File operations (có thể nguy hiểm)
            'createfile', 'writefile', 'deletefile', 'movefile',
            'copyfile', 'setfileattributes',
            # Memory manipulation
            'virtualalloc', 'virtualprotect', 'virtualfree',
            'heapcreate', 'heapalloc', 'heapfree',
            # Crypto functions
            'cryptencrypt', 'cryptdecrypt', 'cryptgenkey',
            # Anti-debugging
            'isdebuggerpresent', 'checkremotedebuggerpresent',
            'ntqueryinformationprocess', 'ntsetinformationthread',
            # Code injection
            'createthread', 'loadlibrary', 'getprocaddress',
            'loadlibrarya', 'loadlibraryw', 'getprocaddress',
            # System functions
            'system', 'shellexecute', 'shellexecutea', 'shellexecutew',
            'winexec', 'exitprocess', 'terminateprocess',
            # Service manipulation
            'createservice', 'startservice', 'controlservice',
            # Privilege escalation
            'adjusttokenprivileges', 'lookupprivilegevalue',
            # Network enumeration
            'gethostbyname', 'gethostbyaddr', 'getaddrinfo',
        }
        
        # Kiểm tra function name
        if func_lower in dangerous_functions:
            return True
        
        # Kiểm tra các patterns nguy hiểm
        dangerous_patterns = [
            'crypt', 'encrypt', 'decrypt',
            'inject', 'hook', 'patch',
            'bypass', 'evade', 'stealth',
        ]
        
        for pattern in dangerous_patterns:
            if pattern in func_lower:
                return True
        
        return False
    
    def _is_dangerous_dll(self, dll_name):
        """Kiểm tra DLL có nguy hiểm không"""
        dll_lower = dll_name.lower()
        dangerous_dlls = [
            'ws2_32.dll', 'wininet.dll', 'urlmon.dll', 'wsock32.dll',
            'advapi32.dll',  # Registry, service manipulation
            'ntdll.dll',     # Low-level system calls
            'dbghelp.dll',   # Debugging functions
        ]
        return dll_lower in dangerous_dlls
    
    def _display_imports_exports(self, pe_info):
        """Hiển thị chi tiết Imports và Exports trong tab riêng với highlight nguy hiểm"""
        if not pe_info.get('is_pe'):
            self.imports_text.setHtml("<p><b>Không phải file PE - Không có imports/exports</b></p>")
            return
        
        html = """
        <style>
            body { font-family: 'Courier New', monospace; font-size: 10pt; }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 15px;
                text-align: center;
            }
            .section-title {
                background-color: #e9ecef;
                padding: 8px;
                margin: 15px 0 10px 0;
                border-left: 4px solid #007bff;
                font-weight: bold;
                font-size: 11pt;
            }
            .dll-name {
                font-weight: bold;
                color: #495057;
                margin-top: 10px;
            }
            .dll-name.dangerous {
                color: #dc3545;
            }
            .function-item {
                padding: 2px 0;
                margin-left: 20px;
                font-family: 'Courier New', monospace;
            }
            .function-item.dangerous {
                color: #dc3545;
                font-weight: bold;
            }
            .warning-icon {
                color: #ff9800;
                font-size: 14px;
            }
            .stats-box {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                padding: 10px;
                margin: 15px 0;
                border-radius: 5px;
            }
            .risk-high {
                color: #dc3545;
                font-weight: bold;
            }
        </style>
        
        <div class="header">
            <h2>📦 IMPORTS & EXPORTS ANALYSIS</h2>
        </div>
        """
        
        # ===== IMPORTS SECTION =====
        imports = pe_info.get('imports', [])
        
        if imports:
            html += '<div class="section-title">📥 IMPORTS</div>'
            html += f'<p><b>Total DLLs imported:</b> {len(imports)}</p>'
            
            # Hiển thị tất cả DLLs (không giới hạn 5)
            for idx, imp in enumerate(imports, 1):
                dll_name = imp['dll']
                total_funcs = imp['total_functions']
                functions = imp.get('functions', [])
                
                # Kiểm tra DLL có nguy hiểm không
                is_dll_dangerous = self._is_dangerous_dll(dll_name)
                dll_class = 'dll-name dangerous' if is_dll_dangerous else 'dll-name'
                dll_warning = ' ⚠️' if is_dll_dangerous else ''
                
                html += f'<div class="{dll_class}">'
                html += f'[{idx}] {dll_name}{dll_warning} ({total_funcs} functions)'
                html += '</div>'
                
                # Hiển thị functions
                dangerous_count = 0
                for func in functions:
                    is_func_dangerous = self._is_dangerous_function(func, dll_name)
                    if is_func_dangerous:
                        dangerous_count += 1
                    
                    func_class = 'function-item dangerous' if is_func_dangerous else 'function-item'
                    warning_icon = '<span class="warning-icon">⚠️</span> ' if is_func_dangerous else ''
                    
                    html += f'<div class="{func_class}">'
                    html += f'{warning_icon}- {func}'
                    html += '</div>'
                
                if dangerous_count > 0:
                    html += f'<div style="margin-left: 20px; color: #dc3545; font-size: 9pt;">'
                    html += f'⚠️ {dangerous_count} dangerous function(s) detected in this DLL'
                    html += '</div>'
                
                html += '<br>'
            
            # Tổng hợp các DLLs nguy hiểm
            dangerous_dlls_found = []
            for imp in imports:
                if self._is_dangerous_dll(imp['dll']):
                    dangerous_dlls_found.append(imp['dll'])
            
            if dangerous_dlls_found:
                html += '<div class="section-title">⚠️ SUSPICIOUS DLLs DETECTED</div>'
                html += '<ul style="color: #dc3545;">'
                for dll in dangerous_dlls_found:
                    html += f'<li><b>{dll}</b> - Network/System capability</li>'
                html += '</ul>'
        
        else:
            html += '<div class="section-title">📥 IMPORTS</div>'
            html += '<p style="color: #ff9800;">⚠️ No imports found (unusual for normal PE files)</p>'
        
        # ===== EXPORTS SECTION =====
        exports = pe_info.get('exports', [])
        
        html += '<div class="section-title">📤 EXPORTS</div>'
        
        if exports:
            html += f'<p><b>Total functions exported:</b> {len(exports)}</p>'
            html += '<table style="width: 100%; border-collapse: collapse; font-family: Courier New;">'
            html += '<tr style="background-color: #e9ecef;">'
            html += '<th style="padding: 5px; text-align: left; width: 50px;">#</th>'
            html += '<th style="padding: 5px; text-align: left;">Function Name</th>'
            html += '<th style="padding: 5px; text-align: left; width: 100px;">Ordinal</th>'
            html += '</tr>'
            
            display_limit = 50  # Tăng lên 50 để hiển thị nhiều hơn
            for idx, exp in enumerate(exports[:display_limit], 1):
                func_name = exp['name']
                ordinal = exp['ordinal']
                
                # Kiểm tra export có nguy hiểm không
                is_dangerous = self._is_dangerous_function(func_name)
                row_style = 'background-color: #ffe5e5; color: #dc3545; font-weight: bold;' if is_dangerous else ''
                warning_icon = '⚠️ ' if is_dangerous else ''
                
                html += f'<tr style="{row_style}">'
                html += f'<td style="padding: 3px;">{idx}</td>'
                html += f'<td style="padding: 3px;">{warning_icon}{func_name}</td>'
                html += f'<td style="padding: 3px;">{ordinal}</td>'
                html += '</tr>'
            
            html += '</table>'
            
            if len(exports) > display_limit:
                html += f'<p style="color: #6c757d;">... and {len(exports) - display_limit} more export(s)</p>'
        
        else:
            html += '<p>No exports found (typical for .exe files)</p>'
        
        # ===== SUMMARY STATISTICS =====
        html += '<div class="section-title">📊 SUMMARY STATISTICS</div>'
        html += '<div class="stats-box">'
        
        total_imported_funcs = sum(imp['total_functions'] for imp in imports)
        
        # Đếm số functions nguy hiểm
        dangerous_functions_count = 0
        for imp in imports:
            functions = imp.get('functions', [])
            for func in functions:
                if self._is_dangerous_function(func, imp['dll']):
                    dangerous_functions_count += 1
        
        html += f'<p><b>Total Imported DLLs:</b> {len(imports)}</p>'
        html += f'<p><b>Total Imported Functions:</b> {total_imported_funcs}</p>'
        if dangerous_functions_count > 0:
            html += f'<p class="risk-high"><b>⚠️ Dangerous Functions Detected:</b> {dangerous_functions_count}</p>'
        html += f'<p><b>Total Exported Functions:</b> {len(exports)}</p>'
        
        # File type detection
        file_type = "Unknown"
        if len(exports) > 0:
            file_type = "DLL (Dynamic Link Library)"
        elif len(imports) > 0:
            file_type = "EXE (Executable)"
        
        html += f'<p><b>Probable File Type:</b> {file_type}</p>'
        
        # Risk assessment
        risk_score = 0
        risk_factors = []
        
        if dangerous_functions_count > 0:
            risk_score += min(3, dangerous_functions_count // 5)  # +1-3 điểm
            risk_factors.append(f"{dangerous_functions_count} dangerous function(s) detected")
        
        if any(self._is_dangerous_dll(imp['dll']) for imp in imports):
            risk_score += 2
            risk_factors.append("Suspicious DLLs (Network/System capability)")
        
        if len(imports) > 50:
            risk_score += 1
            risk_factors.append("High number of imports")
        
        if len(imports) == 0:
            risk_score += 3
            risk_factors.append("No imports (highly unusual)")
        
        risk_score = min(risk_score, 10)  # Giới hạn tối đa 10
        
        risk_color = '#dc3545' if risk_score >= 7 else '#ff9800' if risk_score >= 4 else '#28a745'
        
        html += f'<p><b>Import Risk Score:</b> <span style="color: {risk_color}; font-weight: bold; font-size: 12pt;">{risk_score}/10</span></p>'
        
        if risk_factors:
            html += '<p><b>Risk Factors:</b></p><ul>'
            for factor in risk_factors:
                html += f'<li style="color: #dc3545;">{factor}</li>'
            html += '</ul>'
        else:
            html += '<p><b>Risk Factors:</b> <span style="color: #28a745;">None detected</span></p>'
        
        html += '</div>'
        
        self.imports_text.setHtml(html)
    
    def _display_virustotal(self, vt_report):
        """Hiển thị kết quả VirusTotal"""
        if vt_report.get('status') != 'success':
            self.vt_text.setText(f"❌ Lỗi: {vt_report.get('message', 'Không có dữ liệu')}")
            return
        
        text = f"""
<h3>🌐 VirusTotal Analysis</h3>
<p><b>Verdict:</b> <span style='color: {"red" if vt_report.get("verdict") == "MALICIOUS" else "green"};'>
{vt_report.get('verdict', 'Unknown')}</span></p>
<p><b>Detection Rate:</b> {vt_report.get('detected_by', 0)}/{vt_report.get('total_scanners', 0)}</p>
<p><b>Scan Date:</b> {vt_report.get('scan_date', 'N/A')}</p>
<p><b>Permalink:</b> <a href='{vt_report.get("permalink", "#")}'>{vt_report.get("permalink", "#")}</a></p>
"""
        self.vt_text.setHtml(text)
    
    def handle_error(self, error_message):
        """Xử lý lỗi"""
        QMessageBox.critical(self, "Lỗi", error_message)
        self.scan_btn.setEnabled(True)
        self.browse_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Lỗi xảy ra!")
    
    def export_report(self):
        """Xuất báo cáo ra file"""
        if not self.current_report:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Lưu báo cáo",
            f"report_{self.current_report['filename']}.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("="*70 + "\n")
                    f.write("PYMALSCAN-LITE - SCAN REPORT\n")
                    f.write("="*70 + "\n\n")
                    f.write(f"File: {self.current_report['filename']}\n")
                    f.write(f"Path: {self.current_report['filepath']}\n")
                    f.write(f"Status: {'MALICIOUS' if not self.current_report['is_safe'] else 'CLEAN'}\n")
                    f.write("\n" + "="*70 + "\n")
                    # Thêm chi tiết...
                
                QMessageBox.information(self, "Thành công", f"Đã xuất báo cáo tại:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Lỗi", f"Không thể xuất báo cáo:\n{str(e)}")
    
    def clear_results(self):
        """Xóa kết quả"""
        self.summary_text.clear()
        self.hash_table.setRowCount(0)
        self.pe_text.clear()
        self.imports_text.clear()
        self.security_text.clear()
        self.vt_text.clear()
        
        # Reset batch results
        if hasattr(self, 'batch_total_label'):
            self.batch_total_label.setText("Tổng: 0 file")
            self.batch_safe_label.setText("✅ An toàn: 0")
            self.batch_malicious_label.setText("🚨 Nguy hiểm: 0")
            self.batch_malicious_label.setStyleSheet("font-size: 12pt; color: red; cursor: pointer;")
            if hasattr(self, 'batch_malicious_table'):
                self.batch_malicious_table.setVisible(False)
                self.batch_malicious_table.setRowCount(0)
        
        self.current_report = None
        self.batch_results = None


def main():
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    window = PyMalScanGUI()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()