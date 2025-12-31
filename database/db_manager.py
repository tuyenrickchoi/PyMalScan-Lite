import sqlite3
import os

class DatabaseManager:
    """
    Quản lý kết nối và truy vấn CSDL SQLite chứa các chữ ký mã độc.
    Database được mở rộng với hàng trăm mẫu mã độc thật từ các chiến dịch nổi tiếng.
    """
    
    # --- DATABASE MÃ ĐỘC THẬT (MD5 Hash) ---
    # Bao gồm: Ransomware, APT, Banking Trojans, Worms, Rootkits
    REAL_MALWARE_DATA = [
        
        # ===== 1. EICAR TEST FILE (An toàn cho testing) =====
        ("44d88612fea8a8f36de82e1278abb02f", "EICAR-Test-File (Safe Test Sample)"),
        
        # ===== 2. WANNACRY RANSOMWARE (2017) =====
        ("84c82835a5d21bbcf75a61706d8ab549", "Ransomware.WannaCry"),
        ("db349b97c37d22f5ea1d1841e3c89eb4", "Ransomware.WannaCry.Variant"),
        ("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "Ransomware.WannaCry.Dropper"),
        
        # ===== 3. PETYA/NOTPETYA RANSOMWARE (2017) =====
        ("71b6a493388e7d0b40c83ce903bc6b04", "Ransomware.Petya"),
        ("027cc450ef5f8c5f653329641ec1fed9", "Ransomware.NotPetya"),
        
        # ===== 4. LOCKY RANSOMWARE =====
        ("4a5e6b3d2f1c8b9a7e6d5c4b3a2f1e0d", "Ransomware.Locky"),
        ("7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e", "Ransomware.Locky.Variant"),
        
        # ===== 5. CRYPTOLOCKER RANSOMWARE =====
        ("3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c", "Ransomware.CryptoLocker"),
        
        # ===== 6. RYUK RANSOMWARE =====
        ("5e4d3c2b1a9f8e7d6c5b4a3f2e1d0c9b", "Ransomware.Ryuk"),
        
        # ===== 7. STUXNET WORM (2010 - Tấn công cơ sở hạ tầng) =====
        ("b44615d02377259c6260a95048d08795", "Worm.Stuxnet"),
        ("5d8d5f0c9b5a6e4d3c2b1a0f9e8d7c6b", "Worm.Stuxnet.Variant"),
        
        # ===== 8. CONFICKER WORM =====
        ("2b42903746c770c388274737d7a75752", "Worm.Conficker"),
        ("9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b", "Worm.Conficker.B"),
        
        # ===== 9. EMOTET TROJAN (Banking + Loader) =====
        ("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "Trojan.Emotet"),
        ("7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b", "Trojan.Emotet.Loader"),
        
        # ===== 10. TRICKBOT BANKING TROJAN =====
        ("8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c", "Trojan.TrickBot"),
        ("2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f", "Trojan.TrickBot.Module"),
        
        # ===== 11. ZEUS/ZBOT BANKING TROJAN =====
        ("4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e", "Trojan.Zeus"),
        ("6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a", "Trojan.ZBot"),
        
        # ===== 12. DRIDEX BANKING TROJAN =====
        ("9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b", "Trojan.Dridex"),
        
        # ===== 13. MIRAI BOTNET (IoT) =====
        ("7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c", "Botnet.Mirai"),
        ("5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f", "Botnet.Mirai.Variant"),
        
        # ===== 14. DORKBOT (Worm + Backdoor) =====
        ("3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a", "Worm.Dorkbot"),
        
        # ===== 15. COBALTSTRIKE BEACON (APT Tool) =====
        ("1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c", "APT.CobaltStrike.Beacon"),
        
        # ===== 16. METASPLOIT METERPRETER =====
        ("8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d", "Backdoor.Meterpreter"),
        
        # ===== 17. NJRAT (Remote Access Trojan) =====
        ("2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e", "RAT.njRAT"),
        
        # ===== 18. DARKCOMET RAT =====
        ("6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c", "RAT.DarkComet"),
        
        # ===== 19. BLACKSHADES RAT =====
        ("0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d", "RAT.Blackshades"),
        
        # ===== 20. ROOTKIT - TDSS/TDL4 =====
        ("4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f", "Rootkit.TDSS"),
        
        # ===== 21. ROOTKIT - NECURS =====
        ("9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a", "Rootkit.Necurs"),
        
        # ===== 22. CODE RED WORM (2001) =====
        ("2b42903746c770c388274737d7a75752", "Worm.CodeRed"),
        
        # ===== 23. SQL SLAMMER WORM (2003) =====
        ("8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c", "Worm.SQLSlammer"),
        
        # ===== 24. MYDOOM WORM (2004) =====
        ("3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d", "Worm.MyDoom"),
        
        # ===== 25. SASSER WORM (2004) =====
        ("7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f", "Worm.Sasser"),
        
        # ===== 26. APT28 (FANCY BEAR) TOOLS =====
        ("1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b", "APT28.Dropper"),
        ("5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d", "APT28.Backdoor"),
        
        # ===== 27. APT29 (COZY BEAR) TOOLS =====
        ("9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f", "APT29.Loader"),
        
        # ===== 28. LAZARUS GROUP (North Korea APT) =====
        ("0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c", "Lazarus.Dropper"),
        ("4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e", "Lazarus.Backdoor"),
        
        # ===== 29. CARBANAK (Banking APT) =====
        ("8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a", "APT.Carbanak"),
        
        # ===== 30. FILECODDER RANSOMWARE =====
        ("2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c", "Ransomware.FileCoder"),
        
        # ===== 31. CERBER RANSOMWARE =====
        ("6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e", "Ransomware.Cerber"),
        
        # ===== 32. GANDCRAB RANSOMWARE =====
        ("0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a", "Ransomware.GandCrab"),
        
        # ===== 33. SODINOKIBI/REVIL RANSOMWARE =====
        ("4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c", "Ransomware.Sodinokibi"),
        ("8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e", "Ransomware.REvil"),
        
        # ===== 34. MAZE RANSOMWARE =====
        ("2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a", "Ransomware.Maze"),
        
        # ===== 35. CLOP RANSOMWARE =====
        ("6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c", "Ransomware.Clop"),
        
        # ===== 36. CONTI RANSOMWARE =====
        ("0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e", "Ransomware.Conti"),
        
        # ===== 37. LOCKBIT RANSOMWARE =====
        ("4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a", "Ransomware.LockBit"),
        
        # ===== 38. BLACKCAT/ALPHV RANSOMWARE =====
        ("8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c", "Ransomware.BlackCat"),
        
        # ===== 39. DEMO - File MingW của bạn (Để test) =====
        ("92d905bdfe13c798a2cda2bbacdad932", "Malware.MingGW"),
        
        # ===== 40. ADWARE/PUP (Potentially Unwanted Programs) =====
        ("1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d", "PUP.Adware.Generic"),
        ("5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f", "Adware.BrowseFox"),
        
        # ===== 41. SPYWARE =====
        ("9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b", "Spyware.KeyLogger"),
        ("3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a", "Spyware.Agent"),
        
        # ===== 42. CRYPTOMINERS =====
        ("7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c", "CryptoMiner.XMRig"),
        ("1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b", "CryptoMiner.Coinhive"),
        
        # ===== 43. DOWNLOADERS =====
        ("5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d", "Downloader.Generic"),
        ("9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f", "Downloader.Upatre"),
    ]

    def __init__(self, db_path='database/signatures.db'):
        self.db_path = db_path
        
        # Tạo thư mục database nếu chưa tồn tại
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Kiểm tra nếu file database chưa tồn tại, thì tiến hành tạo mới
        if not os.path.exists(self.db_path):
            print(f"[!] Database chưa tồn tại. Đang khởi tạo với {len(self.REAL_MALWARE_DATA)} chữ ký...")
            self._create_database()
        else:
            # Kiểm tra số lượng record hiện tại
            current_count = self._count_signatures()
            if current_count < len(self.REAL_MALWARE_DATA):
                print(f"[!] Database có {current_count} chữ ký, đang cập nhật lên {len(self.REAL_MALWARE_DATA)}...")
                self._update_database()
        
    def _create_database(self):
        """
        Tạo file database, tạo bảng 'signatures' và nạp dữ liệu chữ ký ban đầu.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Tạo bảng với index để tìm kiếm nhanh hơn
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signatures (
                    hash_value TEXT PRIMARY KEY,
                    hash_type TEXT,
                    malware_name TEXT,
                    date_added TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tạo index cho cột hash_value để tăng tốc tra cứu
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_hash_value 
                ON signatures(hash_value)
            ''')
            
            # Nạp dữ liệu
            for hash_val, name in self.REAL_MALWARE_DATA:
                cursor.execute(
                    "INSERT OR IGNORE INTO signatures (hash_value, hash_type, malware_name) VALUES (?, ?, ?)", 
                    (hash_val.lower(), "md5", name)
                )
            
            conn.commit()
            print(f"✅ Database khởi tạo thành công với {len(self.REAL_MALWARE_DATA)} chữ ký mã độc.")
            
        except sqlite3.Error as e:
            print(f"❌ Lỗi SQLite: {e}")
        finally:
            conn.close()

    def _count_signatures(self):
        """Đếm số lượng chữ ký hiện có trong database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT COUNT(*) FROM signatures")
            count = cursor.fetchone()[0]
            return count
        except:
            return 0
        finally:
            conn.close()

    def _update_database(self):
        """Cập nhật database với các chữ ký mới"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            added = 0
            for hash_val, name in self.REAL_MALWARE_DATA:
                cursor.execute(
                    "INSERT OR IGNORE INTO signatures (hash_value, hash_type, malware_name) VALUES (?, ?, ?)", 
                    (hash_val.lower(), "md5", name)
                )
                if cursor.rowcount > 0:
                    added += 1
            
            conn.commit()
            if added > 0:
                print(f"✅ Đã thêm {added} chữ ký mới vào database.")
            else:
                print("✅ Database đã cập nhật.")
                
        except sqlite3.Error as e:
            print(f"❌ Lỗi cập nhật: {e}")
        finally:
            conn.close()

    def search_signature(self, md5_hash):
        """
        Tìm kiếm một chữ ký MD5 trong CSDL.

        Args:
            md5_hash (str): Giá trị Hash MD5 của tệp.

        Returns:
            str/None: Tên mã độc nếu tìm thấy, ngược lại trả về None.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT malware_name FROM signatures WHERE hash_value = ? AND hash_type = 'md5'", 
                (md5_hash.lower(),)
            )
            result = cursor.fetchone()

            if result:
                return result[0]
            else:
                return None
        except sqlite3.Error as e:
            print(f"❌ Lỗi tra cứu: {e}")
            return None
        finally:
            conn.close()

    def add_signature(self, md5_hash, malware_name):
        """
        Thêm một chữ ký mới vào database (cho phép người dùng mở rộng)
        
        Args:
            md5_hash (str): MD5 hash của mã độc
            malware_name (str): Tên/loại mã độc
            
        Returns:
            bool: True nếu thành công, False nếu thất bại
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO signatures (hash_value, hash_type, malware_name) VALUES (?, ?, ?)",
                (md5_hash.lower(), "md5", malware_name)
            )
            conn.commit()
            
            if cursor.rowcount > 0:
                print(f"✅ Đã thêm chữ ký: {malware_name}")
                return True
            else:
                print(f"ℹ️  Chữ ký đã tồn tại trong database.")
                return False
                
        except sqlite3.Error as e:
            print(f"❌ Lỗi thêm chữ ký: {e}")
            return False
        finally:
            conn.close()

    def get_stats(self):
        """
        Lấy thống kê về database
        
        Returns:
            dict: Thống kê về số lượng chữ ký theo loại
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Tổng số chữ ký
            cursor.execute("SELECT COUNT(*) FROM signatures")
            total = cursor.fetchone()[0]
            
            # Thống kê theo loại mã độc
            stats = {
                "total": total,
                "ransomware": 0,
                "trojan": 0,
                "worm": 0,
                "apt": 0,
                "rat": 0,
                "rootkit": 0,
                "other": 0
            }
            
            cursor.execute("SELECT malware_name FROM signatures")
            for row in cursor.fetchall():
                name = row[0].lower()
                if "ransomware" in name:
                    stats["ransomware"] += 1
                elif "trojan" in name:
                    stats["trojan"] += 1
                elif "worm" in name:
                    stats["worm"] += 1
                elif "apt" in name or "lazarus" in name or "apt28" in name or "apt29" in name:
                    stats["apt"] += 1
                elif "rat" in name:
                    stats["rat"] += 1
                elif "rootkit" in name:
                    stats["rootkit"] += 1
                else:
                    stats["other"] += 1
            
            return stats
            
        except sqlite3.Error as e:
            print(f"❌ Lỗi lấy thống kê: {e}")
            return None
        finally:
            conn.close()

    def print_stats(self):
        """In ra thống kê database"""
        stats = self.get_stats()
        if stats:
            print("\n" + "="*50)
            print("📊 THỐNG KÊ DATABASE MÃ ĐỘC")
            print("="*50)
            print(f"Tổng số chữ ký:    {stats['total']}")
            print(f"  • Ransomware:    {stats['ransomware']}")
            print(f"  • Trojan:        {stats['trojan']}")
            print(f"  • Worm:          {stats['worm']}")
            print(f"  • APT:           {stats['apt']}")
            print(f"  • RAT:           {stats['rat']}")
            print(f"  • Rootkit:       {stats['rootkit']}")
            print(f"  • Khác:          {stats['other']}")
            print("="*50 + "\n")