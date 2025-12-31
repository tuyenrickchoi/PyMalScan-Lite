import pefile
import datetime
import hashlib

def analyze_pe_header(filepath):
    """
    Phân tích PE Header chi tiết (giống VirusTotal Details tab).
    Trả về đầy đủ thông tin: Basic Properties, History, Imports, Sections, etc.
    """
    try:
        pe = pefile.PE(filepath)
        
        result = {
            "is_pe": True,
            "status": "success",
            "basic_properties": {},
            "history": {},
            "file_header": {},
            "optional_header": {},
            "sections": [],
            "imports": [],
            "exports": [],
            "resources": []
        }
        
        # ===== 1. BASIC PROPERTIES =====
        result["basic_properties"] = {
            "md5": None,  # Sẽ tính ở ngoài
            "sha1": None,
            "sha256": None,
            "ssdeep": None,  # Cần thư viện ssdeep (optional)
            "file_type": pe.FILE_HEADER.Machine,
            "magic": hex(pe.OPTIONAL_HEADER.Magic),
            "authenticode": None,  # Cần kiểm tra digital signature
            "packed": _check_if_packed(pe)
        }
        
        # ===== 2. HISTORY (Creation Time, Last Analysis) =====
        timestamp = pe.FILE_HEADER.TimeDateStamp
        compile_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
        
        result["history"] = {
            "creation_time": compile_time,
            "first_submission": None,  # Chỉ VirusTotal có
            "last_submission": None,
            "last_analysis": None
        }
        
        # ===== 3. FILE HEADER =====
        result["file_header"] = {
            "machine": _get_machine_type(pe.FILE_HEADER.Machine),
            "compilation_timestamp": compile_time,
            "target_machine": _get_machine_type(pe.FILE_HEADER.Machine),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "pointer_to_symbol_table": hex(pe.FILE_HEADER.PointerToSymbolTable),
            "number_of_symbols": pe.FILE_HEADER.NumberOfSymbols,
            "size_of_optional_header": pe.FILE_HEADER.SizeOfOptionalHeader,
            "characteristics": _parse_characteristics(pe.FILE_HEADER.Characteristics)
        }
        
        # ===== 4. OPTIONAL HEADER =====
        opt = pe.OPTIONAL_HEADER
        result["optional_header"] = {
            "magic": hex(opt.Magic),
            "linker_version": f"{opt.MajorLinkerVersion}.{opt.MinorLinkerVersion}",
            "size_of_code": opt.SizeOfCode,
            "size_of_initialized_data": opt.SizeOfInitializedData,
            "size_of_uninitialized_data": opt.SizeOfUninitializedData,
            "address_of_entry_point": hex(opt.AddressOfEntryPoint),
            "base_of_code": hex(opt.BaseOfCode),
            "image_base": hex(opt.ImageBase),
            "section_alignment": opt.SectionAlignment,
            "file_alignment": opt.FileAlignment,
            "os_version": f"{opt.MajorOperatingSystemVersion}.{opt.MinorOperatingSystemVersion}",
            "image_version": f"{opt.MajorImageVersion}.{opt.MinorImageVersion}",
            "subsystem_version": f"{opt.MajorSubsystemVersion}.{opt.MinorSubsystemVersion}",
            "size_of_image": opt.SizeOfImage,
            "size_of_headers": opt.SizeOfHeaders,
            "checksum": hex(opt.CheckSum),
            "subsystem": _get_subsystem_name(opt.Subsystem),
            "dll_characteristics": _parse_dll_characteristics(opt.DllCharacteristics)
        }
        
        # ===== 5. SECTIONS =====
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            section_data = {
                "name": section_name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": section.get_entropy(),
                "md5": section.get_hash_md5(),
                "characteristics": hex(section.Characteristics)
            }
            result["sections"].append(section_data)
        
        # ===== 6. IMPORTS (DLL & Functions) =====
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                functions = []
                
                for imp in entry.imports:  # Lưu TẤT CẢ functions, không giới hạn
                    if imp.name:
                        functions.append(imp.name.decode('utf-8', errors='ignore'))
                    else:
                        functions.append(f"Ordinal_{imp.ordinal}")
                
                result["imports"].append({
                    "dll": dll_name,
                    "functions": functions,  # Lưu tất cả
                    "total_functions": len(entry.imports)
                })
        
        # ===== 7. EXPORTS (nếu có) =====
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:50]:  # Giới hạn 50
                if exp.name:
                    result["exports"].append({
                        "name": exp.name.decode('utf-8', errors='ignore'),
                        "ordinal": exp.ordinal,
                        "address": hex(exp.address)
                    })
        
        # ===== 8. RESOURCES (nếu có) =====
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            result["resources"] = _parse_resources(pe.DIRECTORY_ENTRY_RESOURCE)
        
        return result
        
    except pefile.PEFormatError:
        return {"is_pe": False, "status": "Not a PE file"}
    except Exception as e:
        return {"is_pe": False, "status": "error", "message": str(e)}


# ===== HÀM PHỤ TRỢ =====

def _get_machine_type(machine_code):
    """Chuyển đổi Machine code thành tên"""
    machines = {
        0x14c: "IMAGE_FILE_MACHINE_I386 (x86)",
        0x8664: "IMAGE_FILE_MACHINE_AMD64 (x64)",
        0x1c0: "IMAGE_FILE_MACHINE_ARM",
        0xaa64: "IMAGE_FILE_MACHINE_ARM64"
    }
    return machines.get(machine_code, f"Unknown (0x{machine_code:x})")

def _get_subsystem_name(subsystem_code):
    """Chuyển đổi Subsystem code thành tên"""
    subsystems = {
        1: "IMAGE_SUBSYSTEM_NATIVE",
        2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
        3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
        7: "IMAGE_SUBSYSTEM_POSIX_CUI"
    }
    return subsystems.get(subsystem_code, f"Unknown ({subsystem_code})")

def _parse_characteristics(chars):
    """Giải mã File Characteristics"""
    flags = {
        0x0001: "RELOCS_STRIPPED",
        0x0002: "EXECUTABLE_IMAGE",
        0x0004: "LINE_NUMS_STRIPPED",
        0x0008: "LOCAL_SYMS_STRIPPED",
        0x0020: "LARGE_ADDRESS_AWARE",
        0x0100: "32BIT_MACHINE",
        0x0200: "DEBUG_STRIPPED",
        0x1000: "SYSTEM",
        0x2000: "DLL"
    }
    return [name for flag, name in flags.items() if chars & flag]

def _parse_dll_characteristics(chars):
    """Giải mã DLL Characteristics"""
    flags = {
        0x0040: "DYNAMIC_BASE (ASLR)",
        0x0080: "FORCE_INTEGRITY",
        0x0100: "NX_COMPAT (DEP)",
        0x0400: "NO_SEH",
        0x0800: "NO_BIND",
        0x2000: "WDM_DRIVER",
        0x8000: "TERMINAL_SERVER_AWARE"
    }
    return [name for flag, name in flags.items() if chars & flag]

def _check_if_packed(pe):
    """Kiểm tra xem file có bị pack không (dựa trên entropy cao)"""
    packed_indicators = 0
    
    for section in pe.sections:
        entropy = section.get_entropy()
        if entropy > 7.0:  # Entropy cao = có thể bị pack
            packed_indicators += 1
    
    # Kiểm tra tên section đáng ngờ
    suspicious_names = [b'UPX0', b'UPX1', b'.ASPack', b'.Themida']
    for section in pe.sections:
        if any(sus in section.Name for sus in suspicious_names):
            return "Yes (Suspicious section names detected)"
    
    if packed_indicators >= 2:
        return "Possibly (High entropy sections)"
    
    return "No"

def _parse_resources(resource_entry, level=0):
    """Phân tích Resource Directory (đệ quy)"""
    resources = []
    
    if level > 3:  # Giới hạn độ sâu
        return resources
    
    try:
        for entry in resource_entry.entries:
            if hasattr(entry, 'directory'):
                resources.extend(_parse_resources(entry.directory, level + 1))
            elif hasattr(entry, 'data'):
                resources.append({
                    "type": entry.name if entry.name else entry.id,
                    "size": entry.data.struct.Size,
                    "lang": entry.data.lang if hasattr(entry.data, 'lang') else None
                })
    except:
        pass
    
    return resources[:20]  # Giới hạn 20 resources