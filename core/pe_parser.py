import pefile
from sixeyes.core.entropy import calculate_entropy

def analyze_pe(file_path: str) -> dict:
    """Basic structural parser for PE files leveraging the pefile library."""
    report = {"is_pe": False, "sections": [], "suspicious_imports": []}
    
    # Common APIs heavily utilized by malware for injection, evasion, or persistence
    sus_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "RegSetValueExA", "CryptoAPI"]
    
    try:
        pe = pefile.PE(file_path)
        report["is_pe"] = True
        
        # 1. Analyze PE sections and calculate individual entropy levels
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            sec_data = section.get_data()
            sec_entropy = calculate_entropy(sec_data)
            
            report["sections"].append({
                "name": sec_name,
                "virtual_size": hex(section.Misc_VirtualSize),
                "entropy": sec_entropy,
                "packed": sec_entropy > 7.2
            })
            
        # 2. Inspect the Import Address Table (IAT) for suspicious APIs
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        if any(api in func_name for api in sus_apis):
                            report["suspicious_imports"].append(func_name)
                            
        pe.close()
    except pefile.PEFormatError:
        # File is not a valid Windows executable (could be a script, ELF, PDF, etc.)
        pass
    except Exception as e:
        report["error"] = f"Error parsing PE structures: {str(e)}"
        
    return report
