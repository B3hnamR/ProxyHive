"""Writes the Windows "Details" tab data (name, author, version) for ProxyHive.exe. The version comes from proxyhive/__init__.py.

Usage: python scripts/make_version_info.py <output file>
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
version = re.search(r'__version__ = "([^"]+)"', (ROOT / "proxyhive" / "__init__.py").read_text(encoding="utf-8")).group(1)
nums = (version.split(".") + ["0", "0", "0"])[:3]
tup = ", ".join(nums + ["0"])

TEXT = f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(filevers=({tup}), prodvers=({tup}), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'B3hnamR'),
      StringStruct('FileDescription', 'ProxyHive - find, test and use proxies'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', 'ProxyHive'),
      StringStruct('LegalCopyright', 'B3hnamR  https://github.com/B3hnamR  https://t.me/B3hnamR'),
      StringStruct('OriginalFilename', 'ProxyHive.exe'),
      StringStruct('ProductName', 'ProxyHive'),
      StringStruct('ProductVersion', '{version}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""

out = Path(sys.argv[1])
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(TEXT, encoding="utf-8")
print(f"version info {version} -> {out}")
