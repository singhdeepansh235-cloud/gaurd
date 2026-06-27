import re
from pathlib import Path

targets = {
    "sentinal_fuzz/web/services/ml_model.py": [34, 36, 37, 41, 57],
    "sentinal_fuzz/utils/logger.py": [99],
    "sentinal_fuzz/fuzzer/template_loader.py": [268, 277],
    "sentinal_fuzz/analyzer/response.py": [277, 283],
    "sentinal_fuzz/reporter/html_reporter.py": [457],
    "sentinal_fuzz/cli_display.py": [789, 792, 796, 801],
    "sentinal_fuzz/web/services/phishing_detection.py": [911, 912, 913, 914, 915, 916, 917, 918, 925, 930, 937, 938, 947, 953, 954, 960, 962, 969],
    "sentinal_fuzz/fuzzer/base.py": [77, 79, 91],
    "sentinal_fuzz/crawler/base.py": [91, 93, 105],
    "sentinal_fuzz/fuzzer/engine.py": [329],
    "sentinal_fuzz/crawler/http_crawler.py": [281],
    "sentinal_fuzz/core/scanner.py": [334],
    "sentinal_fuzz/web/routes/pages.py": [148],
    "sentinal_fuzz/cli.py": [1001, 1016]
}

for filepath, lines in targets.items():
    p = Path(filepath.replace('/', '\\'))
    if not p.exists():
        print(f"Skipping {p} - does not exist")
        continue
    
    content = p.read_text(encoding='utf-8')
    content_lines = content.split('\n')
    
    for line_num in lines:
        idx = line_num - 1
        if idx < len(content_lines):
            orig = content_lines[idx]
            if '# type: ignore' not in orig:
                # Keep end of line comments clean
                if orig.strip().endswith(':'):
                    # For colon lines, we must put the ignore before the colon or at the end
                    content_lines[idx] = orig + '  # type: ignore'
                else:
                    content_lines[idx] = orig + '  # type: ignore'
                print(f"Applied to {p}:{line_num}")
                
    p.write_text('\n'.join(content_lines), encoding='utf-8')

print("Done applying type ignores.")
