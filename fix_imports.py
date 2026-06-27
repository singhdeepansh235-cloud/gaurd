import os

files = [
    'sentinal_fuzz/web/app.py',
    'sentinal_fuzz/web/routes/pages.py',
    'sentinal_fuzz/web/routes/api.py',
    'sentinal_fuzz/web/routes/ws.py',
    'sentinal_fuzz/__init__.py',
    'tests/test_js_crawler.py'
]

for f in files:
    if not os.path.exists(f): continue
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Fix from __future__
    if 'from typing import Any\n"""' in content:
        content = content.replace('from typing import Any\n', '')
        content = content.replace('from __future__ import annotations', 'from __future__ import annotations\nfrom typing import Any')
    elif 'from typing import Any\nfrom __future__ import annotations' in content:
        content = content.replace('from typing import Any\nfrom __future__ import annotations', 'from __future__ import annotations\nfrom typing import Any')
    elif 'from __future__ import annotations' in content and 'from typing import Any' in content:
        # If it's already there but the order is wrong
        lines = content.split('\n')
        future_idx = -1
        typing_idx = -1
        for i, line in enumerate(lines):
            if 'from __future__ import annotations' in line: future_idx = i
            if 'from typing import Any' == line: typing_idx = i
        
        if typing_idx != -1 and future_idx != -1 and typing_idx < future_idx:
            lines.pop(typing_idx)
            future_idx = lines.index('from __future__ import annotations')
            lines.insert(future_idx + 1, 'from typing import Any')
            content = '\n'.join(lines)
            
    # Fix test_js_crawler urls definition
    if f == 'tests/test_js_crawler.py':
        # Let's ensure the urls definition is present after await crawler.crawl
        content = content.replace(
            'endpoints = await crawler.crawl(test_server)\n        assert',
            'endpoints = await crawler.crawl(test_server)\n        urls = {ep.url for ep in endpoints}\n        assert'
        )
        content = content.replace(
            'endpoints = await crawler.crawl(f"{test_server}/spa-app")\n        # The SPA',
            'endpoints = await crawler.crawl(f"{test_server}/spa-app")\n        urls = {ep.url for ep in endpoints}\n        # The SPA'
        )
            
    with open(f, 'w', encoding='utf-8') as file:
        file.write(content)
        
print("Imports and urls fixed.")
