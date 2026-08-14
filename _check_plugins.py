import requests
import urllib.request as _urq
import os as _os

plugins = ['analytics-insights', 'analytics-insights-google-analytics', 'analytics']
for p in plugins:
    url = 'https://downloads.wordpress.org/plugin/%s.6.2.zip' % p
    r = requests.get(url, timeout=5, allow_redirects=True)
    print('%s: %d' % (p, r.status_code))
    if r.status_code == 200:
        _urq.urlretrieve(url, './test.zip')
        print('  Downloaded: %d bytes' % _os.path.getsize('test.zip'))
        _os.remove('test.zip')
