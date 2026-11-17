"""영업 모바일 시안 → 잠근 배포 파일(app.enc · slot.json) 만들기.

쓰는 법:  A1PW='회사 비밀번호' python3 build.py 시안.html  (출력 = 이 폴더의 app.enc · slot.json)
- 내용 열쇠는 비밀번호 + csalt(slot.json에 공개)로 만든다 → 비밀번호가 같으면 다시 만들어도 열쇠가 같아,
  '다음부터 묻지 않기'로 저장한 폰이 업데이트 뒤에도 그대로 열린다. 비밀번호를 바꾸면 모두 다시 묻는다.
- 비밀번호는 파일·저장소·기록 어디에도 남기지 않는다(환경변수로만 받음).
"""
import base64, gzip, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 300000
here = os.path.dirname(os.path.abspath(__file__))
pw = os.environ.get('A1PW', '')
if not pw:
    sys.exit('A1PW 환경변수에 비밀번호를 넣어 주세요')
src = sys.argv[1]
slot_path = os.path.join(here, 'slot.json')
old = json.load(open(slot_path)) if os.path.exists(slot_path) else {}
csalt = base64.b64decode(old['csalt']) if 'csalt' in old else os.urandom(16)

def kdf(salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode('utf-8'))

ckey = kdf(csalt)                       # 내용 열쇠(비밀번호가 같으면 늘 같음)
html = open(src, 'rb').read()
iv = os.urandom(12)
body = AESGCM(ckey).encrypt(iv, gzip.compress(html, 9, mtime=0), None)
open(os.path.join(here, 'app.enc'), 'wb').write(iv + body)

salt, wiv = os.urandom(16), os.urandom(12)
ct = AESGCM(kdf(salt)).encrypt(wiv, ckey, None)
b = lambda x: base64.b64encode(x).decode()
json.dump({'salt': b(salt), 'iv': b(wiv), 'iter': ITER, 'ct': b(ct), 'csalt': b(csalt)}, open(slot_path, 'w'))
print('app.enc', len(iv + body), 'bytes · slot.json ok')
