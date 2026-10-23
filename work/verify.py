import sys, io, json, tempfile, hashlib
from pathlib import Path
sys.path.append(str(Path('.venv/Lib/site-packages').resolve()))
from flask import Flask
sys.path.insert(0, str(Path.cwd()))
from app.routes import bp
from app.db import init_db, get_db
from PIL import Image
root=Path('.').resolve()
with tempfile.TemporaryDirectory(dir=root/'work') as tmp:
 app=Flask('verification',root_path=str(root/'app'));app.config.update(TESTING=True,SECRET_KEY='test',DATABASE=str(Path(tmp)/'test.db'),ENCRYPTED_STORAGE=str(Path(tmp)/'encrypted'));app.register_blueprint(bp)
 with app.app_context():init_db()
 c=app.test_client();other=app.test_client();anon=app.test_client()
 for client,user in [(c,'candidate'),(other,'other')]:
  assert client.post('/register',data={'username':user,'password':'test-password'}).status_code==302
  assert client.post('/login',data={'username':user,'password':'test-password'}).status_code==302
 for path in ['/files','/personal','/decrypt','/benchmark']:
  assert c.get(path).status_code==200,path
  assert anon.get(path).status_code==302,path
 assert c.get('/dashboard',follow_redirects=True).request.path=='/files'
 profile={'full_name':'Kandidat Uji','birth_date':'2000-01-01','phone':'0812345','address':'Jakarta','email':'uji@example.com'}
 assert c.post('/personal',data=profile).status_code==302
 for alg in ['aes','des','rc4']:
  response=c.get('/personal/1/'+alg);assert json.loads(response.data)==profile
  assert other.get('/personal/1/'+alg).status_code==404
  assert anon.get('/personal/1/'+alg).status_code==302
 image=io.BytesIO();Image.new('RGB',(16,16),'green').save(image,'PNG')
 samples=[('ktp.png',image.getvalue()),('cv.pdf',b'%PDF-1.4\nCV test\n%%EOF'),('lamaran.docx',b'PK\x03\x04 office bytes'),('portofolio.xlsx',b'PK\x03\x04 spreadsheet bytes'),('perkenalan.mp4',b'\x00\x00\x00\x18ftypmp42 video bytes')]
 for fid,(name,data) in enumerate(samples,1):
  assert c.post('/upload',data={'file':(io.BytesIO(data),name)}).status_code==302
  for alg in ['aes','des','rc4']:
   path=f'/file/{fid}/{alg}'
   response=c.get(path);assert response.status_code==200 and response.data==data,(name,alg)
   assert other.get(path).status_code==404
   assert anon.get(path).status_code==302
   assert other.get(path+'/encrypted?format=enc').status_code==404
   package=c.get(path+'/encrypted?format=enc');assert package.status_code==200
   assert other.post('/decrypt',data={'file':(io.BytesIO(package.data),'file.enc')}).status_code==403
   decoded=c.post('/decrypt',data={'file':(io.BytesIO(package.data),'file.enc')});assert decoded.data==data
  assert name.encode() not in other.get('/files').data
 assert c.post('/benchmark',data={'file':(io.BytesIO(b'benchmark'),'test.pdf'),'repeats':'2'}).status_code==200
 assert c.post('/decrypt',data={'file':(io.BytesIO(b'bad'),'bad.enc')},follow_redirects=True).status_code==200
 print('PASS: auth, all pages, legacy redirect, profile x3, 5 file types x3, byte-exact recovery, portable exports, account isolation, benchmark, invalid export.')

