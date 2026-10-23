import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
sys.path.append(str(Path('.venv/Lib/site-packages').resolve()))
from flask import Flask
from app.db import init_db
from app.routes import bp
from app.evaluation import evaluate, timing_stats, MAX_INPUT

class EvaluationTests(unittest.TestCase):
    def test_stats(self):
        stats = timing_stats([1, 2, 3, 4, 5], 1048576)
        self.assertEqual(stats['median_ms'], 3)
        self.assertEqual(stats['p95_ms'], 5)
        self.assertAlmostEqual(stats['throughput_mib_s'], 1000 / 3)

    def test_crypto_boundaries(self):
        for size in (1, 8, 16, 17, 4096):
            report = evaluate(bytes(range(256)) * (size // 256) + bytes(range(size % 256)), 'input.bin', 5)
            self.assertEqual(len(report['rows']), 3)
            for row in report['rows']:
                self.assertEqual(row['correct_count'], 5)
                self.assertEqual(row['original_sha256'], row['restored_sha256'])
                self.assertTrue(row['package_tamper_rejected'])
                self.assertFalse(row['wrong_key']['equals_original'])
                self.assertEqual(len(row['samples_encrypt_ms']), 5)
                self.assertEqual(row['ciphertext_bytes'], size if row['name'] == 'RC4' else ((size // (16 if row['name'] == 'AES' else 8)) + 1) * (16 if row['name'] == 'AES' else 8))
                self.assertEqual(row['same_ciphertext'], row['name'] == 'RC4')

    def test_bounds(self):
        for data, repeats in ((b'', 5), (b'one', 4), (b'one', 101), (b'x' * (MAX_INPUT + 1), 5), (b'x' * MAX_INPUT, 100)):
            with self.assertRaises(ValueError): evaluate(data, 'test.bin', repeats)

    def test_developer_routes(self):
        root = Path.cwd()
        with tempfile.TemporaryDirectory(dir=root/'work') as directory:
            app = Flask('evaluation_test', root_path=str(root/'app'))
            app.config.update(TESTING=True, SECRET_KEY='test', DATABASE=str(Path(directory)/'db.sqlite'), DEVELOPER_USERNAMES=('dev',))
            app.register_blueprint(bp)
            with app.app_context(): init_db()
            client = app.test_client()
            self.assertEqual(client.get('/developer/evaluation').status_code, 302)
            with client.session_transaction() as state: state.update(user_id=1, username='ordinary')
            self.assertEqual(client.get('/developer/evaluation').status_code, 403)
            with client.session_transaction() as state: state.update(username='dev')
            response = client.get('/developer/evaluation')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            with client.session_transaction() as state: token = state['evaluation_csrf']
            self.assertEqual(client.post('/developer/evaluation', data={'repeats':'5'}).status_code, 400)
            fields = {'csrf_token':token, 'source':'sample', 'sample_size':'1024', 'repeats':'5'}
            response = client.post('/developer/evaluation', data=fields)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'fixture', response.data)
            fields['output'] = 'json'
            response = client.post('/developer/evaluation', data=fields)
            self.assertEqual(response.status_code, 200)
            report = json.loads(response.data)
            self.assertTrue(all(check['passed'] for check in report['authorization']))
            self.assertEqual(len(report['authorization']), 22)
            self.assertEqual(report['size'], 1024)
            self.assertNotIn('AES_KEY', response.text)
            fields.update(source='upload', file=(io.BytesIO(b'candidate document'), 'cv.pdf'))
            report = json.loads(client.post('/developer/evaluation', data=fields).data)
            self.assertEqual(report['size'], len(b'candidate document'))
            self.assertEqual(report['filename'], 'cv.pdf')
            fields.pop('file')
            fields.update(repeats='invalid')
            response = client.post('/developer/evaluation', data=fields)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'role="alert"', response.data)
            fields.update(repeats='5', file=(io.BytesIO(b'x' * (MAX_INPUT + 1)), 'too-large.bin'))
            response = client.post('/developer/evaluation', data=fields)
            self.assertIn(b'role="alert"', response.data)

if __name__ == '__main__': unittest.main(verbosity=2)
