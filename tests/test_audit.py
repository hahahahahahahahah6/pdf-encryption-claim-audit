EXPECTED_YES = ('encrypt pdf', 'encrypts pdf', 'encrypting pdf', 'encrypt pdfs', 'encrypts pdfs', 'encrypting pdfs', 'encrypt pdf file', 'encrypts pdf file', 'encrypting pdf file', 'encrypt pdf files', 'encrypts pdf files', 'encrypting pdf files', 'encrypt pdf document', 'encrypts pdf document', 'encrypting pdf document', 'encrypt pdf documents', 'password protect pdf', 'password protects pdf', 'password protecting pdf', 'password protect pdfs', 'password protects pdfs', 'password protecting pdfs', 'password protect pdf file', 'password protects pdf file', 'password protecting pdf file', 'password protect pdf files', 'password protects pdf files', 'password protecting pdf files', 'password protect pdf document', 'password protects pdf document', 'password protecting pdf document', 'password protect pdf documents', 'encrypt pdf with password', 'encrypts pdf with password', 'encrypting pdf with password', 'encrypt pdfs with password', 'encrypts pdfs with password', 'pdf encryptor', 'pdf encryption', 'pdf password protection', 'encrypt a pdf', 'encrypts a pdf', 'encrypting a pdf', 'encrypt one pdf', 'password protect a pdf', 'password protects a pdf', 'password protecting a pdf', 'set pdf password', 'sets pdf password', 'setting pdf password')
EXPECTED_NO = ('no pdf encryption', 'does not encrypt pdf', 'does not encrypt pdfs', 'does not encrypt pdf files', 'does not encrypt pdf document', 'does not encrypt pdf documents', 'does not password protect pdf', 'does not password protect pdfs', 'does not password protect pdf files', 'does not password protect pdf document', 'no pdf password protection', 'does not support pdf encryption', 'without pdf encryption', 'pdf encryption not supported', 'no pdf encryption support', 'does not encrypt a pdf', 'does not encrypt pdf with password', 'does not set pdf password', 'no pdf encryptor', 'does not encrypt one pdf', 'does not password protect a pdf', 'does not encrypt pdf file', 'does not password protect pdf documents', 'does not encrypt pdfs with password')
EXPECTED_NAMES = ('encrypt_pdf', 'encrypt_pdfs', 'encrypt_pdf_file', 'encrypt_pdf_files', 'encrypt_pdf_document', 'encrypt_pdf_documents', 'password_protect_pdf', 'password_protect_pdfs', 'password_protect_pdf_file', 'password_protect_pdf_files', 'password_protect_pdf_document', 'password_protect_pdf_documents', 'encrypt_pdf_with_password', 'password_protect_pdf_with_password', 'set_pdf_password', 'pdf_encryptor', 'pdf_encrypt', 'encrypt_pdf_pages', 'encrypt_pdf_content', 'encrypt_pdf_data', 'secure_pdf', 'secure_pdfs', 'secure_pdf_file', 'secure_pdf_files')
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from pdf_encryption_claim_audit.audit import audit, evidence
from pdf_encryption_claim_audit.phrases import PDFENCRYPTION, NOPDFENCRYPTION, GENERIC_NAMES
from pdf_encryption_claim_audit.__main__ import main

class AuditTests(unittest.TestCase):
    def test_phrase_oracle(self):
        self.assertEqual(PDFENCRYPTION, EXPECTED_YES)
        self.assertEqual(NOPDFENCRYPTION, EXPECTED_NO)
        self.assertEqual(GENERIC_NAMES, EXPECTED_NAMES)

    def test_routes(self):
        cases = [
            'from pypdf import PdfWriter as W\nW(); x.encrypt()',
            'import pypdf\npypdf.PdfWriter(); x.encrypt()',
            'import pypdf as p\np.PdfWriter(); x.encrypt()',
            'from PyPDF2 import PdfWriter\nPdfWriter(); x.encrypt()',
            'import PyPDF2\nPyPDF2.PdfWriter(); x.encrypt()',
            'from PyPDF2 import PdfFileWriter\nPdfFileWriter(); x.encrypt()',
        ]
        for module in ('fitz', 'pymupdf'):
            for method in ('open', 'Document'):
                cases += [f'import {module}\n{module}.{method}(); x.save(encryption=1)',
                          f'from {module} import {method} as op\nop(x); x.save(encryption=constant)']
        cases += ['import fitz\nfitz.open(x); x.save(encryption=fitz.PDF_ENCRYPT_NONE)']
        for method in ('open', 'new'):
            for opener in (f'pikepdf.Pdf.{method}', f'pikepdf.{method}'):
                cases.append(f'import pikepdf\nfrom pikepdf import Encryption as E\n{opener}(x); x.save(encryption=E())')
            cases.append(f'from pikepdf import {method} as op, Encryption\nop(x); x.save(encryption=Encryption())')
        cases += ['import pikepdf\npikepdf.Pdf.open(x); x.save(encryption=pikepdf.Encryption())',
                  'from pikepdf import Pdf as P, Encryption\nP.new(); x.save(encryption=Encryption())',
                  'from other import encrypt_pdf as f\nf()']
        cases += ['x.' + name + '()' for name in EXPECTED_NAMES]
        for source in cases:
            with self.subTest(source=source): self.assertTrue(evidence(source))

    def test_not_evidence(self):
        cases = ['import '+x for x in ('pypdf','PyPDF2','fitz','pymupdf','pikepdf')]
        cases += ['import pypdf\npypdf.PdfWriter()', 'x.encrypt()', 'import pypdf\npypdf.PdfWriter().write(x)',
                  'import pypdf\npypdf.PdfReader(x).decrypt(x)', 'import PyPDF2\nPyPDF2.PdfReader(x).decrypt(x)',
                  'import pypdf\npypdf.PdfWriter().add_page(x)', 'import PyPDF2\nPyPDF2.PdfWriter().append(x)',
                  'import PyPDF2\nPyPDF2.PdfWriter().merge(x)', 'import fitz\nfitz.open(x)', 'import fitz\nfitz.open()',
                  'x.save(encryption=1)', 'import fitz\nfitz.open(x).save(x)', 'import fitz\nfitz.open(x).saveIncr()',
                  'import pikepdf\npikepdf.Pdf.open(x)', 'import pikepdf\npikepdf.new()',
                  'from pikepdf import Encryption\nx.save(encryption=Encryption())',
                  'import pikepdf\npikepdf.open(x); x.save()', 'from pikepdf import Encryption\nEncryption()',
                  'import pikepdf\npikepdf.open(); x.save(encryption=pikepdf.Encryption())',
                  'import cryptography\nx.encrypt(x)', 'hashlib.sha256(x)', 'bcrypt.hashpw(x,y)',
                  'import pypdf\npypdf.PdfReader(x)', 'pdfplumber.open(x)', 'extract_text(x)',
                  'reportlab.Canvas(x).save()', 'import fitz\nfitz.open().insert_text(x); x.save()',
                  'import pikepdf\npikepdf.open(x); x.pages.extend(y)', 'pdfrw.addpages(x)',
                  '"pdf encrypt password"', 'x.encrypt_pdf', 'def encrypt_pdf(): pass\nx.encrypt_pdf()',
                  'import pypdf\npypdf=1\npypdf.PdfWriter(); x.encrypt()',
                  'from pypdf import PdfWriter\nwith x as PdfWriter: pass\nPdfWriter(); x.encrypt()',
                  'def broken(']
        cases += [f'import pikepdf\npikepdf.open(x); x.save(encryption={v})' for v in ('True','False','None','value','42','other()')]
        cases += ['import subprocess\nsubprocess.run(["'+x+'", "x"])' for x in ('qpdf','pdftk','gs')]
        cases += [x+'(x)' for x in ('mindee.parse','azure.begin_analyze_document','veryfi.Client','documentai.process_document','textract.analyze_document','eden.universal_ai','llamaparse.parse','nanonets.ocr','docsumo.upload','abbyy.process','rossum.process','klippa.parse','parseur.parse','extend.parse')]
        for source in cases:
            with self.subTest(source=source): self.assertFalse(evidence(source))

    def test_audit_scenarios(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); readme=p/'README.md'; src=p/'app.py'
            readme.write_text('encrypt pdf files'); r=audit(d); self.assertEqual(r['findings'][0]['rule'],'documented-pdf-encryption-claim-false'); self.assertEqual(r['verdict'],'FAIL')
            src.write_text('import fitz\nfitz.open(); d.save(encryption=1)'); self.assertEqual(audit(d)['verdict'],'PASS')
            readme.write_text('does not encrypt pdf files'); r=audit(d); self.assertEqual(r['findings'][0]['rule'],'documented-no-pdf-encryption-claim-false'); self.assertEqual(r['claims'],[])
            src.unlink(); self.assertEqual(audit(d)['verdict'],'PASS')
            readme.write_text('```\nencrypt pdf files\n```'); self.assertEqual(audit(d)['verdict'],'PASS')
            readme.write_text('`encrypt pdf files`'); self.assertEqual(audit(d)['verdict'],'FAIL')
            (p/'tests').mkdir(); (p/'tests/test_app.py').write_text('import fitz\nfitz.open(); d.save(encryption=1)')
            self.assertEqual(audit(d)['findings'][0]['severity'],'MEDIUM'); self.assertEqual(audit(d)['verdict'],'PASS'); self.assertEqual(audit(d, fail_on='medium')['verdict'],'FAIL')
            src.write_text('import fitz\nfitz.open()'); (p/'other.py').write_text('x.save(encryption=1)'); self.assertEqual(audit(d)['findings'][0]['severity'],'MEDIUM')
            readme.write_text('Nothing claimed'); self.assertEqual(audit(d)['verdict'],'PASS')

    def test_exclusions(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); (p/'README.md').write_text('encrypt pdf')
            for name in ('fixtures','examples','docs'):
                (p/name).mkdir(); (p/name/'code.py').write_text('x.encrypt_pdf()')
            (p/'test_file.py').write_text('x.encrypt_pdf()'); (p/'app_test.py').write_text('x.encrypt_pdf()')
            (p/'link.py').symlink_to(p/'test_file.py'); (p/'linked').symlink_to(p/'fixtures', target_is_directory=True)
            r=audit(d); self.assertFalse(r['production_evidence']); self.assertEqual(len(r['test_evidence']),2)
            self.assertEqual(audit(d, ignore=('test_', 'app_'))['findings'][0]['severity'],'HIGH')

    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); (p/'README.md').write_text('encrypt pdf')
            cmd=[sys.executable, '-m', 'pdf_encryption_claim_audit']
            r=subprocess.run(cmd+['audit',d,'--json'],capture_output=True,text=True); self.assertEqual(r.returncode,2)
            data=json.loads(r.stdout); self.assertEqual(data['verdict'],'FAIL'); self.assertTrue(data['findings'][0]['message'])
            self.assertEqual(subprocess.run(cmd+['--version'],capture_output=True,text=True).stdout.strip(),'0.1.0')
            self.assertEqual(subprocess.run(cmd+['audit',d,'--fail-on','HIGH'],capture_output=True).returncode,1)
            self.assertEqual(subprocess.run(cmd+['audit',d+'/missing'],capture_output=True).returncode,1)
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(main(['audit',d]),2)
            (p/'README.md').write_text('does not encrypt pdf'); (p/'app.py').write_text('x.encrypt_pdf()')
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(main(['audit',d]),2)
            (p/'app.py').unlink(); (p/'README.md').write_text('encrypt pdf'); (p/'test_app.py').write_text('x.encrypt_pdf()')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['audit',d]),0); self.assertEqual(main(['audit',d,'--fail-on','medium']),2)
