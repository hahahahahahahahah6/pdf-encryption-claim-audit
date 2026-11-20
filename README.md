# Documentation claim auditor

This offline static auditor compares documentation of the checked capability with Python source patterns. It scans the root README and Markdown under docs. Fenced code is excluded; inline code counts. Source is parsed without execution. Tests are reported separately; fixtures, examples, documentation and symlinks are excluded from production evidence.

```sh
pdf-encryption-claim-audit audit . --json --fail-on medium --ignore vendor/
python3 -m pdf_encryption_claim_audit --version
```

Exit 0 means PASS, 2 means a finding meets the threshold, and 1 means a usage or I/O error. The default threshold is high. Ignore prefixes can be repeated.

```
documented-pdf-encryption-claim-false
documented-no-pdf-encryption-claim-false
```

## Differentiation

The checked operation is distinct from document extraction, generation, merging and splitting, spreadsheet, word processing and presentation reading or generation, table and other document extraction, invoice separation, multiple receipt detection, document cropping, electronic signatures, payment processing and OCR. These other claim categories are outside the phrase lists.

## Limitations

- A phrase about the checked capability may describe the status of a file that is only read.
- A phrase may describe an embedded attachment instead of the file itself.
- A phrase may describe a wrapper that never performs the checked operation.
- A phrase may refer to a viewer session or download link password.
- A phrase may describe only checking whether a file is protected.
- A phrase may describe an external command; subprocess calls are not detected and a command-only implementation is flagged.
- A phrase may describe only reporting protection status.
- A writer construction and an unrelated encrypt method call in one module count together.
- A PyMuPDF opener and an unrelated save call with the relevant keyword in one module count together.
- A pikepdf opener and an unrelated save call with a constructed settings value in one module count together.
- The writer pair counts even with empty passwords.
- The PyMuPDF pair counts even when the keyword value disables protection.
- The PyMuPDF pair counts even when saving to the same filename.
- The pikepdf pair counts even with empty passwords in the settings object.
- A writer construction alone is not detected.
- A writer construction and write call alone are not detected.
- An encrypt method call alone is not detected without a matching writer construction in the same module.
- A save call with the relevant keyword alone is not detected without a PyMuPDF opener in the same module.
- A save call with constructed settings alone is not detected without a pikepdf opener in the same module.
- A PyMuPDF opener and save call without the relevant keyword are not detected.
- A PyMuPDF saveIncr call is not detected because it preserves existing protection.
- A pikepdf save call with True as the keyword value is not detected.
- A pikepdf save call with False as the keyword value is not detected.
- A pikepdf save call with None as the keyword value is not detected.
- A pikepdf save call with a variable or literal as the keyword value is not detected.
- A settings construction alone is not detected.
- A reader's decrypt call is not detected because it performs the inverse operation.
- Generic byte encryption, including Fernet, AES, hashing and password hashing, is not detected.
- A writer and add_page call alone are not detected.
- A writer and append or merge call alone are not detected.
- A PyMuPDF opener and insert_pdf call alone are not detected.
- A pikepdf pages.extend call alone is not detected.
- A pdfrw addpage or addpages call alone is not detected.
- A reader call alone is not detected.
- Document generation alone is not detected.
- Document merging alone is not detected.
- Document splitting alone is not detected.
- Document extraction alone is not detected.
- qpdf, pdftk and Ghostscript subprocess calls are not detected.
- Mindee parsing with any product is not detected.
- Azure document analysis with any model ID is not detected.
- Veryfi calls of any kind are not detected.
- Google Document AI processing with any processor is not detected.
- Eden AI universal-ai calls with any model ID are not detected.
- Textract calls of any kind are not detected.
- LlamaParse calls are not detected.
- Nanonets, Docsumo, ABBYY Vantage, Rossum, Klippa, Parseur and Extend calls are not detected because their identifiers or endpoints are opaque.
- A hand-built implementation using raw object streams is not detected without a listed call.
- Detection does not establish password strength: weak RC4 and stronger AES settings both count.
- Static matching cannot judge semantics, and dead code counts.
- Alias chains beyond the tracer are missed.
- Only exact phrases count, and denial handling depends on the listed phrases.
- Each paired route must occur in a single module.
