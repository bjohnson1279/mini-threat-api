## 2024-05-24 - FastAPI Response Compression
**Learning:** Threat intelligence JSON payloads often contain highly repetitive string keys and values (e.g., indicator types, severities, long descriptions) which compress exceptionally well. Adding GZip compression can result in massive payload size reductions (up to 94%).
**Action:** Always consider adding `GZipMiddleware` to FastAPI services returning large lists of homogeneous JSON objects, configuring a `minimum_size` to avoid compressing small, fast responses.
