1. **Optimize `list_iocs` query in `app/main.py`**
   - The query `db.query(Indicator).filter(Indicator.confidence_score >= min_confidence)` is evaluated even when `min_confidence` is 0, which is the default. Since all confidence scores are guaranteed to be >= 0 (by validation and data type), this filter is completely redundant when `min_confidence == 0`. We will conditionally apply the filter only when `min_confidence > 0`.
   - This avoids processing a no-op WHERE clause on the database side for the default query.
2. **Pre-commit Steps**
   - Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.
3. **Submit**
   - Submit the changes using the commit title "⚡ Bolt: [performance improvement]".
