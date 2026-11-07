1. **Optimize Rate Limit Cleanup in `app/main.py`**
   - The current rate limiting cleanup loop at `login_for_access_token` iterates over `list(LOGIN_ATTEMPTS.keys())` and then fetches `ip_attempts = LOGIN_ATTEMPTS.get(ip, [])`.
   - Iterate over `list(LOGIN_ATTEMPTS.items())` instead to avoid redundant dictionary lookups. Also use `del` instead of `.pop(..., None)` when the key is guaranteed to exist.
   - Use `read_file` to verify the modified `app/main.py`.
2. **Run tests**
   - Run `python3 -m pytest tests/` to ensure nothing is broken.
3. **Add Learning to Journal**
   - Append to `.jules/bolt.md` detailing the learning that `list(dict.items())` is faster than `list(dict.keys())` coupled with `dict.get()` in hot paths, and only updating the list if it has actually changed minimizes dictionary mutations.
4. **Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.**
   - Run `pre_commit_instructions` and follow the steps.
5. **Submit the Pull Request**
   - Submit the changes using the commit title "⚡ Bolt: [performance improvement]".
