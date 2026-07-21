class HashProgressWrapper:
    def __init__(self, progress_bar, hash_class):
        self.progress_bar = progress_bar
        self.hash_class = hash_class
        self.hash_obj = None

    def __call__(self, *args, **kwargs):
        self.hash_obj = self.hash_class(*args, **kwargs)
        return self

    def update(self, data):
        result = self.hash_obj.update(data)
        try:
            self.progress_bar.update(len(data))
        except Exception:
            # A progress display failure must not abort or truncate hashing
            pass
        return result

    def __getattr__(self, item):
        return getattr(self.hash_obj, item)
