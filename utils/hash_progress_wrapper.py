class HashProgressWrapper:
    def __init__(self, progress_bar, hash_class):
        self.progress_bar = progress_bar
        self.hash_class = hash_class
        self.hash_obj = None

    def __call__(self, *args, **kwargs):
        self.hash_obj = self.hash_class(*args, **kwargs)
        return self

    def update(self, data):
        self.progress_bar.update(len(data))
        return self.hash_obj.update(data)

    def __getattr__(self, item):
        return getattr(self.hash_obj, item)
