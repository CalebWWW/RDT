import threading


class ExThread(threading.Thread):
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, t, val, tb):
        self.join()

    def run(self, *args, **kwargs):
        self._exc = None
        try:
            super().run(*args, **kwargs)
        except Exception as ex:
            self._exc = ex
            raise

    def join(self, *args, **kwargs):
        super().join(*args, **kwargs)
        assert not self._exc, 'failure in subthread'
