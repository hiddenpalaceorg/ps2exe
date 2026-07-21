class DecompressionCounterMixin:
    """Progress counter lifecycle shared by container wrappers that
    decompress their contents (ArchiveWrapper, InstallShieldCabWrapper)"""

    BAR_FMT = '{desc} {file_name}{desc_pad}{percentage:3.0f}%|{bar}| ' \
              '{count:!.2j}{unit} / {total:!.2j}{unit} ' \
              '[{elapsed}<{eta}, {rate:!.2j}{unit}/s]'

    # Used instead of BAR_FMT whenever count exceeds total
    COUNTER_FMT = '{desc} {file_name}{desc_pad}{count:!.2j}{unit} / {total:!.2j}{unit} ' \
                  '[{elapsed}, {rate:!.2j}{unit}/s]{fill}'

    pbar = None
    counter = None

    def _create_counter(self, total):
        if self.pbar and not self.counter:
            self.counter = self.pbar.counter(
                total=total,
                desc="Decompressing",
                unit='B',
                leave=False,
                bar_format=self.BAR_FMT,
                counter_format=self.COUNTER_FMT,
                file_name=""
            )
        return self.counter

    def _close_counter(self):
        if not self.counter:
            return
        try:
            self.counter.update(incr=0, file_name="")
        except KeyError:
            pass
        try:
            if not self.counter._closed:
                self.counter.close()
        except KeyError:
            pass
        self.counter = None
