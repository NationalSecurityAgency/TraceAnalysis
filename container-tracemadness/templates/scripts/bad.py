try:
    bad()
except:
    import os, traceback
    on_fail = os.environ.get("ON_FAIL")
    if on_fail is not None:
        with open(on_fail, 'w') as fp:
            traceback.print_exc(file=fp)
