try:
    from ghidra.base.project import GhidraProject
    GhidraProject.getServerRepository("127.0.0.1", 0, getScriptArgs()[0], True)
except:
    import os, traceback
    on_fail = os.environ.get("ON_FAIL")
    if on_fail is not None:
        with open(on_fail, 'w') as fp:
            traceback.print_exc(file=fp)
