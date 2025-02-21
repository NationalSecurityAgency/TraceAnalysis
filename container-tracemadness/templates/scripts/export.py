try:
    from ghidra.framework.main import AppInfo
    from ghidra.framework.model import ProjectLocator
    from ghidra.framework.protocol.ghidra import GhidraURL
    from ghidra.util.task import TaskMonitor
    args = getScriptArgs()
    proj = AppInfo.getActiveProject()
    local_data = proj.getProjectData()
    dst = local_data.getRootFolder()
    if len(args) < 3:
        url = GhidraURL.makeURL("127.0.0.1", 0, args[0])
    else:
        url = ProjectLocator(args[0], args[1]).getURL()
    proj.addProjectView(url, True)
    remote_data = proj.getViewedProjectData()[0]
    if len(args) < 3:
        remote_data.getFolder(args[1]).copyTo(dst, TaskMonitor.DUMMY)
    else:
        remote_data.getFolder(args[2]).copyTo(dst, TaskMonitor.DUMMY)        
except:
    import os, traceback
    on_fail = os.environ.get("ON_FAIL")
    if on_fail is not None:
        with open(on_fail, 'w') as fp:
            traceback.print_exc(file=fp)
