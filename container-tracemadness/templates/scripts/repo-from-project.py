try:
    from ghidra.framework.main import AppInfo
    from ghidra.framework.model import ProjectLocator
    from ghidra.base.project import GhidraProject

    def dirwalk(root):
        files = []
        stack = [root]
        while len(stack) > 0:
            top = stack.pop()
            stack.extend(top.getFolders())
            files.extend(top.getFiles())
        return files


    args = getScriptArgs()
    project = AppInfo.getActiveProject()
    manager = project.getProjectManager()
    locator = project.getProjectLocator()

    # Copy the target folder from provided project to this project
    project.addProjectView(ProjectLocator(args[0], args[1]).getURL(), True)
    project.getViewedProjectData()[0].getFolder(args[2]).copyTo(getProjectRootFolder(), monitor)
    project.removeProjectView(ProjectLocator(args[0], args[1]).getURL())

    # Create a new repo for this project and convert this project to shared
    repo = GhidraProject.getServerRepository("127.0.0.1", 0, project.getName(), True)
    project.getProjectData().convertProjectToShared(repo, monitor)

    # Must close and reopen project after converting to shared
    project.close()
    del project
    project = manager.openProject(locator, False, False)

    # Add all the files to version control to move them to server
    for file in dirwalk(project.getProjectData().getRootFolder()):
        print(file.getPathname())
        file.addToVersionControl("adding {}".format(file.getPathname()), False, monitor)
except:
    import os, traceback
    on_fail = os.environ.get("ON_FAIL")
    if on_fail is not None:
        with open(on_fail, 'w') as fp:
            traceback.print_exc(file=fp)
