#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import logging
from multiprocessing import Process
import os
from pathlib import Path
import pwd
from random import randrange
import shutil
import subprocess
import time

logger = logging.getLogger(Path(__file__).stem)

debug = logger.debug
info = logger.info
warn = logger.warning
error = logger.error

class FileTypeError(RuntimeError):
    def __init__(self, msg):
        super().__init__(msg)

class RetryLimitError(RuntimeError):
    def __init__(self, limit):
        self.limit = limit
        super().__init__(f"Retry limit exceeded: {self.limit}")

class EnvironmentNotSetError(RuntimeError):
    def __init__(self, var):
        self.var = var
        super().__init__(f"Environment variable not set: {self.var}")

class GhidraScriptError(RuntimeError):
    def __init__(self, backtrace):
        self.backtrace = backtrace
        super().__init__(f"Ghidra script failed")
        
class TempDir(object):
    charset = list(range(0x30, 0x3a)) + list(range(0x41, 0x5b)) + list(range(0x61, 0x7b))
    retries = 10
    
    def __init__(self):
        for i in range(0, TempDir.retries):
            try:
                suffix = [ TempDir.charset[randrange(0, len(TempDir.charset))] for i in range(0, 10) ]
                path = Path(f"/tmp/tmp.{bytearray(suffix).decode()}")
                debug(f"Creating temporary directory: {path}")
                path.mkdir(parents=True, exist_ok=False)
                self._path = path
                return
            except FileExistsError:
                debug(f"{path} already exists")
                continue
        error("Retry limit exceeded while creating a temporary directory")
        raise RetryLimitError(TempDir.retries)

    @property
    def path(self):
        return self._path

    def close(self):
        debug(f"Cleaning up temporary directory: {self.path}")
        shutil.rmtree(self.path)

    def __enter__(self):
        return self.path

    def __exit__(self, type, value, traceback):
        self.close()
        
        
class TemporaryGhidraServer(object):
    def __init__(self):
        ghidra_server_conf = ghidra_install_dir() / "server" / "server.conf"
        restore_conf = False
        self.tmpdir = TempDir()
        repos = self.tmpdir.path / "repos"
        try:
            repos.mkdir()
            shutil.copy2(str(ghidra_server_conf), str(self.tmpdir.path / "server.conf"))
            restore_conf = True
            server_conf = data_dir().joinpath("server.conf").read_text()
            ghidra_server_conf.write_text(server_conf.replace("$REPOS$", str(repos)))
            command = [ str(ghidra_install_dir() / "server" / "svrInstall") ]
            debug(f"Running command: {command}")
            subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)    
        except Exception as e:
            if restore_conf:
                shutil.copy2(str(self.tmpdir.path / "server.conf"), str(ghidra_server_conf))
            self.tmpdir.close()
            raise e
        
        command = [ str(ghidra_install_dir() / "server" / "svrAdmin"), "-add", whoami() ]
        debug(f"Running command: {command}")
        try:
            subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self.close()
            raise e
    @property
    def path(self):
        return self.tmpdir.path

    @property
    def url(self):
        return f"ghidra://127.0.0.1"

    def uniq_path(self, *args):
        hasher = hashlib.md5()
        for arg in args:
            hasher.update(arg)
        return self.path / hasher.hexdigest()
    
    def close(self):
        debug("Shutting down temporary Ghidra server")
        command = [ str(ghidra_install_dir() / "server" / "svrUninstall") ]
        debug(f"Running command: {command}")
        try:
            subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            warn(f"Command ({command}) returned non-zero exit code")
        shutil.copy2(str(self.path / "server.conf"), str(ghidra_install_dir() / "server" / "server.conf"))
        self.tmpdir.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

class TemporaryRepo(object):
    def __init__(self, server, name, path=None, folder=None):
        self.server = server
        self.name = name

        if path is not None and folder is not None:
            self._from_project(path, folder)
            return    

        scripts = data_dir() / "scripts"
        command = [
            str(ghidra_install_dir() / "support" / "analyzeHeadless"),
            str(self.server.path),
            "dummy",
            "-scriptPath",
            str(scripts),
            "-preScript",
            "new-repo.py",
            self.name
        ]
        on_fail = self.server.uniq_path(*list(map(lambda x: x.encode(), command)))
        debug(f"Running command: {command}")
        subprocess.check_call(command,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              env=update_env(ON_FAIL=on_fail, DISPLAY=None))
        if on_fail.exists():
            backtrace = on_fail.read_text()
            warn(f"Command ({command}) failed")
            debug(f"Backtrace:\n{backtrace}")
            raise GhidraScriptError(backtrace)

    def _from_project(self, path, folder):
        command = [
            str(ghidra_install_dir() / "support" / "analyzeHeadless"),
            str(self.server.path),
            self.name,
            "-scriptPath",
            str(data_dir() / "scripts"),
            "-preScript",
            "repo-from-project.py",
            str(path),
            self.name,
            str(folder)
        ]
        on_fail = self.server.uniq_path(*list(map(lambda x: x.encode(), command)))
        debug(f"Running command: {command}")
        subprocess.check_call(command,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              env=update_env(ON_FAIL=on_fail, DISPLAY=None))
        if on_fail.exists():
            backtrace = on_fail.read_text()
            warn(f"Command ({command}) failed")
            debug(f"Backtrace:\n{backtrace}")
            raise GhidraScriptError(backtrace)

    def import_file(self, file, folder_path=None):
        info(f"Importing: {file}")
        prefix = Path("/") / self.name
        if folder_path is None:
            folder_path = prefix
        elif folder_path.is_absolute():
            folder_path = prefix / folder_path.relative_to(Path("/"))
        else:
            folder_path = prefix / folder_path
        command = [
            str(ghidra_install_dir() / "support" / "analyzeHeadless"),
            f"{self.server.url}{folder_path}",
            "-import",
            str(file),
            "-overwrite",
            "-commit",
            f"adding {file}",
        ]
        on_fail = self.server.uniq_path(*list(map(lambda x: x.encode(), command)))
        debug(f"Running command: {command}")
        return (on_fail, subprocess.Popen(command,
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL,
                                          env=update_env(ON_FAIL=on_fail, DISPLAY=None)))

    def copy_to(self, folder, project, item):
        command = [
            str(ghidra_install_dir() / "support" / "analyzeHeadless"),
            str(folder),
            str(project),
            "-scriptPath",
            str(data_dir() / "scripts"),
            "-preScript",
            "export.py",
            self.name,
            str(item)
        ]
        on_fail = self.server.uniq_path(*list(map(lambda x: x.encode(), command)))
        debug(f"Running command: {command}")
        subprocess.check_call(command,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              env=update_env(ON_FAIL=on_fail, DISPLAY=None))
        if on_fail.exists():
            backtrace = on_fail.read_text()
            warn(f"Command ({command}) failed")
            debug(f"Backtrace:\n{backtrace}")
            raise GhidraScriptError(backtrace)

    def extract_static(self, file, folder_path=None):
        info(f"Extracting static data from: {file}")
        prefix = Path("/") / self.name
        if folder_path is None:
            folder_path = prefix
        elif folder_path.is_absolute():
            folder_path = prefix / folder_path.relative_to(Path("/"))
        else:
            folder_path = prefix / folder_path
        dest = self.server.uniq_path(*[str(file).encode(), str(folder_path).encode()])
        dest.mkdir()
        command = [
            str(ghidra_install_dir() / "support" / "analyzeHeadless"),
            f"{self.server.url}{folder_path}",
            "-process",
            str(file),
            "-scriptPath",
            str(data_dir() / "scripts"),
            "-postScript",
            "extractstatic.java",
            str(dest),
            "-noanalysis"
        ]
        on_fail = self.server.uniq_path(*list(map(lambda x: x.encode(), command)))
        debug(f"Running command: {command}")
        return (on_fail, subprocess.Popen(command,
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL,
                                          env=update_env(ON_FAIL=on_fail, DISPLAY=None)))

def dirwalk(root):
    for (dirpath, dirnames, filenames) in os.walk(root):
        for name in dirnames:
            yield Path(dirpath) / name
        for name in filenames:
            yield Path(dirpath) / name
        
def update_env(**kwargs):
    env = { key: value for (key, value) in os.environ.items() }
    for (key, value) in kwargs.items():
        if key not in env:
            continue
        if value is None:
            del env[key]
        else:
            env[key] = value
    return env

def ghidra_install_dir():
    install_dir = getattr(ghidra_install_dir, "GHIDRA_INSTALL_DIR", None)
    if install_dir is None:
        install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if install_dir is None:
            error("GHIDRA_INSTALL_DIR environment variable must be set")
            raise EnvironmentNotSetError("GHIDRA_INSTALL_DIR")
        install_dir = Path(install_dir)
        setattr(ghidra_install_dir, "GHIDRA_INSTALL_DIR", install_dir)
    return install_dir

def data_dir():
    return Path("/usr/local/share/container-tracemadness")

def whoami():
    return pwd.getpwuid(os.geteuid()).pw_name

def walk_sysroot(sysroot):
    for file in filter(lambda x: x.is_file(), dirwalk(sysroot)):
        yield (file, file.relative_to(sysroot.parent).parent)

def create_ghidra_project(args):
    info(f"Creating ghidra project: {args.ghidra_project}")

    if args.ghidra_project.exists():
        warn("Removing existing ghidra project")
        args.ghidra_project.unlink()
        shutil.rmtree(args.ghidra_project.with_suffix(".rep"))

    args.ghidra_project.parent.mkdir(parents=True)

    with TemporaryGhidraServer() as server:
        repo = TemporaryRepo(server, "temporary-project")
        imports = list(map(lambda f: repo.import_file(f[0], folder_path=f[1]), walk_sysroot(args.sysroot)))
        excepts = []
        for (on_fail, proc) in imports:
            proc.wait()
            if on_fail.exists():
                backtrace = on_fail.read_text()
                warn(f"Command ({proc.args}) failed")
                debug(f"Backtrace:\n{backtrace}")
                excepts.append(GhidraScriptError(backtrace))
        
        if len(excepts) > 0:
            raise excepts[0]
        
        repo.copy_to(args.ghidra_project.parent,
                     args.ghidra_project.stem,
                     Path("/") / args.sysroot.name)

def extract_static(args):
    info("Extracting static information")

    if not args.ghidra_project.is_file():
        error("attempting to extract static information without a valid Ghidra project")
        raise RuntimeError("Missing required Ghidra project")

    if args.static.exists():
        warn("Removing existing static data")
        shutil.rmtree(args.static)

    args.static.mkdir(parents=True)

    with TemporaryGhidraServer() as server:
        repo = TemporaryRepo(server,
                             args.ghidra_project.stem,
                             path=args.ghidra_project.parent,
                             folder=Path("/") / args.sysroot.name)
        items = list(map(lambda f: repo.extract_static(f[0].name, folder_path=f[1]), walk_sysroot(args.sysroot)))
        excepts = []
        for (on_fail, proc) in items:
            proc.wait()
            if on_fail.exists():
                backtrace = on_fail.read_text()
                warn(f"Command ({proc.args}) failed")
                debug(f"Backtrace:\n{backtrace}")
                excepts.append(GhidraScriptError(backtrace))
        
        if len(excepts) > 0:
            raise excepts[0]

        buffers = {
            "blocks.jsonl": "",
            "functions.jsonl": "",
            "cdg.jsonl": "",
            "blockof.jsonl": "",
            "successorof.jsonl": "",
            "callerof.jsonl": ""
        }

        for path in dirwalk(server.path):
            if not path.suffix == ".jsonl":
                continue

            if path.name in buffers:
                buffers[path.name] += path.read_text()

        for (name, data) in buffers.items():
            args.static.joinpath(name).write_text(data)

def extract_dynamic(args):
    info("Extracting dynamic information")

    if not args.trace_file.is_file():
        error("attempting to extract dynamic information without a valid trace file")
        raise RuntimeError("Missing required trace file")

    if args.dynamic.exists():
        warn("Removing existing dynamic data")
        shutil.rmtree(args.dynamic)

    with TempDir() as tmpdir:
        cwd = Path.cwd()
        os.chdir(tmpdir)
        try:
            command = [
                "tm-analyze",
                "-i",
                str(args.trace_file),
            ]
            debug(f"Running command: {command}")
            subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            shutil.copytree(str(tmpdir / "out"), str(args.dynamic))
        finally:
            os.chdir(cwd)

def make_modules(args):
    info("Creating dynamic modules file")

    if not args.memory_map.is_file():
        error("attempting to create modules file without a valid map file")
        raise RuntimeError("Missing required memory maps file")

    if args.memory_map.suffix == '.out':
        make_modules_from_out_file(args)
    elif args.memory_map.suffix == '.jsonl':
        make_modules_from_jsonl_file(args)
    else:
        warn("Unknown file type for memory map, assuming .out format")
        make_modules_from_out_file(args)

def make_modules_from_out_file(args):
    data = args.memory_map.read_text().strip()
    if '\x00' not in data:
        warn("Memory maps file does not contain null-byte delimited fields")
        warn("Falling back on deprecated format, there may be parsing ambiguities")
        entries = []
        for entry in data.split('\n'):
            parts = entry.split(' ')
            entries.append(' '.join(parts[:-1]))
            entries.append(parts[-1])
    else:
        entries = data.split('\x00')
        
    modules = {}
    for i in range(0, len(entries), 2):
        if entries[i].startswith('['):
            continue
        
        path = Path(entries[i])
        name = path.name
        location = entries[i+1].split(':')
        base = parse_int(location[0])
        end = None if len(location) < 2 else base + parse_int(location[1])
        
        if path not in modules:
            modules[path] = {
                'name': name,
                'base': base,
                'end': end,
            }
        else:   
            modules[path]['base'] = min(base, modules[path]['base'])
            modules[path]['end'] = max_or_none(modules[path]['end'], end)

    with open(args.dynamic / "modules.csv", 'w', newline='') as fp:
        writer = csv.writer(fp)
        writer.writerow(['base', 'size', 'name', 'path'])
        for (path, entry) in modules.items():
            base = entry['base']
            size = None if entry['end'] is None else entry['end'] - base
            name = entry['name']
            prefix = Path('/') / args.sysroot.name
            if path.is_absolute():
                path = prefix / path.relative_to('/')
            else:
                path = prefix / path 
            writer.writerow([base, size, name, path])

def make_modules_from_jsonl_file(args):
    entries = map(lambda x: json.loads(x), args.memory_map.read_text().strip().split('\n'))
        
    modules = {}
    for entry in entries:
        if entry['name'].startswith('['):
            continue
        
        path = Path(entry['name'])
        name = path.name
        base = parse_int(entry['low'])
        end = parse_int(entry.get('high', None))
        
        if path not in modules:
            modules[path] = {
                'name': name,
                'base': base,
                'end': end,
            }
        else:   
            modules[path]['base'] = min(base, modules[path]['base'])
            modules[path]['end'] = max_or_none(modules[path]['end'], end)

    with open(args.dynamic / "modules.csv", 'w', newline='') as fp:
        writer = csv.writer(fp)
        writer.writerow(['base', 'size', 'name', 'path'])
        for (path, entry) in modules.items():
            base = entry['base']
            size = None if entry['end'] is None else entry['end'] - base
            name = entry['name']
            prefix = Path('/') / args.sysroot.name
            if path.is_absolute():
                path = prefix / path.relative_to('/')
            else:
                path = prefix / path 
            writer.writerow([base, size, name, path])

def max_or_none(a, b):
    if a is None or b is None:
        return None
    
    return max(a, b)

def parse_int(x):
    try:
        return int(x)
    except ValueError:
        pass
    
    return int(x, 16)

def stop_database():
    info("Stopping database")
    command = ["service", "arangodb3", "stop"]
    debug(f"Running command: {command}")
    subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
def start_database_proc(args):
    info("Starting database")
    command = ["service", "arangodb3", "start"]
    debug(f"Running command: {command}")
    subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # TODO: get heartbeat from database
    # Currently simulated with a 10 second sleep
    time.sleep(10)

def static_proc(args, needs_ghidra_project, needs_static):
    if needs_ghidra_project and not args.no_create_ghidra_project:
        create_ghidra_project(args)

    if needs_static and not args.no_create_static:
        extract_static(args)

def dynamic_proc(args, needs_dynamic):
    if needs_dynamic:
        extract_dynamic(args)
        
    make_modules(args)


def import_to_database(args):
    info("Initializing database")
    command = [
        "dbmanager",
        "--schema",
        "/usr/local/share/database-manager/schema.xml",
        "init"
    ]
    debug(f"Running command: {command}")
    subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    info("Importing data to database")
    command = [
        "dbmanager",
        "--schema",
        "/usr/local/share/database-manager/schema.xml",
        "populate-all",
        "--dynamic",
        str(args.dynamic),
        "--static",
        str(args.static),
        "--constant",
        "/usr/local/share/database-manager/constants/x86_64"
    ]
    debug(f"Running command: {command}")
    subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    

def start_ghidra_client():
    info("Starting ghidra client")
    extensions = Path.home() / ".config" / "ghidra" / "ghidra_11.3.1_PUBLIC" / "Extensions"
    extensions.mkdir(parents=True)
    command = f"unzip /usr/local/share/tracemadness/*_tracemadness.zip -d {extensions}"
    debug(f"Running command: {command}")
    subprocess.check_call(command,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,
                          shell=True)
    
    command = [
        str(ghidra_install_dir() / "support" / "launch.sh"),
        "fg",
        "jdk",
        "Ghidra",
        "",
        "",
        "ghidra.GhidraRun"
    ]
    debug(f"Running command: {command}")
    subprocess.run(command)

def main(args):
    if args.ghidra_project.suffix not in ['.gpr', None]:
        error("Provided Ghidra Project should be a .gpr file")
        raise FileTypeError("expected extension for Ghidra Project is .gpr")
    
    args.ghidra_project = args.ghidra_project.with_suffix(".gpr")
    
    needs_ghidra_project = args.create_ghidra_project or not args.ghidra_project.is_file()
    needs_static = args.create_static or not args.static.is_dir()
    needs_dynamic = args.create_dynamic or not args.dynamic.is_dir()
    needs_modules = not args.dynamic.joinpath('modules.csv').is_file()

    should_launch_static = (needs_ghidra_project and not args.no_create_ghidra_project) or (
        needs_static and not args.no_create_static)

    should_launch_dynamic = (needs_dynamic and not args.no_create_dynamic) or needs_modules

    should_exit = False
    database_started = False
    
    proc_dbstart = Process(target=start_database_proc, args=[args])
    proc_dbstart.start()
    
    proc_static = None
    if should_launch_static:
        proc_static = Process(target=static_proc, args=[args, needs_ghidra_project, needs_static])
        proc_static.start()

    proc_dynamic = None
    if should_launch_dynamic:
        proc_dynamic = Process(target=dynamic_proc, args=[args, needs_dynamic])
        proc_dynamic.start()

    if proc_static is not None:
        proc_static.join()
        if not proc_static.exitcode == 0:
            error(f"Static subprocess returned non-zero exit code {proc_static.exitcode}")
            should_exit = True

    if proc_dynamic is not None:
        proc_dynamic.join()
        if not proc_dynamic.exitcode == 0:
            error(f"Dynamic subprocess returned non-zero exit code {proc_dynamic.exitcode}")
            should_exit = True

    proc_dbstart.join()
    if not proc_dbstart.exitcode == 0:
        error(f"Database starter subprocess returned non-zero exit code {proc_dbstart.exitcode}")
        should_exit = True
    else:
        database_started = True

    if should_exit:
        if database_started:
            stop_database()            
        raise RuntimeError("One or more external processes returned unsuccessful")

    try:
        import_to_database(args)
        if "DISPLAY" in os.environ:
            start_ghidra_client()
        else:
            warn("Not running Ghidra because DISPLAY is not set")
            info("Ghidra project and database are initialized!")
    finally:
        stop_database()

def path_or_none(arg):
    return None if arg is None else Path(arg)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sysroot",
                        type=path_or_none,
                        default=None,
                        help="Path to sysroot (env: TM_SYSROOT) (default: /appdata/sysroot)")
    parser.add_argument("--memory-map",
                        type=path_or_none,
                        default=None,
                        help="Path to file containing memory map information (env: TM_MEMORY_MAP) (default: /appdata/maps.out)")
    parser.add_argument("--trace-file",
                        type=path_or_none,
                        default=None,
                        help="Path to trace file (env: TM_TRACE_FILE) (default: /appdata/trace.out)")
    parser.add_argument("--ghidra-project",
                        type=path_or_none,
                        default=None,
                        help="Path to new or existing ghidra project (env: TM_GHIDRA_PROJECT) (default: /appdata/project/MyProject.gpr)")
    parser.add_argument("--static",
                        type=path_or_none,
                        default=None,
                        help="Path to directory for new or existing static data (env: TM_STATIC) (default: /appdata/static)")
    parser.add_argument("--dynamic",
                        type=path_or_none,
                        default=None,
                        help="Path to directory for new or existing dynamic data (env: TM_DYNAMIC) (default: /appdata/analyzed)")

    create_ghidra = parser.add_mutually_exclusive_group()
    create_ghidra.add_argument("--create-ghidra-project",
                               action='store_true',
                               help='Overwrite an existing ghidra project')
    create_ghidra.add_argument("--no-create-ghidra-project",
                               action='store_true',
                               help='Do not create a new ghidra project')

    create_static = parser.add_mutually_exclusive_group()
    create_static.add_argument("--create-static",
                               action='store_true',
                               help='Overwrite any existing static data')
    create_static.add_argument("--no-create-static",
                               action='store_true',
                               help='Do not create new static data')

    create_dynamic = parser.add_mutually_exclusive_group()
    create_dynamic.add_argument("--create-dynamic",
                                action='store_true',
                                help='Overwrite any existing dynamic data')
    create_dynamic.add_argument("--no-create-dynamic",
                                action='store_true',
                                help='Do not create new dynamic data')

    parser.add_argument("-v", "--verbose",
                        action='store_true',
                        help="Display debug information")

    args = parser.parse_args()

    if args.sysroot is None:
        args.sysroot = Path(os.environ.get("TM_SYSROOT", "/appdata/sysroot"))
        
    if args.memory_map is None:
        args.memory_map = Path(os.environ.get("TM_MEMORY_MAP", "/appdata/maps.out"))
        
    if args.trace_file is None:
        args.trace_file = Path(os.environ.get("TM_TRACE_FILE", "/appdata/trace.out"))
        
    if args.ghidra_project is None:
        args.ghidra_project = Path(os.environ.get("TM_GHIDRA_PROJECT", "/appdata/project/MyProject.gpr"))
        
    if args.static is None:
        args.static = Path(os.environ.get("TM_STATIC", "/appdata/static"))
        
    if args.dynamic is None:
        args.dynamic = Path(os.environ.get("TM_DYNAMIC", "/appdata/analyzed"))

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    main(args)
