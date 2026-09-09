"""Reviewed normal plugin dependency closure; no deployment or activation."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile

PLUGIN = "Kaevo.Plugin.KaevoForJellyfin"
TARGET = ".NETCoreApp,Version=v8.0"
# Reviewed publish closure; new dependencies or versions require explicit review.
RUNTIME = {
    f"{PLUGIN}/0.3.25": f"{PLUGIN}.dll",
    "BouncyCastle.Cryptography/2.5.1": "lib/net6.0/BouncyCastle.Cryptography.dll",
    "Google.Api.CommonProtos/2.17.0": "lib/netstandard2.0/Google.Api.CommonProtos.dll",
    "Google.Api.Gax/4.13.1": "lib/netstandard2.0/Google.Api.Gax.dll",
    "Google.Api.Gax.Grpc/4.13.1": "lib/netstandard2.0/Google.Api.Gax.Grpc.dll",
    "Google.Apis/1.73.0": "lib/net6.0/Google.Apis.dll",
    "Google.Apis.Auth/1.73.0": "lib/net6.0/Google.Apis.Auth.dll",
    "Google.Apis.Core/1.73.0": "lib/net6.0/Google.Apis.Core.dll",
    "Google.Cloud.Firestore.V1/4.4.0": "lib/netstandard2.0/Google.Cloud.Firestore.V1.dll",
    "Google.Cloud.Location/2.4.0": "lib/netstandard2.0/Google.Cloud.Location.dll",
    "Google.LongRunning/3.5.0": "lib/netstandard2.0/Google.LongRunning.dll",
    "Google.Protobuf/3.31.1": "lib/net5.0/Google.Protobuf.dll",
    "Grpc.Auth/2.71.0": "lib/netstandard2.0/Grpc.Auth.dll",
    "Grpc.Core.Api/2.71.0": "lib/netstandard2.1/Grpc.Core.Api.dll",
    "Grpc.Net.Client/2.71.0": "lib/net8.0/Grpc.Net.Client.dll",
    "Grpc.Net.Common/2.71.0": "lib/net8.0/Grpc.Net.Common.dll",
    "Microsoft.Bcl.AsyncInterfaces/6.0.0": "lib/netstandard2.1/Microsoft.Bcl.AsyncInterfaces.dll",
    "Microsoft.Extensions.DependencyInjection.Abstractions/8.0.2": "lib/net8.0/Microsoft.Extensions.DependencyInjection.Abstractions.dll",
    "Microsoft.Extensions.Logging.Abstractions/8.0.2": "lib/net8.0/Microsoft.Extensions.Logging.Abstractions.dll",
    "Newtonsoft.Json/13.0.4": "lib/net6.0/Newtonsoft.Json.dll",
    "QRCoder/1.6.0": "lib/net6.0/QRCoder.dll",
    "System.CodeDom/7.0.0": "lib/net7.0/System.CodeDom.dll",
    "System.Management/7.0.2": "lib/net7.0/System.Management.dll",
}
WINDOWS_ASSET = "runtimes/win/lib/net7.0/System.Management.dll"
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:raise ValueError("plugin_dependency_duplicate_key")
        result[key] = value
    return result


def read_member(directory, relative):
    """Walk from an open root descriptor: no file or intermediate symlink."""
    path = PurePosixPath(relative)
    if path.is_absolute() or str(path) != relative or any(p in (".", "..") for p in path.parts):
        raise ValueError("plugin_dependency_path_invalid")
    descriptors = [os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        for part in path.parts[:-1]:
            descriptors.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptors[-1]))
        file = os.open(path.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptors[-1])
        descriptors.append(file)
        info = os.fstat(file)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_FILE_BYTES:
            raise ValueError("plugin_dependency_file_invalid")
        with os.fdopen(file, "rb", closefd=False) as source:body = source.read(MAX_FILE_BYTES + 1)
        if len(body) != info.st_size:raise ValueError("plugin_dependency_changed")
        return body
    finally:
        for descriptor in reversed(descriptors):os.close(descriptor)


def collect(directory, version="0.3.25"):
    if not __import__("re").fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",version):raise ValueError("plugin_version_invalid")
    name = f"{PLUGIN}.deps.json"
    body = read_member(directory, name)
    dependency = json.loads(body, object_pairs_hook=unique_object)
    if dependency.get("runtimeTarget", {}).get("name") != TARGET or set(dependency.get("targets", {})) != {TARGET}:
        raise ValueError("plugin_dependency_target_unreviewed")
    runtime, rid = {}, {}
    for library, definition in dependency["targets"][TARGET].items():
        for asset in definition.get("runtime", {}):
            runtime[(library, asset)] = PurePosixPath(asset).name
        for asset, metadata in definition.get("runtimeTargets", {}).items():
            rid[(library, asset)] = metadata
        if definition.get("native") or definition.get("resources"):
            raise ValueError("plugin_dependency_asset_unreviewed")
    expected = {(library, asset): PurePosixPath(asset).name for library, asset in {**{k:v for k,v in RUNTIME.items() if not k.startswith(PLUGIN+"/")},PLUGIN+"/"+version:PLUGIN+".dll"}.items()}
    if runtime != expected or len(set(runtime.values())) != len(runtime):
        raise ValueError("plugin_dependency_closure_unreviewed")
    if (set(rid) != {("System.Management/7.0.2", WINDOWS_ASSET)}
            or rid[("System.Management/7.0.2", WINDOWS_ASSET)].get("rid") != "win"
            or rid[("System.Management/7.0.2", WINDOWS_ASSET)].get("assetType") != "runtime"):
        raise ValueError("plugin_dependency_rid_unreviewed")
    files = {name: body}
    for member in sorted([*runtime.values(), WINDOWS_ASSET]):
        data = read_member(directory, member)
        # Minimal format check only; actual assembly loading/ABI is separate.
        if not data.startswith(b"MZ"):raise ValueError("plugin_dependency_not_pe_candidate")
        files[member] = data
    if sum(map(len, files.values())) > MAX_TOTAL_BYTES:
        raise ValueError("plugin_dependency_archive_too_large")
    return files



HOST_OWNED={"Microsoft.Extensions.DependencyInjection.Abstractions.dll", "Microsoft.Extensions.Logging.Abstractions.dll"}


def package(publish, directory, output, *, version, timestamp):
    import datetime
    # Validate every original dependency before excluding the host-owned pair.
    files={k:v for k,v in collect(publish,version).items() if k not in HOST_OWNED}
    date=datetime.datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
    if not 1980<=date.year<=2107:raise ValueError("package_timestamp_invalid")
    metadata={"category":"General","changelog":"Includes connector transport dependencies with explicit Jellyfin assembly selection.",
        "description":"Connects Jellyfin securely to the Kaevo app with simple app-guided setup.",
        "guid":"80c77b84-7f2d-4b52-84c7-7dfe68cd95ae","name":"Kaevo","overview":"Secure Kaevo Cloud access for Jellyfin",
        "owner":"Kaevo","targetAbi":"10.11.0.0","timestamp":timestamp,"version":version+".0",
        "assemblies":sorted(k for k in files if k.endswith('.dll') and '/' not in k)}
    files['meta.json']=json.dumps(metadata,sort_keys=True,indent=2).encode()+b'\n'
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_STORED) as archive:
        for name,body in sorted(files.items()):
            entry=zipfile.ZipInfo(name,(date.year,date.month,date.day,date.hour,date.minute,date.second//2*2))
            entry.create_system=3;entry.external_attr=0o100644<<16
            archive.writestr(entry,body)
    data=buffer.getvalue()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if sorted(archive.namelist())!=sorted(files) or any(archive.read(k)!=v for k,v in files.items()):
            raise ValueError('package_readback_failed')
    if directory.exists() or directory.is_symlink() or output.exists() or output.is_symlink():
        raise FileExistsError('existing_package_preserved_choose_new_output')
    directory.mkdir(parents=True)
    for name,body in files.items():
        target=directory/name;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream:stream.write(body)
    with output.open('xb') as stream:stream.write(data)
    if output.read_bytes()!=data or any(read_member(directory,k)!=v for k,v in files.items()):
        raise ValueError('package_disk_readback_failed')
    return {'state':'dependency_package_verified','files':len(files),'sha256':hashlib.sha256(data).hexdigest(),
        'version':version+'.0','published':False,'activation_verified':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('publish',type=Path);parser.add_argument('directory',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--version',required=True);parser.add_argument('--timestamp',required=True)
    args=parser.parse_args()
    print(json.dumps(package(args.publish,args.directory,args.output,version=args.version,timestamp=args.timestamp)))
