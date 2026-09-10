"""Dependency packaging refusal and reproducibility checks with synthetic DLLs."""
import importlib.util
import json
from pathlib import Path
import zipfile
import pytest

path=Path(__file__).parents[1]/'scripts/package-plugin-dependencies.py'
spec=importlib.util.spec_from_file_location('dependencies',path)
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

@pytest.fixture
def publish(tmp_path):
    root=tmp_path/'publish';root.mkdir();libraries={}
    for library,asset in p.RUNTIME.items():
        libraries[library]={'runtime':{asset:{}}}
        (root/Path(asset).name).write_bytes(b'MZsynthetic-'+library.encode())
    libraries['System.Management/7.0.2']['runtimeTargets']={p.WINDOWS_ASSET:{'rid':'win','assetType':'runtime'}}
    win=root/p.WINDOWS_ASSET;win.parent.mkdir(parents=True);win.write_bytes(b'MZsynthetic-windows')
    (root/(p.PLUGIN+'.deps.json')).write_text(json.dumps({'runtimeTarget':{'name':p.TARGET},'targets':{p.TARGET:libraries}}))
    return root


def run(root,tmp_path,label='one'):
    return p.package(root,tmp_path/label,tmp_path/(label+'.zip'),version='0.3.25',timestamp='2026-09-07T00:00:00Z')


def test_dependencies_are_preserved_without_host_or_rid_duplicate_loading(publish,tmp_path):
    first=run(publish,tmp_path);second=run(publish,tmp_path,'two')
    assert first['sha256']==second['sha256']
    with zipfile.ZipFile(tmp_path/'one.zip') as archive:
        meta=json.loads(archive.read('meta.json'))
        assert 'Google.Cloud.Firestore.V1.dll' in archive.namelist()
        assert p.WINDOWS_ASSET in archive.namelist() and p.WINDOWS_ASSET not in meta['assemblies']
        assert not p.HOST_OWNED.intersection(archive.namelist())
        assert meta['version']=='0.3.25.0' and meta['targetAbi']=='10.11.0.0'
    with pytest.raises(FileExistsError):run(publish,tmp_path)


def test_missing_firestore_dependency_never_creates_partial_package(publish,tmp_path):
    (publish/'Google.Cloud.Firestore.V1.dll').unlink()
    with pytest.raises(FileNotFoundError):run(publish,tmp_path)
    assert not (tmp_path/'one').exists() and not (tmp_path/'one.zip').exists()


def test_version_mismatch_and_symlink_refused(publish,tmp_path):
    with pytest.raises(ValueError):p.package(publish,tmp_path/'one',tmp_path/'one.zip',version='0.3.26',timestamp='2026-09-07T00:00:00Z')
    dll=publish/'Google.Cloud.Firestore.V1.dll';dll.rename(publish/'other.dll');dll.symlink_to(publish/'other.dll')
    with pytest.raises(OSError):run(publish,tmp_path)
    assert not (tmp_path/'one.zip').exists()
