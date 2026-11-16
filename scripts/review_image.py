"""Observe retained layers without running older ACL images."""
import importlib.util
import json
from pathlib import Path
import sys

spec=importlib.util.spec_from_file_location('inspect_image',Path(__file__).with_name('inspect-container.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

if __name__=='__main__':
    layers=Path(sys.argv[2]);result=module.unpack_image(sys.argv[1],layers,enforce_user=False)
    result['digest']=sys.argv[3]
    result['legal_paths']=sorted(str(p.relative_to(layers)) for p in layers.rglob('*') if p.is_file() and ('/usr/share/doc/' in '/'+str(p.relative_to(layers)) or '/usr/share/common-licenses/' in '/'+str(p.relative_to(layers)) or '/usr/share/acl-service/' in '/'+str(p.relative_to(layers))))
    from assert_no_source_bundles import prohibited
    result['source_bundle_paths']=sorted(str(p.relative_to(layers)) for p in layers.rglob('*') if p.is_file() and prohibited(p.relative_to(layers).relative_to(p.relative_to(layers).parts[0]).as_posix()))
    result['source_bundle_present']=bool(result['source_bundle_paths'])
    result['debian_source_bundle_present']=any('/debian-sources/' in p for p in result['source_bundle_paths'])
    from container_audit import check_member
    findings=[]
    for path in layers.rglob('*'):
        if path.is_file() and 'site-packages/' in str(path):
            relative=str(path).partition('site-packages/')[2]
            try:
                check_member(relative,path.read_bytes())
            except ValueError:
                findings.append(str(path.relative_to(layers)))
    result['hosted_content_paths']=sorted(findings)
    result['publication_cleared']=False
    result['scope']='All retained layers, not a reconstructed final filesystem; secret scan is separate'
    for path in layers.rglob('*.gz'):
        if path.is_file():
            with path.open('rb') as stream:
                magic = stream.read(2)
            if magic != b'\x1f\x8b':
                target = path.with_name(path.name.removesuffix('.gz') + '.scan-text')
                if target.exists():
                    raise ValueError('Scan path collision')
                path.rename(target)
    print('HISTORICAL_IMAGE_REVIEW='+json.dumps(result,sort_keys=True))
