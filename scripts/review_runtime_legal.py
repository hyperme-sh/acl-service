"""Record installed legal metadata and upstream references; never fetch sources."""
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
from urllib.parse import quote


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def debian_inventory(root, rows):
    packages = []
    for line in rows.splitlines():
        binary, version, source, source_version = line.split('\t')
        name = binary.split(':')[0]
        if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', name):
            raise ValueError('Invalid Debian package name')
        copyright = root / 'usr/share/doc' / name / 'copyright'
        if not copyright.is_file() or not copyright.resolve().is_relative_to(root.resolve()):
            raise ValueError('Missing installed Debian copyright: ' + name)
        source = source or name
        source_version = source_version or version
        packages.append({'binary':binary, 'version':version, 'source':source,
                         'source_version':source_version,
                         'copyright':str(copyright.relative_to(root)),
                         'copyright_sha256':sha(copyright),
                         'upstream_reference':'https://sources.debian.org/src/'+quote(source,safe='')+'/'+quote(source_version,safe='')+'/'})
    if not packages:
        raise ValueError('Empty Debian package inventory')
    return packages


def python_candidates(rows):
    result = []
    for row in rows:
        terms = '\n'.join(str(row.get(field) or '') for field in
                          ('license_expression','license_metadata','license_classifiers'))
        if re.search(r'\b(?:LGPL|MPL)\b|Lesser General Public|Mozilla Public',terms,re.I):
            result.append({'name':row['name'],'version':row['version'],
                           'license_expression':row.get('license_expression'),
                           'license_metadata':row.get('license_metadata'),
                           'license_classifiers':row.get('license_classifiers'),
                           'notice_texts':row['texts'],
                           'upstream_reference':'https://pypi.org/project/'+quote(row['name'],safe='')+'/'+quote(row['version'],safe='')+'/'})
    return result


def review(root, rows, python_version):
    notices = root / 'usr/share/acl-service/notices'
    packages = debian_inventory(root, rows)
    python_license = root / ('usr/local/lib/python'+'.'.join(python_version.split('.')[:2])+'/LICENSE.txt')
    if not python_license.is_file():
        raise ValueError('Missing CPython installed license')
    common = root / 'usr/share/common-licenses'
    legal = {str(p.relative_to(root)):sha(p) for p in sorted(common.iterdir()) if p.is_file()}
    if not legal:
        raise ValueError('Missing Debian common license texts')
    return {'schema_version':1,'publication_cleared':False,
            'debian_packages':packages,'common_license_sha256':legal,
            'python':{'version':python_version,'license_sha256':sha(python_license),
                      'upstream_reference':'https://github.com/python/cpython/tree/v'+python_version},
            'python_lgpl_mpl_candidates':python_candidates(json.loads((notices/'python/index.json').read_text())),
            'scope':'Installed metadata and legal text; candidates require review, not a legal compliance determination. References identify upstream locations, not source offers. No source downloads or bundles.'}


if __name__ == '__main__':
    rows = subprocess.check_output(['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n'],text=True)
    print(json.dumps(review(Path('/'),rows,platform.python_version()),indent=2,sort_keys=True))
