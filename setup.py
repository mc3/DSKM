from setuptools import setup, find_packages

# Version info -- read without importing
_locals = {}
with open('DSKM/_version.py') as fp:
    exec(fp.read(), None, _locals)
version = _locals['__version__']

with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name = "DSKM",
    version = version,
    author = "Axel Rau",
    author_email = "axel.rau@chaos1.de",
    description = "DNSsec key management",
    long_description = long_description,
    long_description_content_type="text/markdown",
    url = "https://github.com/mc3/DSKM",
    packages = find_packages(),
    data_files =[('share/doc/DSKM', ['docs/dnssec_key_states.graffle',
                                          'docs/dnssec_key_states.pdf'])],                                      
    entry_points = {
        'console_scripts': [
            'operate_dskm = DSKM.operate:execute_from_command_line',
        ],
    },
    license = 'GPLv3',
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: POSIX',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Natural Language :: English',
    ],
    install_requires=[
        'dnspython>=1.16.0',
        'ecdsa>=0.13',  
        'pycryptodome>=3.7.3',
        'script>=1.7.2',
    ],
)
