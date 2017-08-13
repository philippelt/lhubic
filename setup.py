# python setup.py --dry-run --verbose install

from distutils.core import setup

setup(
    name='lhubic',
    version='1.0.11',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3'
        ],
    author='Philippe Larduinat',
    author_email='ph.larduinat@wanadoo.fr',
    py_modules=['lhubic'],
    scripts=[],
    data_files=[],
    install_requires=[
        "requests >= 2.5.1",
        "python-swiftclient >= 2.5.0"
        ],
    url='https://github.com/philippelt/lhubic',
    download_url='https://github.com/philippelt/lhubic/tarball/v1.0.11.tar.gz',
    license='GPL V3',
    description='Python swift client with Hubic authentication library'
)
