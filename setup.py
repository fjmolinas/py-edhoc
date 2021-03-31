import os

from setuptools import setup, find_packages


def _read_requirements(file_name):
    """
    Returns list of required modules for 'install_requires' parameter. Assumes
    requirements file contains only module lines and comments.
    """
    requirements = []
    with open(os.path.join(file_name)) as f:
        for line in f:
            if not line.startswith('#'):
                requirements.append(line)
    return requirements


INSTALL_REQUIREMENTS = _read_requirements('requirements.txt')

# README as long description
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md')) as f:
    LONG_DESCRIPTION = f.read()

setup(
    name='edhoc',
    version='0.2.dev3',
    packages=find_packages(exclude=['tests', 'docs']),
    python_requires='>=3.6',
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'edhoc-responder = scripts.edhoc_responder:main',
            'edhoc-initiator = scripts.edhoc_initiator:sync_main',
        ],
    },
    package_data={
        '': [
            'requirements.txt',
        ],
    },
    install_requires=INSTALL_REQUIREMENTS,
    long_description_content_type='text/markdown',
    long_description=LONG_DESCRIPTION,
    description='Ephemeral Diffie-Hellman Over COSE (EDHOC)',
    keywords=['EDHOC', 'Internet of Things', 'CBOR', 'object security', 'COSE', 'OSCORE', 'cryptography'],
    author='Timothy Claeys',
    author_email='timothy.claeys@gmail.com',
    license='BSD-3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Internet',
        'Topic :: Communications',
        'Topic :: Software Development',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
