from setuptools import setup


def get_requirements():
    with open('requirements.txt', 'r') as f:
        return [line.strip() for line in f if line.strip()]


setup(
    name='mypass-logman',
    version='1.0.0',
    description='Mypass Service',
    author='ricky :) (: skyzip',
    author_email='skyzip96@gmail.com',
    license='MIT',
    packages=['mypass_service'],
    package_dir={'mypass_service': 'mypass'},
    install_requires=get_requirements(),
    package_data={'': ['license']}
)
