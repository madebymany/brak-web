#!/usr/bin/env python
from setuptools import setup, find_packages

setup(name='brak-web',
      version='0.1',
      description='Web front-end for Brak',
      author='Dan Brown',
      author_email='dan@madebymany.co.uk',
      url='https://github.com/madebymany/brak-web',
      packages=find_packages('.', exclude=['tests*']),
      package_dir={'brak_web': 'brak_web'},
      include_package_data=True,
      install_requires=[
          'Flask==0.10.1',
          'flask-appconfig==0.9.1',
          'SQLAlchemy==0.9.9',
          'Flask-SQLAlchemy==1.0',
          'pg8000==1.10.2',
          'Flask-OAuthlib==0.9.1',
          'jsonrpc2-zeromq==2.0.1',
          'tornado==4.1',
          'Flask-SSLify==0.1.5',
      ],
      entry_points={
          'console_scripts': [
              'brak-web = brak_web:run'
          ],
      },
      )
