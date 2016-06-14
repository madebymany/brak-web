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
          'Flask==0.11.1',
          'flask-appconfig==0.11.1',
          'SQLAlchemy==1.0.13',
          'Flask-SQLAlchemy==2.1',
          'pg8000==1.10.6',
          'Flask-OAuthlib==0.9.3',
          'jsonrpc2-zeromq==2.0.1',
          'tornado==4.3',
          'Flask-SSLify==0.1.5',
      ],
      entry_points={
          'console_scripts': [
              'brak-web = brak_web:run'
          ],
      },
      )
