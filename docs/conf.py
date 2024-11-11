# Configuration file for the Sphinx documentation builder.
import os
import sys
sys.path.insert(0, os.path.abspath('..'))

# Project information
project = 'Flask Admin Dashboard'
copyright = '2024, Admin Dashboard Team'
author = 'Admin Dashboard Team'
release = '1.0.0'

# General configuration
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    'autoapi.extension'
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# HTML output options
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# AutoAPI settings
autoapi_type = 'python'
autoapi_dirs = ['..']
autoapi_ignore = ['*migrations*', '*tests*', '*venv*', '*env*']
