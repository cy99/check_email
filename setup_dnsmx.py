from distutils.core import setup, Extension
import os;

#os.environ['CC'] = 'g++'
#os.environ['CXX'] = 'g++'
#os.environ['CPP'] = 'g++'

module_dnsmx = Extension('dnsmx', 
                        library_dirs = ['/usr/lib'],
                        include_dirs = ['/usr/include'],
                        libraries = ['resolv'],
                        sources = ['bind.c','check_email.c'])

setup (name = 'DNS MX Records',
       version = '0.1',
       description = 'Python module for querying DNS MX Records',
       ext_modules = [module_dnsmx])
