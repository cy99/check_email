#include <Python.h>
#include "check_email.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int dns_mx_lookup(char *domain, char ***server_list);
extern int smtp_query(char *server, char *email);

static PyObject *get_dns_mx_record(PyObject *self, PyObject *args)
{
    const char *email;
    char **list = NULL;
    PyObject *result = PyList_New(0);

    // extract the e-mail from the parameters
    if (!PyArg_ParseTuple(args, "s", &email)) {
        // create an AttributeError exception (no need to increment ref count)
        PyErr_SetString(PyExc_AttributeError, "Usage: get_dns_mx_record(\"email@domain.com\")");
        
        // raise the AttributeError exception
        return NULL; 
    }
    
    // extract the domaing from the e-mail
    char* pdomain = strchr(email, '@');
    if (!pdomain || !++pdomain) {
    
        // raise a runtime exception in python if the parameter is not right
        PyErr_SetString(PyExc_RuntimeError, "The email must respect the name@domain format");

        return NULL;
    }

    if (strlen(pdomain) >= 512) {

        // raise a runtime exception in python if the domain is too large 
        PyErr_SetString(PyExc_RuntimeError, "The domain name must not be greater than 512 characters");

        return NULL;
    }

    // get the mail servers from the dns mx records
    int msgs_number = dns_mx_lookup(pdomain, &list);

    int i;
    for (i = 0; i < msgs_number; ++i) {
    
        // append each record found in a python list
        PyList_Append(result, PyString_FromString(list[i]));

    }

     // free allocated resources
    for (i = 0; i < msgs_number; ++i) {

        // item by item...
        free(list[i]);
        
    }
    // ...and finally the list
    free(list);
    list = NULL;

    // the caller is responsible for the PyList memory
    return result;
}

static PyObject *verify_email(PyObject *self, PyObject *args)
{
    char *email;
    char *server;

    // extract the e-mail from the parameters
    if (!PyArg_ParseTuple(args, "ss", &server, &email)) {
        // create an AttributeError exception (no need to increment ref count)
        PyErr_SetString(PyExc_AttributeError, "Usage: verify_email(\"smtp_server.com\", \"email@domain.com\")");
        
        // raise the AttributeError exception
        return NULL; 
    }

    // open a socket to the SMTP server to validate the email
    int ret = smtp_query(server, email);

    // return the numeric error (0 = success)
    return PyInt_FromLong((long)ret);
}

static PyMethodDef DNSMXMethods[] =
{
    {"get_dns_mx_record", &get_dns_mx_record, METH_VARARGS, ""},
    {"verify_email",      &verify_email,      METH_VARARGS, ""},
    { NULL,               NULL,               0,          NULL}
};

PyMODINIT_FUNC initdnsmx(void)
{
    (void) Py_InitModule("dnsmx", DNSMXMethods);
}


#ifdef __cplusplus
}
#endif
