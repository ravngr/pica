#!/usr/bin/python
 # -*- coding: utf-8 -*-

import argparse
import os
import shutil
import stat
import sqlite3
import subprocess
import sys
import tempfile

### Exception
class CertificateException(Exception):
    pass

### Base templates
templateBaseCA = """# OpenSSL CA
[ default ]
    name_opt    = multiline, -esc_msb, utf8

# CA Policies
[ policy_anything ]
    countryName             = optional
    stateOrProvinceName     = optional
    localityName            = optional
    organizationName        = optional
    organizationalUnitName  = optional
    commonName              = supplied
    emailAddress            = optional

[ policy_default ]
    countryName             = supplied
    stateOrProvinceName     = optional
    localityName            = optional
    organizationName        = supplied
    organizationalUnitName  = optional
    commonName              = supplied
    emailAddress            = optional

[ policy_org ]
    countryName             = match
    stateOrProvinceName     = match
    localityName            = match
    organizationName        = match
    organizationalUnitName  = supplied
    commonName              = supplied
    emailAddress            = optional

"""

### Section Templates
templateCA = """# CA - %(caId)s (%(caPath)s)
[ ca_%(caId)s ]
    certificate         = %(caRootPath)s/%(caId)s.crt
    private_key         = %(caPath)s/ca/private.key

    certs               = %(caPath)s/crt
    new_certs_dir       = %(caPath)s/new

    crl                 = %(caRootPath)s/crl/%(caId)s.crl
    crl_dir             = %(caRootPath)s/crl

    crlnumber           = %(caPath)s/ca/crlno
    database            = %(caPath)s/ca/index.txt
    serial              = %(caPath)s/ca/srl
    RANDFILE            = %(caPath)s/ca/.rand

    cert_opt            = ca_default
    copy_extensions     = %(copyExt)s
    default_crl_days    = %(crlDays)d
    default_days        = %(reqDays)d
    default_md          = %(certMD)s
    email_in_dn         = no
    name_opt            = $name_opt
    policy              = %(caPolicy)s
    preserve            = no
    unique_subject      = no
    %(caCRLExt)s
"""

templateCASection = """[ ca ]
    # Default to root CA
    default_ca      = ca_%(caId)s

"""

templateCRL = """[ ext_%(caId)s_crl ]
    authorityInfoAccess     = @%(aiaSection)s
    authorityKeyIdentifier  = keyid:always

"""

templateRequest = """# Request
[ req ]
    default_bits        = %(certBits)s
    default_md          = %(certMD)s
    distinguished_name  = %(reqDN)s
    encrypt_key         = %(reqEncrypt)s
    prompt              = no
    x509_extensions     = %(reqTemplate)s
    string_mask         = utf8only
    utf8                = yes

"""

### CA Class
class CertificateAuthority:
    policy = ['policy_default', 'policy_org', 'policy_anything']
    defaultPolicy = 0

    def __init__(self, db, caRootPath, id=None, name=None):
        c = db.cursor()

        # Retreive CA information
        if id:
            self.id = id
            c.execute('SELECT ident, parent, chain, policy, crl, issue, ocsp FROM ca WHERE id = ?', (id,))
        elif name:
            self.name = name
            c.execute('SELECT id, parent, chain, policy, crl, issue, ocsp FROM ca WHERE ident = ?', (name,))
        else:
            raise CertificateException('CA must be identified by ID or name')

        row = c.fetchmany()

        # Fill in missing information
        if len(row) != 1:
            raise CertificateException('Specified CA does not exist')

        if not id:
            self.id = row[0][0]

        if not name:
            self.name = row[0][0]

        # Fetch parent CA if required
        if row[0][1]:
            self.parent = CertificateAuthority(db, caRootPath, id=row[0][1])
        else:
            self.parent = None

        self.rootPath = caRootPath
        self.path = os.path.join(caRootPath, self.name)

        self.chain = row[0][2]
        self.policy = row[0][3]
        self.crl = row[0][4]
        self.issue = row[0][5]
        self.ocsp = row[0][6]

        # Generate AIA and CRL sections to pass to extensions
        self.crlSection = None

        if self.issue or self.ocsp:
            self.aiaSection = "%s_info_aia" % (self.name)
        else:
            self.aiaSection = None

        if self.crl:
            self.crlSection = "%s_info_crl" % (self.name)
        else:
            self.crlSection = None

    def generateCA(self, copyExt=False):
        # Inclide CRL section if AIA information is provided
        crlExt = "crl_extensions\t= ext_%s_crl\n" % (self.name) if self.issue or self.ocsp else '\n'

        cnf = templateCA % {
            'caId': self.name,
            'caPath': self.path,
            'caRootPath': self.rootPath,
            'caPolicy': self.policy,
            'caCRLExt': crlExt,
            'copyExt': 'copyall' if copyExt else 'none',
            'crlDays': CertificateRequest.defaultCRLDays,
            'reqDays': CertificateRequest.defaultCertDays,
            'certMD': CertificateRequest.defaultCertMD
        }

        # CRL extension section
        if self.aiaSection:
            cnf += templateCRL % {
                'caId': self.name,
                'aiaSection': self.aiaSection
            }

            cnf += "[ %s ]\n" % (self.aiaSection)

            if self.issue:
                cnf += "\tcaIssuers;URI.0\t= %s\n" % (self.issue)

            if self.ocsp:
                cnf += "\tOCSP;URI.0\t= %s\n" % (self.ocsp)

            cnf += '\n'

        if self.crlSection:
            cnf += "[ %s ]\n\tURI.0\t= %s\n\n" % (self.crlSection, self.crl)

        return cnf

    @staticmethod
    def create(db, caRootPath, name, parent, chain, policy, crl, issue, ocsp, req):
        # Check for existing CA on path
        caPath = os.path.join(caRootPath, name)

        if os.path.exists(caPath):
            raise CertificateException('Specified CA directory already exists')

        # Get parent if necessary
        if parent and not isinstance(parent, CertificateAuthority):
            parent = CertificateAuthority(db, caRootPath, name=parent)

        # Create new CA directory
        try:
            os.makedirs(caPath)

            # Create directory structure
            for p in ('ca', 'crt', 'key', 'new', 'p12', 'req'):
                os.makedirs(os.path.join(caPath, p))

            # Secure directories
            for p in ('ca',):
                os.chmod(os.path.join(caPath, p), stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            # Create database and serial files
            for p in ('index.txt',):
                touch(os.path.join(caPath, 'ca', p))

            with open(os.path.join(caPath, 'ca', 'srl'), 'w') as f:
                f.write('01')

            with open(os.path.join(caPath, 'ca', 'crlno'), 'w') as f:
                f.write('01')
        except:
            try:
                shutil.rmtree(caPath)
            except:
                pass
            raise

        # Add new CA to database
        try:
            c = db.cursor()

            c.execute('INSERT INTO ca VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)', (name, parent.id if parent else None, chain, policy, crl, issue, ocsp))

            db.commit()
        except:
            try:
                shutil.rmtree(caPath)
            except:
                pass
            raise

        # Generate CA section
        ca = CertificateAuthority(db, caRootPath, name=name)

        if not parent:
            signer = None
        else:
            signer = parent

        # Generate certificate request section
        crtPath = os.path.join(caRootPath, "%s.crt" % (name))
        keyPath = os.path.join(caPath, 'ca', 'private.key')

        req.sign(signer, crtPath, keyPath)

        return ca

    @staticmethod
    def delete(db, caRootPath, name):
        caPath = os.path.join(caRootPath, name)

        c = db.cursor()
        c.execute('DELETE FROM ca WHERE ident = ?', (name,))
        db.commit()

        shutil.rmtree(caPath)

    @staticmethod
    def generateCASection(caid):
        return templateCASection % {
            'caId': caid
        }

    @staticmethod
    def openDatabase(caRootPath):
        # Create new base directory if necessary
        newBase = False

        try:
            if not os.path.isdir(caRootPath):
                newBase = True
                os.makedirs(caRootPath)
                os.makedirs(os.path.join(caRootPath, 'crl'))

            dbPath = os.path.join(caRootPath, 'ca.db')

            db = sqlite3.connect(dbPath)

            if newBase:
                c = db.cursor()
                c.execute('CREATE TABLE ca (id INTEGER PRIMARY KEY, ident TEXT NOT NULL UNIQUE, parent INTEGER, chain INTEGER, policy TEXT, crl TEXT, issue TEXT, ocsp TEXT)')
                c.execute('CREATE TABLE cert (id INTEGER PRIMARY KEY, ident TEXT NOT NULL UNIQUE, ca INTEGER NOT NULL)')
                db.commit()
        except:
            raise CertificateException('Failed to open CA database')

        return db

### Certificate request class
class CertificateRequest:
    KEY_OID = {
        'ipsecEndSystem': '1.3.6.1.5.5.7.3.5',
        'ipsecIntermediate': '1.3.6.1.5.5.8.2.2',
        'ipsecTermination': '1.3.6.1.5.5.7.3.6',
        'ipsecUser': '1.3.6.1.5.5.7.3.7',
        'kdcAuth': '1.3.6.1.5.2.3.5',
        'msBitlocker': '1.3.6.1.4.1.311.67.1.1',
        'msBitlockerRecover': '1.3.6.1.4.1.311.67.1.2',
        'msDocumentSign': '1.3.6.1.4.1.311.10.3.12',
        'msEFSRecover': '1.3.6.1.4.1.311.10.3.4.1',
        'msKeyRecover': '1.3.6.1.4.1.311.10.3.11',
        'msKeyRecoverAgent': '1.3.6.1.4.1.311.21.6',
        'msKernelCodeSign': '1.3.6.1.4.1.311.61.1.1',
        'msLifetimeLimit': '1.3.6.1.4.1.311.10.3.13',
        'msSmartCard': '1.3.6.1.4.1.311.20.2.2',
        'msDriverSign': '1.3.6.1.4.1.311.10.3.5',
        'msDriverSignOEM': '1.3.6.1.4.1.311.10.3.7',
        'ocspSign': '1.3.6.1.5.5.7.3.9'
    }

    KEY_USAGE = [
        'digitalSignature',
        'nonRepudiation',
        'keyEncipherment',
        'dataEncipherment',
        'keyAgreement',
        'keyCertSign',
        'cRLSign',
        'encipherOnly',
        'decipherOnly'
    ]

    KEY_PURPOSE = [
        'serverAuth',
        'clientAuth',
        'codeSigning',
        'emailProtection',
        'timeStamping',
        'msCodeInd',
        'msCodeCom',
        'msCTLSign',
        'msSGC',
        'msEFS',
        'nsSGC'
    ]

    CERT_MD = [
        'md2',
        'md5',
        'mdc2',
        'rmd160',
        'sha',
        'sha1',
        'sha224',
        'sha256',
        'sha384',
        'sha512'
    ]

    CRL_REASON = [
        'unspecified',
        'keyCompromise',
        'CACompromise',
        'affiliationChanged',
        'superseded',
        'cessationOfOperation',
        'certificateHold',
        'removeFromCRL'
    ]

    class Template:
        def __init__(self, id, usage=None, ca=False, caPathLength=-1, root=False):
            self.id = id
            self.usage = usage
            self.ca = ca
            self.caPathLength = caPathLength
            self.root = root

        def generateExt(self, aiaSection=None, crlSection=None, altNameSection=None, skipBasic=False):
            cnf = "[ %s ]\n" % (self.id)

            if not skipBasic:
                if self.ca:
                    if self.caPathLength >= 0:
                        cnf += "\tbasicConstraints  = critical, CA:true, pathlen:%d\n" % (self.caPathLength)
                    else:
                        cnf += '\tbasicConstraints  = critical, CA:true\n'
                else:
                    cnf += '\tbasicConstraints  = critical, CA:false\n'

            # Key usage
            if self.usage:
                basicUsage = []
                extendedUsage = []

                for use in self.usage:
                    if use in CertificateRequest.KEY_USAGE:
                        basicUsage.append(use)
                    elif use in CertificateRequest.KEY_PURPOSE:
                        extendedUsage.append(use)
                    elif use in CertificateRequest.KEY_OID.keys():
                        extendedUsage.append(CertificateRequest.KEY_OID[use])
                    else:
                        raise CertificateException('Invalid key usage type')

                if len(basicUsage) > 0:
                    cnf += "\tkeyUsage  = critical, %s\n" % (', '.join(basicUsage))

                if len(extendedUsage) > 0:
                    cnf += "\textendedKeyUsage  = %s\n" % (', '.join(extendedUsage))

            if altNameSection:
                cnf += "\tsubjectAltName    = @%s\n" % (altNameSection)

            if aiaSection:
                cnf += "\tauthorityInfoAccess   = @%s\n" % (aiaSection)

            if crlSection:
                cnf += "\tcrlDistributionPoints = @%s\n" % (crlSection)

            if not self.root:
                cnf += '\tauthorityKeyIdentifier    = keyid\n'

            cnf += '\tsubjectKeyIdentifier  = hash\n\n'

            return cnf

    caTemplate = [
        'keyCertSign',
        'cRLSign'
    ]

    certificateExtCopy = Template('ext_copy')

    certificateTemplate = [
        Template('cert_host', [
            'digitalSignature',
            'keyAgreement',
            'keyEncipherment',
            'serverAuth',
            'clientAuth'
        ]),
        Template('cert_user', [
            'dataEncipherment',
            'digitalSignature',
            'keyEncipherment',
            'clientAuth',
            'emailProtection'
        ]),
        Template('cert_ms', [
            'dataEncipherment',
            'digitalSignature',
            'keyEncipherment',
            'clientAuth',
            'emailProtection',
            'msEFS',
            'msBitlocker',
            'msDocumentSign',
            'msSmartCard'
        ]),
        Template('cert_dev', [
            'dataEncipherment',
            'digitalSignature',
            'keyEncipherment',
            'codeSigning',
            'clientAuth',
            'emailProtection',
            'msEFS',
            'msBitlocker',
            'msDocumentSign',
            'msSmartCard'
        ]),
        Template('cert_admin', [
            'dataEncipherment',
            'digitalSignature',
            'keyEncipherment',
            'clientAuth',
            'emailProtection',
            'msEFS',
            'msBitlocker',
            'msBitlockerRecover',
            'msDocumentSign',
            'msEFSRecover',
            'msSmartCard'
        ]),
        Template('cert_sign', [
            'digitalSignature',
            'codeSigning',
            'msCodeInd',
            'msCodeCom',
            'msDocumentSign'
        ])
    ]

    defaultBits = 2048
    defaultCertMD = 'sha1'
    defaultCertDays = 365
    defaultCRLDays = 30
    defaultReason = 'unspecified'

    def __init__(self, id, name, ca, template, altNames=None, organisation=None, organisationUnit=None, country=None, state=None, city=None, email=None, days=defaultCertMD, bits=defaultBits, encrypt=False, md=defaultCertMD):
        self.id = id
        self.name = name
        self.altNames = altNames

        self.ca = ca

        self.country = country
        self.state = state
        self.city = city

        self.organisation = organisation
        self.organisationUnit = organisationUnit

        self.email = email

        self.bits = bits
        self.days = days
        self.template = template

        self.encrypt = encrypt
        self.md = md

    def generateReq(self):
        altid = '_'.join(['alt', self.id])
        dnid = '_'.join(['dn', self.id])

        # Distinguished name
        cnf = "[ %s ]\n" % (dnid)

        if self.country:
            cnf += "\tcountryName = %s\n" % (self.country)

        if self.state:
            cnf += "\tstateOrProvinceName = %s\n" % (self.state)

        if self.city:
            cnf += "\tlocalityName = %s\n" % (self.city)

        if self.organisation:
            cnf += "\torganizationName = %s\n" % (self.organisation)

            if self.organisationUnit:
                cnf += "\torganizationalUnitName = %s\n" % (self.organisationUnit)

        if self.email:
            cnf += "\temailAddress = %s\n" % (self.email)

        if self.name:
            cnf += "\tcommonName = %s\n" % (self.name)

        cnf += '\n'

        # Allow email as an alternate name if the key can be used for email protection
        if self.email and 'emailProtection' in self.template.usage:
            if not self.altNames:
                self.altNames = []

            self.altNames.append('email:copy')

        # Generate alternate names section
        if self.altNames:
            cnf += "[ %s ]\n" % (altid)

            if self.altNames:
                nameType = {}

                for name in self.altNames:
                    # Split name into components
                    nameSplit = name.split(':')

                    if len(nameSplit) != 2:
                        raise CertificateException('Alternate name format invalid')

                    k = nameSplit[0].lower()

                    if not nameType.has_key(k):
                        nameType[k] = 1
                    else:
                        nameType[k] = nameType[k] + 1

                    cnf += "\t%s.%d = %s\n" % (nameSplit[0], nameType[k], nameSplit[1])

            cnf += '\n'

        # Extensions for certificate
        aiaSection = self.ca.aiaSection if self.ca else None
        crlSection = self.ca.crlSection if self.ca else None

        cnf += self.template.generateExt(aiaSection=aiaSection, crlSection=crlSection, altNameSection=altid if self.altNames else None)

        # req section
        cnf += templateRequest % {
            'reqDN': dnid,
            'reqEncrypt': 'yes' if self.encrypt else 'no',
            'reqTemplate': self.template.id,
            'certBits': self.bits,
            'certMD': self.md
        }

        return cnf

    def sign(self, ca, crtPath, keyPath):
        cnfFile = tempConfig(ca, self)

        # Generate certificate
        if ca:
            csrFile = tempfile.NamedTemporaryFile(prefix='csr', delete=False)
            csrFile.close()

            cmdReq = "openssl req -config %s -new -keyout %s -out %s" % (cnfFile.name, keyPath, csrFile.name)
            cmdCA = "openssl ca -config %s -out %s -in %s -batch -days %d -extensions %s -md %s" % (cnfFile.name, crtPath, csrFile.name, self.days, self.template.id, self.md)

            print cmdReq
            if subprocess.call(cmdReq.split(' ')):
                os.unlink(csrFile.name)
                raise CertificateException('Failed to create certificate signing request')

            print cmdCA
            if subprocess.call(cmdCA.split(' ')):
                raise CertificateException('Failed to sign certificate')

            os.unlink(csrFile.name)
        else:
            cmdReq = "openssl req -x509 -config %s -new -keyout %s -out %s -days %d" % (cnfFile.name, keyPath, crtPath, self.days)

            print cmdReq
            if subprocess.call(cmdReq.split(' ')):
                raise CertificateException('Failed to create self-signed certificate')

        # Delete config file
        os.unlink(cnfFile.name)

### Helper functions
def tempConfig(ca=None, req=None, template=None, copyExt=False):
    cnf = templateBaseCA

    if ca:
        cnf += ca.generateCA(copyExt)

        cnf += CertificateAuthority.generateCASection(ca.name)

    if req:
        cnf += req.generateReq()

    if template:
        for t in template:
            cnf += t.generateExt(aiaSection=ca.aiaSection, crlSection=ca.crlSection, skipBasic=True)

    # Save configuration to temporary file
    cnfFile = tempfile.NamedTemporaryFile(prefix='openssl', delete=False)

    cnfFile.write(cnf)
    cnfFile.close()

    return cnfFile

def printTreeCA(node, prefix=''):
    print prefix + node[0]

    childPrefix = prefix.replace(u'└', u'│').replace(u'├', u'│').replace(u'─', u' ')

    if len(node[1]) > 0:
        for n in node[1][:-1]:
            printTreeCA(n, childPrefix + u'├─')

        printTreeCA(node[1][-1], childPrefix + u'└─')

def touch(path):
    open(path, 'a').close()

def main():
    # Command line arguments
    parser = argparse.ArgumentParser(description='Certificate Authority')

    parser.add_argument('--base', help='Base directory', default='/etc/ca', dest='base')

    subparsers_root = parser.add_subparsers(help='CA commands', dest='action')

    # Generate new certificates
    parser_gen = subparsers_root.add_parser('gen', help='Generate new CA or certificates')
    parser_gen.add_argument('--encrypt', help='Encrypt private key', action='store_true', dest='cert_encrypt')
    parser_gen.add_argument('--bits', help="Certificate bits (default: %d)" % (CertificateRequest.defaultBits), dest='cert_bits', metavar='BITS', type=int, default=CertificateRequest.defaultBits)
    parser_gen.add_argument('--days', help="Certificate expiry (default: %d)" % (CertificateRequest.defaultCertDays), dest='cert_days', metavar='DAYS', type=int, default=CertificateRequest.defaultCertDays)
    parser_gen.add_argument('--md', help="Certificate hash algorithm (default: %s)" % (CertificateRequest.defaultCertMD), dest='cert_md', default=CertificateRequest.defaultCertMD, choices=CertificateRequest.CERT_MD)
    parser_gen.add_argument('--org', help='Certificate organization', dest='cert_org')
    parser_gen.add_argument('--unit', help='Certificate organizational unit', dest='cert_unit')
    parser_gen.add_argument('--country', help='Certificate country', dest='cert_country')
    parser_gen.add_argument('--state', help='Certificate state', dest='cert_state')
    parser_gen.add_argument('--city', help='Certificate city', dest='cert_city')

    subparsers_gen = parser_gen.add_subparsers(help='Certificate generation options', dest='gen_type')

    # Generate - New CA
    parser_gen_ca = subparsers_gen.add_parser('ca', help='New CA')
    parser_gen_ca.add_argument('ca_id', help='CA identifier')
    parser_gen_ca.add_argument('ca_name', help='CA common name')
    parser_gen_ca.add_argument('--parent', help='Parent CA', dest='ca_parent')
    parser_gen_ca.add_argument('--chain', help='CA maximum chain length', dest='ca_chain', type=int, default=-1)
    parser_gen_ca.add_argument('--policy', help='CA signing policy', dest='ca_policy', default=CertificateAuthority.policy[CertificateAuthority.defaultPolicy], choices=CertificateAuthority.policy)
    parser_gen_ca.add_argument('--issuer', help='Issuing CA URL', dest='ca_issue', metavar='URL')
    parser_gen_ca.add_argument('--crl', help='CRL URL', dest='ca_crl', metavar='URL')
    parser_gen_ca.add_argument('--ocsp', help='OCSP URL', dest='ca_ocsp', metavar='URL')

    # Generate - New certificate
    parser_gen_cert = subparsers_gen.add_parser('cert', help='New certificate')
    parser_gen_cert.add_argument('ca_id', help='Signing CA identifier')
    parser_gen_cert.add_argument('cert_id', help='Certificate identifier')
    parser_gen_cert.add_argument('cert_type', help='Certificate usage', choices=[x.id for x in CertificateRequest.certificateTemplate])
    parser_gen_cert.add_argument('cert_name', help='Certificate name(s)', nargs='+')
    parser_gen_cert.add_argument('--email', help='Certificate email', dest='cert_email')

    # CA managment options
    parser_ca = subparsers_root.add_parser('ca', help='CA managment')
    parser_ca.add_argument('ca_id', help='CA identifier')

    subparsers_ca = parser_ca.add_subparsers(help='CA managment options', dest='ca_action')

    # CA managment - Certificate revoke
    parser_ca_revoke = subparsers_ca.add_parser('revoke', help='Revoke certificate')
    parser_ca_revoke.add_argument('cert_id', help='Certificate identifier')
    parser_ca_revoke.add_argument('revoke_reason', help='Reason for revoking certificate', default=CertificateRequest.defaultReason, choices=CertificateRequest.CRL_REASON)

    # CA managment - Certificate renew
    parser_ca_renew = subparsers_ca.add_parser('renew', help='Renew certificate')
    parser_ca_renew.add_argument('cert_id', help='Certificate identifier')
    parser_ca_renew.add_argument('--days', help="Certificate expiry (default: %d)" % (CertificateRequest.defaultCertDays), dest='cert_days', metavar='DAYS', type=int, default=CertificateRequest.defaultCertDays)
    parser_ca_renew.add_argument('--md', help="Certificate hash algorithm (default: %s)" % (CertificateRequest.defaultCertMD), dest='cert_md', default=CertificateRequest.defaultCertMD, choices=CertificateRequest.CERT_MD)

    # CA managment - Delete CA
    parser_ca_rm = subparsers_ca.add_parser('rm', help='Delete certificate authority')

    # CA managment - Export
    parser_export = subparsers_ca.add_parser('export', help='Export certificates in PKCS12 format')
    parser_export.add_argument('cert_id', help='Certificate identifier')
    parser_export.add_argument('output', help='Exported file name')

    # CRL options
    parser_crl = subparsers_root.add_parser('crl', help='Update CRL(s)')
    parser_crl.add_argument('crl_ca', help='CA identifier', nargs='*')
    parser_crl.add_argument('--days', help="CRL expiry (default: %d)" % (CertificateRequest.defaultCRLDays), dest='crl_days', metavar='DAYS', type=int, default=CertificateRequest.defaultCRLDays)
    parser_crl.add_argument('--md', help="CRL hash algorithm (default: %s)" % (CertificateRequest.defaultCertMD), dest='crl_md', default=CertificateRequest.defaultCertMD, choices=CertificateRequest.CERT_MD)

    # List options
    parser_ls = subparsers_root.add_parser('ls', help='List available CAs')

    # Signature options
    parser_sign = subparsers_root.add_parser('sign', help='Sign certificate request')
    parser_sign.add_argument('ca_id', help='Signing CA')
    parser_sign.add_argument('cert_id', help='Certificate identifier')
    parser_sign.add_argument('csr', help='Certificate signing request')
    parser_sign.add_argument('--days', help="Certificate expiry (default: %d)" % (CertificateRequest.defaultCertDays), dest='cert_days', metavar='DAYS', type=int, default=CertificateRequest.defaultCertDays)
    parser_sign.add_argument('--md', help="Certificate hash algorithm (default: %s)" % (CertificateRequest.defaultCertMD), dest='cert_md', default=CertificateRequest.defaultCertMD, choices=CertificateRequest.CERT_MD)

    args = parser.parse_args()

    # Check for existing CA directory
    caRootPath = os.path.abspath(args.base)

    # Connect to database
    db = CertificateAuthority.openDatabase(caRootPath)
    c = db.cursor()

    cnfFile = None

    if args.action == 'gen':
        # Generate new CA/certificate
        if args.gen_type == 'ca':
            ca = None

            if args.ca_parent:
                ca = CertificateAuthority(db, caRootPath, name=args.ca_parent)

            template = CertificateRequest.Template('ext_ca', CertificateRequest.caTemplate, True, args.ca_chain, args.ca_parent == None)

            req = CertificateRequest(
                id=args.ca_id,
                name=args.ca_name,
                ca=ca,
                template=template,
                organisation=args.cert_org,
                organisationUnit=args.cert_unit,
                country=args.cert_country,
                state=args.cert_state,
                city=args.cert_city,
                email=args.cert_email,
                days=args.cert_days,
                bits=args.cert_bits,
                encrypt=args.cert_encrypt,
                md=args.cert_md
            )

            # Create new certificate authority
            try:
                CertificateAuthority.create(db, caRootPath, args.ca_id, args.ca_parent, args.ca_chain, args.ca_policy, args.ca_crl, args.ca_issue, args.ca_ocsp, req)
            except:
                CertificateAuthority.delete(db, caRootPath, args.ca_id)
                raise

            print 'Created new CA: ' + args.ca_id
        elif args.gen_type == 'cert':
            # Get selected CA
            ca = CertificateAuthority(db, caRootPath, name=args.ca_id)

            template = None

            for t in CertificateRequest.certificateTemplate:
                if t.id == args.cert_type:
                    template = t
                    break

            req = CertificateRequest(
                id=args.cert_id,
                name=args.cert_name[0],
                altNames=args.cert_name[1:],
                ca=ca,
                template=template,
                organisation=args.cert_org,
                organisationUnit=args.cert_unit,
                country=args.cert_country,
                state=args.cert_state,
                city=args.cert_city,
                email=args.cert_email,
                days=args.cert_days,
                bits=args.cert_bits,
                encrypt=args.cert_encrypt,
                md=args.cert_md
            )

            # Generate certificate
            crtPath = os.path.join(ca.path, 'crt', "%s.crt" % (args.cert_id))
            keyPath = os.path.join(ca.path, 'key', "%s.key" % (args.cert_id))

            req.sign(ca, crtPath, keyPath)
        else:
            raise CertificateException('Unsuported generation option')
    elif args.action == 'ca':
        ca = CertificateAuthority(db, caRootPath, name=args.ca_id)
        cnfFile = tempConfig(ca)

        if args.ca_action == 'revoke':
            # Revoke certificate
            crtPath = os.path.join(ca.path, 'crt', "%s.crt" % (args.cert_id))

            cmdCA = "openssl ca -config %s -revoke %s -crl_reason %s" % (cnfFile.name, crtPath, args.revoke_reason)

            print cmdCA
            if subprocess.call(cmdCA.split(' ')):
                raise CertificateException('Failed to revoke certificate')

            print 'Certificate revoked: ' + args.cert_id
        elif args.ca_action == 'rm':
            pass
        elif args.ca_action == 'export':
            # Package certificate in pkcs12 file
            #openssl pkcs12 -export -inkey $CA_dir/cert/$P12_name.key -in $CA_dir/cert/$P12_name.crt -out $CA_dir/p12/$P12_name.p12
            crtPath = os.path.join(ca.path, 'crt', "%s.crt" % (args.cert_id))
            keyPath = os.path.join(ca.path, 'key', "%s.key" % (args.cert_id))

            cmdPkcs = "openssl pkcs12 -export -inkey %s -in %s -out %s" % (keyPath, crtPath, args.output)

            print cmdPkcs
            if subprocess.call(cmdPkcs.split(' ')):
                raise CertificateException('Failed to export certificate')

            print 'Exported certificate: ' + args.cert_id
        else:
            raise CertificateException('Unimplemented option')

    elif args.action == 'crl':
        # Generate CRL
        if args.crl_ca:
            caList = args.crl_ca
        else:
            caList = []

            for r in c.execute('SELECT ident FROM ca'):
                caList.append(r[0])

        caList = [CertificateAuthority(db, caRootPath, name=name) for name in caList]

        for ca in caList:
            cnfFile = tempConfig(ca)
            crlFile = os.path.join(caRootPath, 'crl', "%s.crl" % (ca.name))

            cmdCA = "openssl ca -config %s -md %s -gencrl -crldays %d -out %s" % (cnfFile.name, args.crl_md, args.crl_days, crlFile)
            cmdCRL = "openssl crl -in %s -outform der -out %s" % (crlFile, crlFile)

            print cmdCA
            if subprocess.call(cmdCA.split(' ')):
                raise CertificateException('Failed to generate CRL')

            print cmdCRL
            if subprocess.call(cmdCRL.split(' ')):
                raise CertificateException('Failed to convert CRL')

            print 'Generated CRL: ' + ca.name
    elif args.action == 'ls':
        # List all known CAs and their children
        caList = {}

        # Build tree of CAs
        for r in c.execute('SELECT id, ident, parent, chain FROM ca ORDER BY id ASC'):
            caId = r[0]
            caName = r[1]
            caParent = r[2]
            caChain = r[3]

            if caChain >= 0:
                caName = caName

            ca = (caName, [])

            if caParent:
                # Intermediate CA
                caList[caParent][1].append(ca)
            else:
                # Root CA
                caList[caId] = ca

        # Print CA tree
        for ca in caList.values():
            printTreeCA(ca)
    elif args.action == 'sign':
        # Sign existing CSR
        ca = CertificateAuthority(db, caRootPath, name=args.ca_id)

        cnfFile = tempConfig(ca, template=[CertificateRequest.certificateExtCopy], copyExt=True)
        crtPath = os.path.join(ca.path, 'crt', "%s.crt" % (args.cert_id))

        cmdCA = "openssl ca -config %s -out %s -in %s -days %d -extensions %s -md %s" % (cnfFile.name, crtPath, args.csr, args.cert_days, CertificateRequest.certificateExtCopy.id, args.cert_md)

        print cmdCA
        if subprocess.call(cmdCA.split(' ')):
                raise CertificateException('Failed to sign CSR')

        print 'Signed CSR: ' + args.cert_id
    else:
        raise CertificateException('Unimplemented option')

    # Delete temporary config file if generated
    if cnfFile:
        os.unlink(cnfFile.name)

if __name__ == '__main__':
    main()
