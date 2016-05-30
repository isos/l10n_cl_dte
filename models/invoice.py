# -*- coding: utf-8 -*-
##############################################################################
# For copyright and license notices, see __openerp__.py file in module root
# directory
##############################################################################
from openerp import fields, models, api, _
from openerp.exceptions import Warning
from datetime import datetime, timedelta
import logging
import lxml.etree as etree
from lxml import objectify
from lxml.etree import XMLSyntaxError
from openerp import SUPERUSER_ID

import xml.dom.minidom
import pytz


import socket
import collections

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

# ejemplo de suds
import traceback as tb
import suds.metrics as metrics
#from tests import *
#from suds import WebFault
#from suds.client import Client
# from suds.sax.text import Raw
# import suds.client as sudscl

try:
    from suds.client import Client
except:
    pass
# from suds.transport.https import WindowsHttpAuthenticated
# from suds.cache import ObjectCache

# ejemplo de suds

# intento con urllib3
try:
    import urllib3
except:
    pass

# from urllib3 import HTTPConnectionPool
pool = urllib3.PoolManager()

# from inspect import currentframe, getframeinfo
# estas 2 lineas son para imprimir el numero de linea del script
# (solo para debug)

_logger = logging.getLogger(__name__)

try:
    import xmltodict
except ImportError:
    _logger.info('Cannot import xmltodict library')

try:
    import dicttoxml
except ImportError:
    _logger.info('Cannot import dicttoxml library')

try:
    from elaphe import barcode
except ImportError:
    _logger.info('Cannot import elaphe library')

try:
    import M2Crypto
except ImportError:
    _logger.info('Cannot import M2Crypto library')

try:
    import base64
except ImportError:
    _logger.info('Cannot import base64 library')

try:
    import hashlib
except ImportError:
    _logger.info('Cannot import hashlib library')

try:
    import cchardet
except ImportError:
    _logger.info('Cannot import hashlib library')

try:
    from SOAPpy import SOAPProxy
except ImportError:
    _logger.info('Cannot import SOOAPpy')

try:
    from signxml import xmldsig, methods
except ImportError:
    _logger.info('Cannot import signxml')

# timbre patrón. Permite parsear y formar el
# ordered-dict patrón corespondiente al documento
timbre  = """<TED version="1.0"><DD><RE>99999999-9</RE><TD>11</TD><F>1</F>\
<FE>2000-01-01</FE><RR>99999999-9</RR><RSR>\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</RSR><MNT>10000</MNT><IT1>IIIIIII\
</IT1><CAF version="1.0"><DA><RE>99999999-9</RE><RS>YYYYYYYYYYYYYYY</RS>\
<TD>10</TD><RNG><D>1</D><H>1000</H></RNG><FA>2000-01-01</FA><RSAPK><M>\
DJKFFDJKJKDJFKDJFKDJFKDJKDnbUNTAi2IaDdtAndm2p5udoqFiw==</M><E>Aw==</E></RSAPK>\
<IDK>300</IDK></DA><FRMA algoritmo="SHA1withRSA">\
J1u5/1VbPF6ASXkKoMOF0Bb9EYGVzQ1AMawDNOy0xSuAMpkyQe3yoGFthdKVK4JaypQ/F8\
afeqWjiRVMvV4+s4Q==</FRMA></CAF><TSTED>2014-04-24T12:02:20</TSTED></DD>\
<FRMT algoritmo="SHA1withRSA">jiuOQHXXcuwdpj8c510EZrCCw+pfTVGTT7obWm/\
fHlAa7j08Xff95Yb2zg31sJt6lMjSKdOK+PQp25clZuECig==</FRMT></TED>"""
result = xmltodict.parse(timbre)
# result es un OrderedDict patrón

# porcion_firma_documento = """\
# <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
# <SignedInfo>
# <CanonicalizationMethod \
# Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
# <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
# <Reference URI="#{0}">
# <Transforms>
# <Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
# </Transforms>
# <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
# <DigestValue>{1}</DigestValue>
# </Reference>
# </SignedInfo>
# <SignatureValue>{2}</SignatureValue>
# <KeyInfo>
# <KeyValue>
# <RSAKeyValue>
# <Modulus>{3}</Modulus>
# <Exponent>{4}</Exponent>
# </RSAKeyValue>
# </KeyValue>
# <X509Data>
# <X509Certificate>
# {5}
# </X509Certificate>
# </X509Data>
# </KeyInfo>
# </Signature>
# """
#
server_url = 'https://maullin.sii.cl/DTEWS/'

BC = '''-----BEGIN CERTIFICATE-----\n'''
EC = '''\n-----END CERTIFICATE-----\n'''

# hardcodeamos este valor por ahora
import os
xsdpath = os.path.dirname(os.path.realpath(__file__)).replace('/models','/static/xsd/')

connection_status = {
    '0': 'Upload OK',
    '1': 'El Sender no tiene permiso para enviar',
    '2': 'Error en tamaño del archivo (muy grande o muy chico)',
    '3': 'Archivo cortado (tamaño <> al parámetro size)',
    '5': 'No está autenticado',
    '6': 'Empresa no autorizada a enviar archivos',
    '7': 'Esquema Invalido',
    '8': 'Firma del Documento',
    '9': 'Sistema Bloqueado',
    'Otro': 'Error Interno.',
}

class invoice(models.Model):
    _inherit = "account.invoice"

    def split_cert(self, cert):
        # certp = cert.replace('\n', '')
        certf, j = '', 0
        for i in range(0, 29):
            certf += cert[76 * i:76 * (i + 1)] + '\n'
        return certf

    def create_template_envio(self, RutEmisor, RutReceptor, FchResol, NroResol,
                              TmstFirmaEnv, TpoDTE, EnvioDTE):
        xml = '''<SetDTE ID="OdooBMyA">
<Caratula version = "1.0">
<RutEmisor>{0}</RutEmisor>
<RutEnvia>{0}</RutEnvia>
<RutReceptor>{1}</RutReceptor>
<FchResol>{2}</FchResol>
<NroResol>{3}</NroResol>
<TmstFirmaEnv>{4}</TmstFirmaEnv>
<SubTotDTE>
<TpoDTE>{5}</TpoDTE>
<NroDTE>1</NroDTE>
</SubTotDTE>
</Caratula>
{6}
</SetDTE>'''.format(RutEmisor, RutReceptor, FchResol, NroResol, TmstFirmaEnv,
                    TpoDTE, EnvioDTE)
        return xml

    def convert_timezone(self, dia, time):
        print(datetime.strftime(datetime.now(), '%Y-%m-%dT%H:%M:%S'))
        print(datetime.strftime(datetime.now() - timedelta(hours=4), '%Y-%m-%dT%H:%M:%S'))
        # user = self.env['res.users'].browse(SUPERUSER_ID)
        # tz = pytz.timezone(user.partner_id.tz) or pytz.utc
        # print(tz)
        # naive = datetime.strptime(
        #     dia + 'T' + time, '%Y-%m-%dT%H:%M:%S')
        # print('naive', naive)
        # # si lo imprimo solo sale en formato estandar
        # local_dt = tz.localize(naive, is_dst=None)
        # utc_dt = local_dt.astimezone(pytz.utc)
        # print(utc_dt)
        # print(local_dt)
        # raise Warning('fucking time!')
        # return local_dt
        return datetime.now()

    def remove_indents(self, xml):
        return xml.replace(
            '        <','<').replace(
            '      <','<').replace(
            '    <','<').replace(
            '  <','<')

    def whatisthis(self, s):
        if isinstance(s, str):
            _logger.info("ordinary string")
        elif isinstance(s, unicode):
            _logger.info("unicode string")
        else:
            _logger.info("not a string")

    def xml_validator(self, some_xml_string, validacion='doc'):
        if 1==1:
            validacion_type = {
                'doc': 'DTE_v10.xsd',
                'env': 'EnvioDTE_v10.xsd',
                'sig': 'xmldsignature_v10.xsd'
            }
            xsd_file = xsdpath+validacion_type[validacion]
            try:
                schema = etree.XMLSchema(file=xsd_file)
                parser = objectify.makeparser(schema=schema)
                objectify.fromstring(some_xml_string, parser)
                _logger.info(_("The Document XML file validated correctly: \
(%s)") % validacion)
                return True
            except XMLSyntaxError as e:
                _logger.info(_("The Document XML file has error: %s") % e.args)
                raise Warning(_('XML Malformed Error %s') % e.args)

    ### funciones usadas en la autenticacion
    def get_seed(self):
        url = server_url + 'CrSeed.jws?WSDL'
        ns = 'urn:'+server_url + 'CrSeed.jws'
        _server = SOAPProxy(url, ns)
        root = etree.fromstring(_server.getSeed())
        semilla = root[0][0].text
        return semilla

    def create_template_seed(self, seed):
        xml = u'''<getToken>
<item>
<Semilla>{}</Semilla>
</item>
</getToken>
'''.format(seed)
        return xml

    def create_template_doc(self, doc):
        xml = u'''<DTE xmlns="http://www.sii.cl/SiiDte" version="1.0">
{}</DTE>'''.format(doc)
        # create_template_doc
        # anulo el efecto de la funcion
        # para hacer un detached
        return doc

    def create_template_doc1(self, doc, sign):
        xml = '''<DTE xmlns="http://www.sii.cl/SiiDte" version="1.0">
{}{}</DTE>'''.format(doc, sign)
        return xml

    def create_template_doc2(self, doc, sign):
        xml = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<EnvioDTE xmlns="http://www.sii.cl/SiiDte" \
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xsi:schemaLocation="http://www.sii.cl/SiiDte EnvioDTE_v10.xsd" \
version="1.0">
{}{}</EnvioDTE>'''.format(doc, sign)
        return xml

    def sign_seed(self, message, privkey, cert):
        doc = etree.fromstring(message)
        signed_node = xmldsig(
            doc, digest_algorithm=u'sha1').sign(
            method=methods.enveloped, algorithm=u'rsa-sha1',
            key=privkey.encode('ascii'),
            cert=cert)
        msg = etree.tostring(
            signed_node, pretty_print=True).replace('ds:', '')
        return msg

    def sign_full_xml(self, message, privkey, cert, uri, type='doc'):
        print('mensaje de entrada: %s' % type)
        print(message)
        # if type=='env':
        #     print('Asi entra el mensaje para la segunda firma')
        #     print(message)
        #     raise Warning('mensaje antrada segunda firma')
        doc = etree.fromstring(message)
        signed_node = xmldsig(
            doc, digest_algorithm=u'sha1').sign(
            method=methods.detached, algorithm=u'rsa-sha1',
            c14n_algorithm=u'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
            reference_uri='#'+uri,
            key=privkey.encode('ascii'))
        # welcome back to this library... let see what happen this time
        # signed_node = xmldsig(
        #     doc, digest_algorithm=u'sha1').sign(
        #     method=methods.detached, algorithm=u'rsa-sha1',
        #     key=privkey.encode('ascii'))
        Transforms = '''<Transforms>
        <Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      </Transforms>'''
        x509certificate = '''
    <X509Data>
      <X509Certificate>
{}</X509Certificate>
</X509Data>'''.format(cert)
        msg = etree.tostring(signed_node, pretty_print=True)
        msg = msg.replace(
            '</ds:KeyValue>', '''</ds:KeyValue>{}'''.format(x509certificate)).replace(
            '<ds:DigestMethod ', Transforms+'<ds:DigestMethod ').replace(
            'ds:', '').replace(':ds=', '=')
        print(msg)
        msg = msg if self.xml_validator(msg, 'sig') else ''

        print('validacion %s' % type)
        if type=='doc':
            fulldoc = self.create_template_doc1(message, msg)
        elif type=='env':
            fulldoc = self.create_template_doc2(message, msg)

        if type=='env':
            print(fulldoc)
            #raise Warning('fulldoc antes de validar env')
        fulldoc = fulldoc if self.xml_validator(fulldoc, type) else ''
        return fulldoc

    def get_token(self, seed_file):
        url = server_url + 'GetTokenFromSeed.jws?WSDL'
        ns = 'urn:'+ server_url +'GetTokenFromSeed.jws'
        _server = SOAPProxy(url, ns)
        tree = etree.fromstring(seed_file)
        ss = etree.tostring(tree, pretty_print=True, encoding='iso-8859-1')
        respuesta = etree.fromstring(_server.getToken(ss))
        token = respuesta[0][0].text
        return token

    def get_digital_signature_pem(self, comp_id):
        _logger.info(_('Executing digital signature function in PEM format'))
        _logger.info('Service provider for this company is %s' % comp_id)
        if comp_id.dte_service_provider in ['SIIHOMO', 'SII']:
            user_obj = self.env['res.users'].browse([self.env.user.id])
            signature_data = {
                'subject_name': user_obj.name,
                'subject_serial_number': user_obj.subject_serial_number,
                'priv_key': user_obj.priv_key,
                'cert': user_obj.cert}
            # _logger.info('The signature data is the following %s' % signature_data)
            # todo: chequear si el usuario no tiene firma, si esta autorizado por otro usuario
            return signature_data
        else:
            return ''

    def get_digital_signature(self, comp_id):
        _logger.info(_('Executing digital signature function'))
        _logger.info('Service provider for this company is %s' % comp_id)
        if comp_id.dte_service_provider in ['SIIHOMO', 'SII']:
            user_obj = self.env['res.users'].browse([self.env.user.id])
            signature_data = {
                'subject_name': user_obj.name,
                'subject_serial_number': user_obj.subject_serial_number,
                'priv_key': user_obj.priv_key,
                'cert': user_obj.cert}
                # 'cert': user_obj.cert.replace(
                #     '''-----BEGIN CERTIFICATE-----\n''','').replace(
                #     '''\n-----END CERTIFICATE-----\n''','')}
            _logger.info('The signature data is the following %s' % signature_data)
            # todo: chequear si el usuario no tiene firma, si esta autorizado por otro usuario
            return signature_data
        else:
            return ''

    def get_resolution_data(self, comp_id):
        _logger.info('Entering function get_resolution_data')
        _logger.info('Service provider for this company is %s' % comp_id)
        if comp_id.dte_service_provider == 'SIIHOMO':
            resolution_date = '2015-05-08'
            resolution_numb = '0'
            _logger.info('Using hardcoded resolution date and resolution \
number for Certification process')
        else:
            resolution_date = comp_id.dte_resolution_date
            resolution_numb = comp_id.dte_resolution_number
        resolution_data = {
            'dte_resolution_date': resolution_date,
            'dte_resolution_number': resolution_numb}
        return resolution_data

    @api.multi
    def send_xml_file(self):
        _logger.info('Entering Send XML Function')
        _logger.info(
            'Service provider is: %s' % self.company_id.dte_service_provider)

        if self.company_id.dte_service_provider == 'EFACTURADELSUR':
            host = 'https://www.efacturadelsur.cl'
            post = '/ws/DTE.asmx' # HTTP/1.1
            url = host + post
            _logger.info('URL to be used %s' % url)
            _logger.info('Lenght used for forming envelope: %s' % len(self.sii_xml_request))

            response = pool.urlopen('POST', url, headers={
                'Content-Type': 'application/soap+xml',
                'charset': 'utf-8',
                'Content-Length': len(
                    self.sii_xml_request)}, body=self.sii_xml_request)

            _logger.info(response.status)
            _logger.info(response.data)
            self.sii_xml_response = response.data
            self.sii_result = 'Enviado'

        elif self.company_id.dte_service_provider in ['SII', 'SIIHOMO']:
            _logger.info('Entering SII Alternative...')
            signature_d = self.get_digital_signature(self.company_id)
            resol_data = self.get_resolution_data(self.company_id)
            # todo: ver si es necesario chequear el estado de envio antes de
            # hacerlo, para no enviar dos veces.
            # Este lio es porque no puede recorrer los invoices directamente
            # sino que tiene que armar "remesas" de envío, clasificadas por
            # receptor y por tipo de documento, y llevar la cuenta de lo que
            # envía en cada una.
            _logger.info('Classifying sendings ordered by recipient/doc class')
            contador_invoice = {}
            for inv in self:
                receptor = self.format_vat(inv.partner_id.vat)
                clasedoc = str(inv.sii_document_class_id.sii_code)
                if receptor not in contador_invoice:
                    contador_invoice[receptor] = {}
                    if clasedoc not in contador_invoice[receptor]:
                        contador_invoice[receptor][clasedoc] = []
                if inv.sii_result != 'NoEnviado':
                    continue
                contador_invoice[receptor][clasedoc].append(inv.id)
                _logger.info('The following is a dictionary containing the \
ordered scheme for sending packages to SII:')
                print(contador_invoice)

            for receptor in contador_invoice:
                _logger.info('Receptor partner: %s' % receptor)
                caratula = collections.OrderedDict()
                caratula['RutEmisor'] = self.format_vat(inv.company_id.vat)
                caratula['RutEnvia'] = signature_d['subject_serial_number']
                caratula['RutReceptor'] = receptor
                caratula['FchResol'] = resol_data['dte_resolution_date']
                caratula['NroResol'] = resol_data['dte_resolution_number']
                caratula['TmstFirmaEnv'] = '--TmstFirmaEnv--'
                for clasedoc in contador_invoice[receptor]:
                    _logger.info('Doc Class %s, qty: %s' % (
                        clasedoc, len(contador_invoice[receptor][clasedoc])))
                    caratula['SubTotDTE'] = collections.OrderedDict()
                    caratula['SubTotDTE']['TpoDTE'] = clasedoc
                    caratula['SubTotDTE']['NroDTE'] = len(
                        contador_invoice[receptor][clasedoc])
                    _logger.info('Caratula for this sender and its invoices...')
                    print(caratula)
                    caratd = collections.OrderedDict()
                    caratd['Caratula'] = caratula
                    # transformación de la caratula en xml
                    # caratxml_pret = self.remove_indents(etree.tostring(
                    #     etree.XML(dicttoxml.dicttoxml(
                    #         caratd, root=False, attr_type=False)),
                    #         pretty_print=True).replace(
                    #         '<Caratula>', '<Caratula version="1.0">'))
                    # la caratula transformada sin remover indentaciones
                    caratxml_pret = etree.tostring(
                        etree.XML(dicttoxml.dicttoxml(
                            caratd, root=False, attr_type=False)),
                            pretty_print=True).replace(
                            '<Caratula>', '<Caratula version="1.0">')
                    invoices_to_send = ''
                    for invoice in contador_invoice[receptor][clasedoc]:
                        _logger.info('Invoices to send....')
                        print(invoice)
                        invoice_obj = self.env['account.invoice'].browse(
                            invoice)
                        invoices_to_send += invoice_obj.sii_xml_request

                    set_dte = '''
<SetDTE ID="OdooBMyA">
{}{}</SetDTE>'''.format(caratxml_pret, invoices_to_send)
                    # todo: chequear que si no tengo firma, algun usuario del
                    envio_dte = set_dte
#                    envio_dte = """<EnvioDTE xmlns="http://www.sii.cl/SiiDte" \
#xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
#xsi:schemaLocation="http://www.sii.cl/SiiDte EnvioDTE_v10.xsd" \
#version="1.0">{}</EnvioDTE>""".format(set_dte)
                    _logger.info('Envio de DTEs:...')
                    #envio_dte = envio_dte.replace(
                    #    '--TmstFirmaEnv--', datetime.strftime(
                    #        datetime.now(), '%Y-%m-%dT%H:%M:%S'))

                    envio_dte = envio_dte.replace(
                        '--TmstFirmaEnv--', self.convert_timezone(
                            datetime.strftime(datetime.now(), '%Y-%m-%d'),
                            datetime.strftime(
                                datetime.now(), '%H:%M:%S')).strftime(
                            '%Y-%m-%dT%H:%M:%S'))
                    envio_dte = '''<?xml version="1.0" \
encoding="ISO-8859-1"?>
{}'''.format(self.sign_full_xml(envio_dte, signature_d['priv_key'],
                                signature_d['cert'], 'OdooBMyA', 'env'))


                print(envio_dte)
                raise Warning('fuck send!')

                invoice_obj.sii_xml_request = envio_dte

                ###### comienzo de bloque de autenticacion #########
                ### Hipótesis: un envío por cada RUT de receptor ###
                if 1==1:
                    if 1==1:
                        # tengo que sacar de algun lado las claves
                        signature_d = self.get_digital_signature_pem(
                            self.company_id)

                        seed = self.get_seed()
                        _logger.info(_("Seed is:  {}").format(seed))
                        template_string = self.create_template_seed(seed)
                        seed_firmado = self.sign_seed(
                            template_string, signature_d['priv_key'],
                            signature_d['cert'])
                        token = self.get_token(seed_firmado)
                        _logger.info(_("Token is: {}").format(token))
                        raise Warning('fuck token!')
                    else:
                        raise Warning(connection_status[response.e])
                else:
                    #except:
                    # no pudo hacer el envío
                    inv.sii_result = 'NoEnviado'
                    raise Warning('Error')
                ######### fin de bloque de autenticacion ###########
                ########### inicio del bloque de envio #############
                ###
                pass
                ###
                ############# fin del bloque de envio ##############

    # funcion para descargar el XML
    @api.multi
    def get_xml_file(self):
        return {
            'type' : 'ir.actions.act_url',
            'url': '/web/binary/download_document?model=account.invoice\
&field=sii_xml_request&id=%s&filename=demoxml.xml' % (self.id),
            'target': 'self',
        }

    def get_folio(self, inv):
        # saca el folio directamente de la secuencia
        return inv.journal_document_class_id.sequence_id.number_next_actual

    def get_caf_file(self, inv):
        # hay que buscar el caf correspondiente al comprobante,
        # trayendolo de la secuencia
        returnvalue = False
        #try:
        if 1==1:
            no_caf = True
            caffiles = inv.journal_document_class_id.sequence_id.dte_caf_ids
            for caffile in caffiles:
                if caffile.status == 'in_use':
                    resultc = base64.b64decode(caffile.caf_file)
                    no_caf = False
                    break
            if no_caf:
                raise Warning(_('''There is no CAF file available or in use \
for this Document. Please enable one.'''))
            resultcaf = xmltodict.parse(resultc.replace(
                '<?xml version="1.0"?>','',1))

            folio_inicial = resultcaf['AUTORIZACION']['CAF']['DA']['RNG']['D']
            folio_final = resultcaf['AUTORIZACION']['CAF']['DA']['RNG']['H']
            folio = self.get_folio(inv)
            if folio not in range(int(folio_inicial), int(folio_final)):
                msg = '''El folio de este documento: {} está fuera de rango \
del CAF vigente (desde {} hasta {}). Solicite un nuevo CAF en el sitio \
www.sii.cl'''.format(folio, folio_inicial, folio_final)
                _logger.info(msg)
                # defino el status como "spent"
                caffile.status = 'spent'
                raise Warning(_(msg))
            elif folio > int(folio_final) - 2:
                # todo: agregar un wizard al aviso de caf terminándose
                msg = '''El CAF esta pronto a terminarse. Solicite un nuevo \
                CAF para poder continuar emitiendo documentos tributarios'''
            else:
                msg = '''Folio {} OK'''.format(folio)
            _logger.info(msg)
            returnvalue = resultcaf
        else:
            pass
        return returnvalue

    def format_vat(self, value):
        return value[2:10] + '-' + value[10:]

    def convert_encoding(self, data, new_coding = 'UTF-8'):
        encoding = cchardet.detect(data)['encoding']
        if new_coding.upper() != encoding.upper():
            data = data.decode(encoding, data).encode(new_coding)
        return data

    def pdf417bc(self, ted):
        _logger.info('Drawing the TED stamp in PDF417')
        bc = barcode(
            'pdf417',
            ted,
            options = dict(
                compact = False,
                eclevel = 5,
                columns = 13,
                rowmult = 2,
                rows = 3
            ),
            margin=20,
            scale=1
        )
        return bc

    def digest(self, data):
        sha1 = hashlib.sha1()
        sha1.update(data)
        return sha1.digest()

    def signrsa(self, MESSAGE, KEY, digst=''):
        KEY = KEY.encode('ascii')
        rsa = M2Crypto.EVP.load_key_string(KEY)
        rsa.reset_context(md='sha1')
        rsa_m = rsa.get_rsa()
        rsa.sign_init()
        rsa.sign_update(MESSAGE)
        FRMT = base64.b64encode(rsa.sign_final())
        _logger.info('Document signature in base64: %s' % FRMT)
        if digst == '':
            _logger.info("""Signature verified! Returning signature, modulus \
and exponent.""")
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e)}
        else:
            _logger.info("""Signature verified! Returning signature, modulus, \
exponent. AND DIGEST""")
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e),
                'digest': base64.b64encode(self.digest(MESSAGE))}

    # esta es la que estoy usando para firmar el CAF
    def signmessage(self, MESSAGE, KEY, pubk='', digst=''):
        rsa = M2Crypto.EVP.load_key_string(KEY)
        rsa.reset_context(md='sha1')
        rsa_m = rsa.get_rsa()
        rsa.sign_init()
        rsa.sign_update(MESSAGE)
        FRMT = base64.b64encode(rsa.sign_final())
        _logger.info('Document signature in base64: %s' % FRMT)
        if digst == '':
            _logger.info("""Signature verified! Returning signature, modulus \
and exponent.""")
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e)}
        else:
            _logger.info("""Signature verified! Returning signature, modulus, \
exponent. AND DIGEST""")
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e),
                'digest': base64.b64encode(self.digest(MESSAGE))}

#     def signmessage1(self, dd, privkey, pubk='', digst=''):
#         ddd = self.digest(dd)
#         CafPK = M2Crypto.RSA.load_key_string(privkey)
#         firma = CafPK.sign(ddd)
#         FRMT = base64.b64encode(firma)
#         _logger.info('Document signature in base64: %s' % FRMT)
#         # agregado nuevo para que no sea necesario mandar la clave publica
#         if pubk=='':
#             bio = M2Crypto.BIO.MemoryBuffer(privkey)
#             rsa = M2Crypto.RSA.load_key_bio(bio)
#         else:
#             # estas son las dos lineas originales
#             bio = M2Crypto.BIO.MemoryBuffer(pubk)
#             rsa = M2Crypto.RSA.load_pub_key_bio(bio)
#         # fin del cambio
#         pubkey = M2Crypto.EVP.PKey()
#         pubkey.assign_rsa(rsa)
#         # if you need a different digest than the default 'sha1':
#         pubkey.reset_context(md='sha1')
#         pubkey.verify_init()
#         pubkey.verify_update(dd)
#         _logger.info('Validating public key using EVP PK verification....')
#         if pubkey.verify_final(firma) == 1:
#             if digst=='':
#                 _logger.info("""Signature verified! Returning signature, modulus \
# and exponent.""")
#                 return {
#                     'firma': FRMT, 'modulus': base64.b64encode(rsa.n),
#                     'exponent': base64.b64encode(rsa.e)}
#             else:
#                 _logger.info("""Signature verified! Returning signature, modulus \
#     and exponent. AND DIGEST""")
#                 return {
#                     'firma': FRMT, 'modulus': base64.b64encode(rsa.n),
#                     'exponent': base64.b64encode(rsa.e),
#                     'digest': base64.b64encode(ddd)}
#
    #### definición del modelo

    sii_batch_number = fields.Integer(
        copy=False,
        string='Batch Number',
        readonly=True,
        help='Batch number for processing multiple invoices together')

    sii_barcode = fields.Char(
        copy=False,
        string=_('SII Barcode'),
        readonly=True,
        help='SII Barcode Name')

    sii_barcode_img = fields.Binary(
        copy=False,
        string=_('SII Barcode Image'),
        help='SII Barcode Image in PDF417 format')

    sii_message = fields.Text(
        string='SII Message',
        copy=False)
    sii_xml_request = fields.Text(
        string='SII XML Request',
        copy=False)
    sii_xml_response = fields.Text(
        string='SII XML Response',
        copy=False)
    sii_result = fields.Selection([
        ('', 'n/a'),
        ('NoEnviado', 'No Enviado'),
        ('Enviado', 'Enviado'),
        ('Aceptado', 'Aceptado'),
        ('Rechazado', 'Rechazado'),
        ('Reparo', 'Reparo'),
        ('Proceso', 'Proceso'),
        ('Reenviar', 'Reenviar'),
        ('Anulado', 'Anulado')],
        'Resultado',
        readonly=True,
        states={'draft': [('readonly', False)]},
        copy=False,
        help="SII request result",
        default = '')

    @api.multi
    def get_related_invoices_data(self):
        """
        List related invoice information to fill CbtesAsoc.
        """
        self.ensure_one()
        rel_invoices = self.search([
            ('number', '=', self.origin),
            ('state', 'not in',
                ['draft', 'proforma', 'proforma2', 'cancel'])])
        return rel_invoices

    # def invoice_validate(self):
    @api.multi
    def action_number(self):
        self.do_dte_send_invoice()
        res = super(invoice, self).action_number()
        return res

    @api.multi
    def get_barcode(self, dte_service):
        for inv in self:
            ted = False
            folio = self.get_folio(inv)

            result['TED']['DD']['RE'] = inv.format_vat(inv.company_id.vat)
            result['TED']['DD']['TD'] = inv.sii_document_class_id.sii_code
            result['TED']['DD']['F']  = folio
            result['TED']['DD']['FE'] = inv.date_invoice
            result['TED']['DD']['RR'] = inv.format_vat(inv.partner_id.vat)
            result['TED']['DD']['RSR'] = (inv.partner_id.name[:40]).decode(
                'utf-8')
            result['TED']['DD']['MNT'] = int(inv.amount_total)

            for line in inv.invoice_line:
                result['TED']['DD']['IT1'] = line.name.decode('utf-8')
                break

            resultcaf = self.get_caf_file(inv)
            _logger.info(resultcaf)

            result['TED']['DD']['CAF'] = resultcaf['AUTORIZACION']['CAF']
            #_logger.info result
            dte = result['TED']['DD']
            ddxml = '<DD>'+dicttoxml.dicttoxml(
                dte, root=False, attr_type=False).replace(
                '<key name="@version">1.0</key>','',1).replace(
                '><key name="@version">1.0</key>',' version="1.0">',1).replace(
                '><key name="@algoritmo">SHA1withRSA</key>',
                ' algoritmo="SHA1withRSA">').replace(
                '<key name="#text">','').replace(
                '</key>','').replace('<CAF>','<CAF version="1.0">')+'</DD>'
            ###### con esta funcion fuerzo la conversion a iso-8859-1
            ddxml = inv.convert_encoding(ddxml, 'ISO-8859-1')
            # ahora agarro la clave privada y ya tengo los dos elementos
            # que necesito para firmar
            keypriv = (resultcaf['AUTORIZACION']['RSASK']).encode(
                'latin-1').replace('\t','')
            keypub = (resultcaf['AUTORIZACION']['RSAPUBK']).encode(
                'latin-1').replace('\t','')
            #####
            ## antes de firmar, formatear
            root = etree.XML( ddxml )
            # funcion de remover indents en el ted y formateo xml
            # ddxml = self.remove_indents(
            #     (etree.tostring(root, pretty_print=True)))
            ##
            # formateo sin remover indents
            ddxml = etree.tostring(root)

            frmt = inv.signmessage(ddxml, keypriv, keypub)['firma']
            ted = (
                '''<TED version="1.0">{}<FRMT algoritmo="SHA1withRSA">{}\
</FRMT></TED>''').format(ddxml, frmt)
            _logger.info(ted)
            root = etree.XML(ted)
            # inv.sii_barcode = (etree.tostring(root, pretty__logger.info=True))
            inv.sii_barcode = ted
            image = False
            if ted:
                barcodefile = StringIO()
                image = inv.pdf417bc(ted)
                image.save(barcodefile,'PNG')
                data = barcodefile.getvalue()
                inv.sii_barcode_img = base64.b64encode(data)
        return ted

    @api.multi
    def do_dte_send_invoice(self):

        try:
            signature_d = self.get_digital_signature(self.company_id)
        except:
            raise Warning(_('''There is no Signer Person with an \
        authorized signature for you in the system. Please make sure that \
        'user_signature_key' module has been installed and enable a digital \
        signature, for you or make the signer to authorize you to use his \
        signature.'''))
        # try:
        #     resol_data = self.get_resolution_data(self.company_id)
        # except:
        #     raise Warning(_('''There is no SII Resolution Data \
        # available for this company. Please go to the company configuration screen and \
        # set SII resolution data.'''))
        cant_doc_batch = 0
        for inv in self.with_context(lang='es_CL'):
            # control de DTE
            if inv.sii_document_class_id.dte == False:
                continue
            # control de DTE
            cant_doc_batch = cant_doc_batch + 1
            dte_service = inv.company_id.dte_service_provider

            if dte_service in ['SII', 'SIIHOMO']:
                # debe confeccionar el timbre
                ted1 = self.get_barcode(dte_service)

            elif dte_service in ['EFACTURADELSUR']:
                # debe utilizar usuario y contraseña
                # todo: hardcodeado, pero pasar a webservices server
                dte_usuario = 'nueva.gestion' # eFacturaDelSur
                dte_passwrd = 'e7c1c19cbe' # eFacturaDelSur

            elif dte_service in ['', 'NONE']:
                return

            # definicion de los giros del emisor
            giros_emisor = []
            for turn in inv.company_id.company_activities_ids:
                giros_emisor.extend([{'Acteco': turn.code}])

            # definicion de lineas
            line_number = 1
            invoice_lines = []
            for line in inv.invoice_line:
                lines = collections.OrderedDict()
                lines['NroLinDet'] = line_number
                if line.product_id.default_code:
                    lines['CdgItem'] = collections.OrderedDict()
                    lines['CdgItem']['TpoCodigo'] = 'INT1'
                    lines['CdgItem']['VlrCodigo'] = line.product_id.default_code
                lines['NmbItem'] = line.name
                # todo: DscItem opcional (no está)
                lines['QtyItem'] = int(round(line.quantity, 0))
                # todo: opcional lines['UnmdItem'] = line.uos_id.name[:4]
                # lines['UnmdItem'] = 'unid'
                lines['PrcItem'] = int(round(line.price_unit, 0))
                if line.discount != 0:
                    lines['DscItem'] = int(round(line.discount, 0))
                lines['MontoItem'] = int(round(line.price_subtotal, 0))
                line_number = line_number + 1
                invoice_lines.extend([{'Detalle': lines}])

            # _logger.info(invoice_lines)
            #########################
            folio = self.get_folio(inv)
            dte = collections.OrderedDict()
            dte1 = collections.OrderedDict()

            # dte['Documento ID'] = 'F{}T{}'.format(folio, inv.sii_document_class_id.sii_code)
            dte['Encabezado'] = collections.OrderedDict()
            dte['Encabezado']['IdDoc'] = collections.OrderedDict()
            dte['Encabezado']['IdDoc']['TipoDTE'] = inv.sii_document_class_id.sii_code
            dte['Encabezado']['IdDoc']['Folio'] = folio
            dte['Encabezado']['IdDoc']['FchEmis'] = inv.date_invoice
            # todo: forma de pago y fecha de vencimiento - opcional
            dte['Encabezado']['IdDoc']['FmaPago'] = inv.payment_term.dte_sii_code or 1
            dte['Encabezado']['IdDoc']['FchVenc'] = inv.date_due
            dte['Encabezado']['Emisor'] = collections.OrderedDict()
            dte['Encabezado']['Emisor']['RUTEmisor'] = self.format_vat(
                inv.company_id.vat)
            dte['Encabezado']['Emisor']['RznSoc'] = inv.company_id.name
            dte['Encabezado']['Emisor']['GiroEmis'] = inv.turn_issuer.name[:80]
            # todo: Telefono y Correo opcional
            dte['Encabezado']['Emisor']['Telefono'] = inv.company_id.phone or ''
            dte['Encabezado']['Emisor']['CorreoEmisor'] = inv.company_id.dte_email
            dte['Encabezado']['Emisor']['item'] = giros_emisor # giros de la compañia - codigos
            # todo: <CdgSIISucur>077063816</CdgSIISucur> codigo de sucursal
            # no obligatorio si no hay sucursal, pero es un numero entregado
            # por el SII para cada sucursal.
            # este deberia agregarse al "punto de venta" el cual ya esta
            dte['Encabezado']['Emisor']['DirOrigen'] = inv.company_id.street
            dte['Encabezado']['Emisor']['CmnaOrigen'] = inv.company_id.state_id.name
            dte['Encabezado']['Emisor']['CiudadOrigen'] = inv.company_id.city
            dte['Encabezado']['Receptor'] = collections.OrderedDict()
            dte['Encabezado']['Receptor']['RUTRecep'] = self.format_vat(
                inv.partner_id.vat)
            dte['Encabezado']['Receptor']['RznSocRecep'] = inv.partner_id.name
            dte['Encabezado']['Receptor']['GiroRecep'] = inv.invoice_turn.name[:40]
            dte['Encabezado']['Receptor']['DirRecep'] = inv.partner_id.street
            # todo: revisar comuna: "false"
            dte['Encabezado']['Receptor']['CmnaRecep'] = inv.partner_id.state_id.name
            dte['Encabezado']['Receptor']['CiudadRecep'] = inv.partner_id.city
            dte['Encabezado']['Totales'] = collections.OrderedDict()
            if inv.sii_document_class_id.sii_code == 34:
                dte['Encabezado']['Totales']['MntExe'] = int(round(
                    inv.amount_total, 0))
            else:
                dte['Encabezado']['Totales']['MntNeto'] = int(round(
                    inv.amount_untaxed, 0))
                dte['Encabezado']['Totales']['TasaIVA'] = int(round(
                    (inv.amount_total / inv.amount_untaxed -1) * 100, 0))
                dte['Encabezado']['Totales']['IVA'] = int(round(inv.amount_tax, 0))
            dte['Encabezado']['Totales']['MntTotal'] = int(round(
                inv.amount_total, 0))
            dte['item'] = invoice_lines
            doc_id_number = "F{}T{}".format(
                folio, inv.sii_document_class_id.sii_code)
            doc_id = '<Documento ID="{}">'.format(doc_id_number)
            # si es sii, inserto el timbre
            if dte_service in ['SII', 'SIIHOMO']:
                # inserto el timbre
                dte['TEDd'] = 'TEDTEDTED'
                # aca completar el XML

            dte1['Documento ID'] = dte
            xml = dicttoxml.dicttoxml(
                dte1, root=False, attr_type=False).replace(
                    '<item>','').replace('</item>','')

            # agrego el timbre en caso que sea para el SII
            if dte_service in ['SII', 'SIIHOMO']:
                # time = '<TmstFirma>{}</TmstFirma>'.format(
                #     datetime.strftime(datetime.now(), '%Y-%m-%dT%H:%M:%S'))

                time = '<TmstFirma>{}</TmstFirma>'.format(self.convert_timezone(
                        datetime.strftime(datetime.now(), '%Y-%m-%d'),
                        datetime.strftime(datetime.now(), '%H:%M:%S')).strftime(
                        '%Y-%m-%dT%H:%M:%S'))

                xml = xml.replace('<TEDd>TEDTEDTED</TEDd>', ted1 + time)

            root = etree.XML( xml )
            # xml_pret = self.remove_indents(
            #     (etree.tostring(root, pretty_print=True)).replace(
            #         '<Documento_ID>', doc_id).replace(
            #         '</Documento_ID>', '</Documento>'))
            # sin remober indents
            xml_pret = etree.tostring(root, pretty_print=True).replace(
'<Documento_ID>', doc_id).replace('</Documento_ID>', '</Documento>')
            if dte_service in ['SII', 'SIIHOMO']:
                envelope_efact = self.convert_encoding(xml_pret, 'ISO-8859-1')
                # inv.sii_xml_request = envelope_efact
                # ACA INCORPORO EL RESTO DE LA FIRMA
                 # ahora firmo
                # _logger.info('Document: \n%s' % envelope_efact)
                # _logger.info('Signature: \n%s' % signature_d['priv_key'])
                envelope_efact = self.create_template_doc(envelope_efact)
                # Inicio de Firma del dte
                # print(envelope_efact)

                ### formateo del certificado
                certp = signature_d['cert'].replace(
                    BC, '').replace(EC, '').replace('\n', '')
                # certf =

                ## firma del documento
                einvoice = self.sign_full_xml(
                    envelope_efact, signature_d['priv_key'],
                    self.split_cert(certp), doc_id_number)
                _logger.info('Document signed!')

                ## armado del sobre directamente sobre la variable envelope
                # (esquema 1 documento = 1 sobre)
                resol_data = self.get_resolution_data(self.company_id)
                envio_dte = self.create_template_envio(
                    dte['Encabezado']['Emisor']['RUTEmisor'],
                    dte['Encabezado']['Receptor']['RUTRecep'],
                    resol_data['dte_resolution_date'],
                    resol_data['dte_resolution_number'],
                    self.convert_timezone(
                        datetime.strftime(datetime.now(), '%Y-%m-%d'),
                        datetime.strftime(
                            datetime.now(), '%H:%M:%S')).strftime(
                        '%Y-%m-%dT%H:%M:%S'),
                    inv.sii_document_class_id.sii_code, einvoice)

                # firma del sobre
                envio_dte = self.sign_full_xml(
                    envio_dte, signature_d['priv_key'], certp,
                    'OdooBMyA', 'env')


                raise Warning('envio individual dte ')
                #inv.sii_xml_request = einvoice
                #inv.sii_result = 'NoEnviado'
                # HASTA ACA LA FIRMA
            elif dte_service == 'EFACTURADELSUR':
                # armado del envolvente rrespondiente a EACTURADELSUR

                envelope_efact = '''<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
<soap12:Body>
<PonerDTE xmlns="https://www.efacturadelsur.cl">
<usuario>{0}</usuario>
<contrasena>{1}</contrasena>
<xml><![CDATA[{2}]]></xml>
<enviar>false</enviar>
</PonerDTE>
</soap12:Body>
</soap12:Envelope>'''.format(dte_usuario, dte_passwrd, xml_pret)
                inv.sii_xml_request = envelope_efact
                inv.sii_result = 'NoEnviado'

            elif dte_service == 'FACTURACION':
                envelope_efact = '''<?xml version="1.0" encoding="ISO-8859-1"?>
{}'''.format(self.convert_encoding(xml_pret, 'ISO-8859-1'))
                inv.sii_xml_request = envelope_efact
                self.get_xml_file()

            elif dte_service == 'ENTERNET':
                # servicio a realizar mediante sponsor
                pass

            elif dte_service == 'FACTURAENLINEA':
                # servicio a realizar mediante sponsor
                pass

            elif dte_service == 'LIBREDTE':
                # servicio a realizar mediante sponsor
                pass
            # en caso que no sea DTE, el proceso es finalizado sin
            # consecuencias (llamando a super
            else:
                _logger.info('NO HUBO NINGUNA OPCION DTE VALIDA')
