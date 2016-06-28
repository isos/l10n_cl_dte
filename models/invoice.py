# -*- coding: utf-8 -*-
##############################################################################
# For copyright and license notices, see __openerp__.py file in module root
# directory
##############################################################################
from openerp import fields, models, api, _
from openerp.exceptions import Warning
from datetime import datetime, timedelta
import logging, json
import lxml.etree as etree
from lxml import objectify
from lxml.etree import XMLSyntaxError

#from inspect import currentframe, getframeinfo

import collections, re

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

try:
    from suds.client import Client
except:
    pass

try:
    import urllib3
except:
    pass

# from urllib3 import HTTPConnectionPool
urllib3.disable_warnings()
# para que funcione, hay que hacer:
'''
pip install --upgrade requests
y
pip install --upgrade urllib3
'''
#import urllib3
import certifi

pool = urllib3.PoolManager(
    cert_reqs='CERT_REQUIRED', # Force certificate check.
    ca_certs=certifi.where(),  # Path to the Certifi bundle.
)
#pool = urllib3.PoolManager()

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
    _logger.info('Cannot import cchardet library')

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

# hardcodeamos este valor por ahora
import os
xsdpath = os.path.dirname(os.path.realpath(__file__)).replace('/models','/static/xsd/')
host = 'https://libredte.cl/api'
api_emitir = host + '/dte/documentos/emitir'
api_generar = host + '/dte/documentos/generar'
api_gen_pdf = host + '/dte/documentos/generar_pdf'
api_upd_satus = host + '/dte/dte_emitidos/actualizar_estado/'
'''
Extensión del modelo de datos para contener parámetros globales necesarios
 para todas las integraciones de factura electrónica.
 @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
 @version: 2016-06-11
'''
class invoice(models.Model):
    _inherit = "account.invoice"


    '''
    Creacion de plantilla xml para envolver el DTE
    Previo a realizar su firma (1)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_doc(self, doc):
        xml = '''<DTE xmlns="http://www.sii.cl/SiiDte" version="1.0">
<!-- Odoo Implementation Blanco Martin -->
{}</DTE>'''.format(doc)
        return xml

    '''
    Funcion que permite crear una plantilla para el EnvioDTE
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_envio(self, RutEmisor, RutReceptor, FchResol, NroResol,
                              TmstFirmaEnv, TpoDTE, EnvioDTE):
        signature_d = self.get_digital_signature_pem(self.company_id)

        xml = '''<SetDTE ID="OdooBMyA">
<Caratula version="1.0">
<RutEmisor>{0}</RutEmisor>
<RutEnvia>{1}</RutEnvia>
<RutReceptor>{2}</RutReceptor>
<FchResol>{3}</FchResol>
<NroResol>{4}</NroResol>
<TmstFirmaEnv>{5}</TmstFirmaEnv>
<SubTotDTE>
<TpoDTE>{6}</TpoDTE>
<NroDTE>1</NroDTE>
</SubTotDTE>
</Caratula>
{7}
</SetDTE>
'''.format(RutEmisor, signature_d['subject_serial_number'], RutReceptor,
           FchResol, NroResol, TmstFirmaEnv, TpoDTE, EnvioDTE)
        return xml

    '''
    Funcion para remover los indents del documento previo a enviar el xml
     a firmaar. Realizada para probar si el problema de
    error de firma proviene de los indents.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def remove_indents(self, xml):
        return xml.replace(
            '        <','<').replace(
            '      <','<').replace(
            '    <','<').replace(
            '  <','<')


    '''
    Funcion auxiliar para conversion de codificacion de strings
     proyecto experimentos_dte
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2014-12-01
    '''
    def convert_encoding(self, data, new_coding = 'UTF-8'):
        encoding = cchardet.detect(data)['encoding']
        if new_coding.upper() != encoding.upper():
            data = data.decode(encoding, data).encode(new_coding)
        return data

    '''
    Funcion auxiliar para saber que codificacion tiene el string
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def whatisthis(self, s):
        if isinstance(s, str):
            _logger.info("ordinary string")
        elif isinstance(s, unicode):
            _logger.info("unicode string")
        else:
            _logger.info("not a string")

    '''
    Función para crear los headers necesarios por LibreDTE
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-23
    '''
    def create_headers_ldte(self):
        headers = {}
        headers['Authorization'] = 'Basic {}'.format(
            base64.b64encode('{}:{}'.format(
                self.company_id.dte_password,
                self.company_id.dte_username)))
        headers['Accept-Encoding'] = 'gzip, deflate, identity'
        headers['Accept'] = '*/*'
        headers['User-Agent'] = 'python-requests/2.6.0 CPython/2.7.6 \
Linux/3.13.0-88-generic'
        headers['Connection'] = 'keep-alive'
        headers['Content-Type'] = 'application/json'
        return headers

    '''
    Funcion para validar los xml generados contra el esquema que le corresponda
    segun el tipo de documento.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
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

    '''
    obtener estado de DTE.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-16
    '''
    @api.multi
    def check_dte_status(self):
        self.ensure_one()
        folio = self.get_folio_current()
        if self.dte_service_provider in [
            'EFACTURADELSUR', 'EFACTURADELSUR_TEST']:
            # reobtener el folio
            dte_username = self.company_id.dte_username
            dte_password = self.company_id.dte_password
            envio_check = '''<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <ObtenerEstadoDTE xmlns="https://www.efacturadelsur.cl">
      <usuario>{0}</usuario>
      <contrasena>{1}</contrasena>
      <rutEmisor>{2}</rutEmisor>
      <tipoDte>{3}</tipoDte>
      <folio>{4}</folio>
    </ObtenerEstadoDTE>
  </soap12:Body>
</soap12:Envelope>'''.format(
            dte_username,
            dte_password,
            self.format_vat(self.company_id.vat),
            self.sii_document_class_id.sii_code,
            folio)

            _logger.info("envio: %s" % envio_check)
            host = 'https://www.efacturadelsur.cl'
            post = '/ws/DTE.asmx'  # HTTP/1.1
            url = host + post
            _logger.info('URL to be used %s' % url)
            response = pool.urlopen('POST', url, headers={
                'Content-Type': 'application/soap+xml',
                'charset': 'utf-8',
                'Content-Length': len(
                    envio_check)}, body=envio_check)
            _logger.info(response.status)
            _logger.info(response.data)
            if response.status != 200:
                pass
                raise Warning(
                    'The Transmission Has Failed. Error: %s' % response.status)

            setenvio = {
                # 'sii_result': 'Enviado' if self.dte_service_provider == 'EFACTURADELSUR' else self.sii_result,
                'sii_xml_response': response.data}
            self.write(setenvio)
            x = xmltodict.parse(response.data)
            raise Warning(x['soap:Envelope']['soap:Body'][
                              'ObtenerEstadoDTEResponse'][
                              'ObtenerEstadoDTEResult'])

            root = etree.fromstring(response.data)
            raise Warning(root.ObtenerEstadoDTEResult)

        elif self.dte_service_provider in [
            'LIBREDTE', 'LIBREDTE_TEST']:
            headers = self.create_headers_ldte()
            metodo = 1  # =1 servicio web, =0 correo
            # consultar estado de dte emitido
            response_status = pool.urlopen(
                'GET',
                api_upd_satus + str(self.sii_document_class_id.sii_code) + '/' + str(folio) + '/' + str(
                    self.format_vat(self.company_id.vat)) + '/' + str(metodo),
                headers=headers)

            if response_status.status != 200:
                raise Warning(
                    'Error al obtener el estado del DTE emitido: ' + response_status.data)
            print(response_status.data)

    '''
    Realización del envío de DTE.
    nota: se cambia el nombre de la función de "send xml file"
    a "send_dte" para ser mas abarcativa en cuanto a que algunos
    service provider no trabajan con xml sino con un diccionario
    (caso de libre dte por ejemplo). Como la funcion se invoca desde un
    boton, pero trambién se podría cambiar aejecutar automaticamente,
    pienso que es más conveniente tratar todas las opciones de provider
    en la misma funcion.
    La funcion selecciona el proveedor de servicio de DTE y efectua el envio
    de acuerdo a la integracion del proveedor.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    @api.multi
    def send_dte(self):
        self.ensure_one()

        _logger.info('Entering Send XML Function')
        _logger.info(
            'Service provider is: %s' % self.dte_service_provider)

        if self.dte_service_provider in [
            'EFACTURADELSUR', 'EFACTURADELSUR_TEST']:
            host = 'https://www.efacturadelsur.cl'
            post = '/ws/DTE.asmx' # HTTP/1.1
            url = host + post
            _logger.info('URL to be used %s' % url)
            _logger.info('Lenght used for forming envelope: %s' % len(
                self.sii_xml_request))
            response = pool.urlopen('POST', url, headers={
                'Content-Type': 'application/soap+xml',
                'charset': 'utf-8',
                'Content-Length': len(
                    self.sii_xml_request)}, body=self.sii_xml_request)
            _logger.info(response.status)
            _logger.info(response.data)
            if response.status != 200:
                raise Warning(
                    'The Transmission Has Failed. Error: %s' % response.status)
            setenvio = {
                'sii_result': 'Enviado' if self.dte_service_provider == 'EFACTURADELSUR' else self.sii_result,
                'sii_xml_response': response.data}
            self.write(setenvio)

        elif self.dte_service_provider in ['LIBREDTE', 'LIBREDTE_TEST']:
            '''
            import base64
            user = 'Aladdin'
            passw = 'open sesame'
            base64.b64encode('{}:{}'.format(user, passw))
            QWxhZGRpbjpvcGVuIHNlc2FtZQ==
            '''
            pass
        else:
            pass

    '''
    Funcion para descargar el xml en el sistema local del usuario
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    @api.multi
    def get_xml_file(self):
        return {
            'type' : 'ir.actions.act_url',
            'url': '/web/binary/download_document?model=account.invoice\
&field=sii_xml_request&id=%s&filename=demoxml.xml' % (self.id),
            'target': 'self',
        }

    '''
    Funcion para descargar el folio tomando el valor desde la secuencia
    correspondiente al tipo de documento.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def get_folio(self, inv):
        # saca el folio directamente de la secuencia
        return inv.journal_document_class_id.sequence_id.number_next_actual

    '''
    Funcion para actualizar el folio tomando el valor devuelto por el
    tercera parte integrador.
    Esta funcion se usa cuando un tercero comanda los folios
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-23
    '''
    def set_folio(self, inv, folio):
        inv.journal_document_class_id.sequence_id.number_next_actual = folio

    '''
    Funcion que devuelve el service provider desde la compañia
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def get_company_dte_service_provider(self):
        # raise Warning(self.company_id.dte_service_provider)
        return self.company_id.dte_service_provider

    '''
    Funcion para obtener el folio ya registrado en el dato
    correspondiente al tipo de documento.
    (remoción del prefijo almacenado)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def get_folio_current(self):
        prefix = self.journal_document_class_id.sequence_id.prefix
        folio = self.sii_document_number.replace(prefix, '', 1)
        return int(folio)

    def format_vat(self, value):
        return value[2:10] + '-' + value[10:]


    '''
    Definicion de extension de modelo de datos para account.invoice
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-02-01
    '''
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
        string='XML Request',
        copy=False)
    sii_xml_response = fields.Text(
        string='XML Response',
        copy=False)
    sii_send_ident = fields.Text(
        string='SII Send Identification',
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

    dte_service_provider = fields.Selection(
        (
            ('', 'None'),
            ('EFACTURADELSUR', 'efacturadelsur.cl'),
            ('EFACTURADELSUR_TEST', 'efacturadelsur.cl (test mode)'),
            ('ENTERNET', 'enternet.cl'),
            ('FACTURACION', 'facturacion.cl'),
            ('FACTURAENLINEA', 'facturaenlinea.cl'),
            ('LIBREDTE', 'LibreDTE'),
            ('LIBREDTE_TEST', 'LibreDTE (test mode)'),
            ('SIIHOMO', 'SII - Certification process'),
            ('SII', 'www.sii.cl'),
            ('SII MiPyme', 'SII - Portal MiPyme'),
        ), 'DTE Service Provider',
        related='company_id.dte_service_provider',
        #default=get_company_dte_service_provider,
        readonly=True)

    dte_resolution_number = fields.Char('SII Exempt Resolution Number',
                                        help='''This value must be provided \
and must appear in your pdf or printed tribute document, under the electronic \
stamp to be legally valid.''')

    third_party_pdf = fields.Binary('PDF File')
    filename_pdf = fields.Char('File Name PDF')
    third_party_xml = fields.Binary('XML File')
    filename_xml = fields.Char('File Name XML')

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


    '''
     A partir de aca se realiza la toma del pdf con la factura impresa
     directamente desde libreDTE
     podria existir la posibilidad técnica de imprimir la factura
     desde odoo con otro módulo l10n_cl_dte_pdf
     o desde esta "función"
     obtener el PDF desde LibreDTE'''
    '''
    Función para tomar el PDF generado en libreDTE y adjuntarlo al registro
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-23
    '''
    @api.multi
    def bring_pdf_ldte(self):
        self.ensure_one()
        print('entrada a bringpdf function')
        headers = self.create_headers_ldte()
        generar_pdf_request = json.dumps({'xml': self.third_party_xml,
                                          'compress': False})
        print(generar_pdf_request)
        response_pdf = pool.urlopen(
            'POST', api_gen_pdf,  headers=headers,
            body=generar_pdf_request)
        if response_pdf.status != 200:
            raise Warning('Error en conexión al generar: %s, %s' % (
                response_pdf.status, response_pdf.data))
        invoice_pdf = base64.b64encode(response_pdf.data)
        attachment_obj = self.env['ir.attachment']
        attachment_id = attachment_obj.create(
            {
                'name': 'INVOICE '+self.sii_document_class_id.name+'-'+self.sii_document_number,
                'datas': invoice_pdf,
                'datas_fname': 'INVOICE '+self.sii_document_class_id.name+'-'+self.sii_document_number,
                'res_model': self._name,
                'res_id': self.id,
                'type': 'binary'
            })
        _logger.info('Se ha generado factura en PDF con el id {}'.format(attachment_id))

    '''
    Funcion que envía el email por correo electrónico al cliente
    es la funcion original en la cual se ha modificado la plantilla
    autor de la modificacion: Daniel Blanco - daniel[at]blancomartin.cl
    @version: 2016-06-27
    '''
    @api.multi
    def action_invoice_sent(self):
        """
        Open a window to compose an email, with the edi invoice template
        message loaded by default
        """
        _logger.info('controlo el proceso de envio con mi propia funcion...')
        assert len(
            self) == 1, 'This option should only be used for a single id at a time.'

        ## hace este cambio: reemplaza el template (inicio)
        template = self.env.ref(
            'l10n_cl_dte.email_template_edi_invoice', False)
        ## hace este cambio: reemplaza el template (fin)

        compose_form = self.env.ref(
            'mail.email_compose_message_wizard_form', False)
        ctx = dict(
            default_model='account.invoice',
            default_res_id=self.id,
            default_use_template=bool(template),
            default_template_id=template.id,
            default_composition_mode='comment',
            mark_invoice_as_sent=True,
        )
        return {
            'name': _('Compose Email'),
            'type': 'ir.actions.act_window',
            'view_type': 'form',
            'view_mode': 'form',
            'res_model': 'mail.compose.message',
            'views': [(compose_form.id, 'form')],
            'view_id': compose_form.id,
            'target': 'new',
            'context': ctx,
        }


    @api.multi
    def action_invoice_print(self):
        print('entrando a impresion de factura desde boton de arriba')
        pass

    @api.multi
    def action_number(self):
        self.do_dte_send_invoice()
        res = super(invoice, self).action_number()
        return res

    @api.multi
    def do_dte_send_invoice(self):
        cant_doc_batch = 0
        for inv in self.with_context(lang='es_CL'):
            # control de DTE
            if inv.sii_document_class_id.dte == False:
                continue
            # control de DTE
            cant_doc_batch = cant_doc_batch + 1

            if inv.dte_service_provider in ['EFACTURADELSUR',
                                            'EFACTURADELSUR_TEST',
                                            'LIBREDTE',
                                            'LIBREDTE_TEST']:
                # debe utilizar usuario y contraseña
                # todo: hardcodeado, pero pasar a webservices server
                dte_username = self.company_id.dte_username
                dte_password = self.company_id.dte_password

            elif inv.dte_service_provider in ['', 'NONE']:
                return


            # giros_emisor = []
            # # definicion de los giros del emisor
            # for turn in inv.company_id.company_activities_ids:
            #     if inv.dte_service_provider not in ['LIBREDTE', 'LIBREDTE_TEST']:
            #         giros_emisor.extend([{'Acteco': turn.code}])
            #     else:
            #         giros_emisor.extend([turn.code])

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
                if inv.dte_service_provider not in ['LIBREDTE', 'LIBREDTE_TEST']:
                    invoice_lines.extend([{'Detalle': lines}])
                else:
                    invoice_lines.extend([lines])

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
            if inv.dte_service_provider not in ['LIBREDTE', 'LIBREDTE_TEST']:
                dte['Encabezado']['IdDoc']['FchEmis'] = inv.date_invoice
            # todo: forma de pago y fecha de vencimiento - opcional
            dte['Encabezado']['IdDoc']['FmaPago'] = inv.payment_term.dte_sii_code or 1
            dte['Encabezado']['IdDoc']['FchVenc'] = inv.date_due
            dte['Encabezado']['Emisor'] = collections.OrderedDict()
            dte['Encabezado']['Emisor']['RUTEmisor'] = self.format_vat(
                inv.company_id.vat)
            dte['Encabezado']['Emisor']['RznSoc'] = inv.company_id.name
            dte['Encabezado']['Emisor']['GiroEmis'] = inv.turn_issuer.name[:80]
            dte['Encabezado']['Emisor']['Acteco'] = inv.turn_issuer.code
            # if inv.dte_service_provider not in ['LIBREDTE', 'LIBREDTE_TEST']:
            #     dte['Encabezado']['Emisor']['item'] = giros_emisor # giros de la compañia - codigos
            # else:
            #     dte['Encabezado']['Emisor']['Acteco'] = giros_emisor  # giros de la compañia - codigos
            # todo: Telefono y Correo opcional
            dte['Encabezado']['Emisor']['Telefono'] = inv.company_id.phone or ''
            if inv.dte_service_provider not in ['LIBREDTE', 'LIBREDTE_TEST']:
                dte['Encabezado']['Emisor']['CorreoEmisor'] = inv.company_id.dte_email

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
            if inv.dte_service_provider not in ['LIBREDTE', 'LIBREDTE_TEST']:
                # no se envían los totales a LibreDTE
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
            if inv.dte_service_provider not in ['LIBREDTE', 'LIBREDTE_TEST']:
                dte['item'] = invoice_lines
            else:
                dte['Detalle'] = invoice_lines
            doc_id_number = "F{}T{}".format(
                folio, inv.sii_document_class_id.sii_code)
            doc_id = '<Documento ID="{}">'.format(doc_id_number)
            # si es sii, inserto el timbre
            dte1['Documento ID'] = dte
            xml = dicttoxml.dicttoxml(
                dte1, root=False, attr_type=False).replace(
                    '<item>','').replace('</item>','')

            root = etree.XML( xml )
            # xml_pret = self.remove_indents(
            #     (etree.tostring(root, pretty_print=True)).replace(
            #         '<Documento_ID>', doc_id).replace(
            #         '</Documento_ID>', '</Documento>'))
            # sin remober indents
            xml_pret = etree.tostring(root, pretty_print=True).replace(
'<Documento_ID>', doc_id).replace('</Documento_ID>', '</Documento>')

            xml_pret = self.create_template_doc(xml_pret)

            if inv.dte_service_provider in [
                'EFACTURADELSUR', 'EFACTURADELSUR_TEST']:
                enviar = 'true' if self.dte_service_provider == \
                                   'EFACTURADELSUR' else 'false'
                # armado del envolvente rrespondiente a EACTURADELSUR
                envelope_efact = '''<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xmlns:xsd="http://www.w3.org/2001/XMLSchema" \
xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
<soap12:Body>
<PonerDTE xmlns="https://www.efacturadelsur.cl">
<usuario>{0}</usuario>
<contrasena>{1}</contrasena>
<xml><![CDATA[{2}]]></xml>
<enviar>{3}</enviar>
</PonerDTE>
</soap12:Body>
</soap12:Envelope>'''.format(dte_username, dte_password, xml_pret, enviar)
                print(inv.sii_xml_request)
                inv.sii_xml_request = envelope_efact
                inv.sii_result = 'NoEnviado'
                _logger.info('OPCION DTE: ({})'.format(str(
                    inv.dte_service_provider)).lower())
            elif inv.dte_service_provider in [
                'LIBREDeTE', 'LIBREDTE_TEST']:
                print('password: %s' % self.company_id.dte_password)
                print('username: %s' % self.company_id.dte_username)

                headers = self.create_headers_ldte()

                # raise Warning(headers)

                response_emitir = pool.urlopen(
                    'POST', api_emitir, headers=headers, body=json.dumps(dte))
                if response_emitir.status != 200:
                    raise Warning('Error en conexión al emitir: %s, %s' % (
                        response_emitir.status, response_emitir.data))
                _logger.info('response_emitir: %s' % response_emitir.data)

                try:
                    inv.sii_xml_response = response_emitir.data
                except:
                    _logger.warning(
                        'no pudo guardar la respuesta al ws de emision')
                '''
                {"emisor": 76085472, "receptor": 1, "dte": 33,
                 "codigo": "7a1f42de0e8a3dcdd0500f7ad6c8266a"}
                '''

                response_generar = pool.urlopen(
                    'POST', api_generar, headers=headers,
                    body=response_emitir.data)
                if response_generar.status != 200:
                    raise Warning('Error en conexión al generar: %s, %s' % (
                        response_generar.status, response_generar.data))
                _logger.info('response_generar: %s' % response_generar.data)
                # Estos son los valores que puedo validar de lo emitido antes
                # de efectivamente validar el documento
                response_j = json.loads(response_generar.data)
                '''
                response_j['emisor']
                response_j['dte']
                response_j['folio']
                response_j['certificacion']
                response_j['tasa']
                response_j['fecha']
                response_j['sucursal_sii']
                response_j['receptor']
                response_j['exento']
                response_j['neto']
                response_j['iva']
                response_j['total']
                response_j['usuario']
                '''
                # llegado a este punto, el documento ya está emitido y ha consumido
                # un folio por lo tanto se actualiza el folio mediante una funcion para
                # esa finalidad
                self.set_folio(inv, response_j['folio'])
                _logger.info('Este es el XML decodificado:')
                # da problemas al guardar el documento con codificación 8859-1
                _logger.info(base64.b64decode(response_j['xml']))

                # agregar funcion para traer el pdf
                # prueba de incluir el pdf como adjunto en lugar de guardarlo
                # en account_invoice
                try:
                    inv.sii_xml_request = self.convert_encoding(
                        base64.b64decode(response_j['xml']))
                except:
                    pass
                    _logger.warning(
                        'no pudo codificar y guardar el documento... ')

                try:
                    self.bring_pdf_ldte()
                except:
                    pass
                    _logger.warning('no pudo traer el pdf')

                inv.write(
                    {
                        'third_party_xml': response_j['xml'],
                        'sii_result': 'Enviado',
                        # 'third_party_pdf': base64.b64encode(invoice_pdf)
                    }
                )
                _logger.info('se guardó xml con la factura')
            else:
                _logger.info('NO HUBO NINGUNA OPCION DTE VALIDA ({})'.format(
                    inv.dte_service_provider))
                raise Warning('None DTE Provider Option')