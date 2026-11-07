import io
import ipaddress
from html import escape as html_escape

import requests
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

from .analyzer import analyze_eml

app = FastAPI(title='MailForensic AI', version='2.0.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=False,
    allow_methods=['*'],
    allow_headers=['*']
)

MAX_FILE_SIZE = 10 * 1024 * 1024


async def read_eml(file: UploadFile):
    filename = file.filename or ''
    if not filename.lower().endswith('.eml'):
        raise HTTPException(400, 'Please upload a .eml file')

    data = await file.read()
    if not data:
        raise HTTPException(400, 'The uploaded file is empty')

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(413, 'File too large. Maximum 10 MB.')

    return data, filename


@app.get('/api/health')
def health():
    return {'status': 'ok', 'service': 'MailForensic AI', 'version': '2.0.0'}


@app.post('/api/analyze')
async def analyze(file: UploadFile = File(...)):
    data, filename = await read_eml(file)
    try:
        return analyze_eml(data, filename)
    except Exception as exc:
        raise HTTPException(400, f'Unable to parse email: {exc}')


@app.post('/api/intel')
async def intel(ip: str):
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_reserved:
            return {
                'ip': ip,
                'status': 'local_or_reserved',
                'message': 'External geolocation is not applicable.'
            }
    except ValueError:
        raise HTTPException(400, 'Invalid IP address')

    try:
        response = requests.get(
            f'https://ipapi.co/{ip}/json/',
            timeout=5,
            headers={'User-Agent': 'MailForensicAI/2.0'}
        )
        response.raise_for_status()
        data = response.json()
        return {
            'ip': ip,
            'status': 'ok',
            'country': data.get('country_name'),
            'country_code': data.get('country_code'),
            'region': data.get('region'),
            'city': data.get('city'),
            'org': data.get('org'),
            'asn': data.get('asn'),
            'latitude': data.get('latitude'),
            'longitude': data.get('longitude'),
            'source': 'ipapi.co'
        }
    except Exception as exc:
        return {
            'ip': ip,
            'status': 'unavailable',
            'message': str(exc)
        }


def build_graph(result):
    nodes = []
    edges = []
    seen = set()

    def add_node(node_id, label, kind):
        if node_id not in seen:
            nodes.append({'id': node_id, 'label': label, 'kind': kind})
            seen.add(node_id)

    sender = result['email']['from'] or 'Unknown sender'
    add_node('sender', sender, 'sender')

    for i, domain in enumerate(result['indicators']['domains'][:20]):
        node_id = f'domain-{i}'
        add_node(node_id, domain, 'domain')
        edges.append({'source': 'sender', 'target': node_id, 'label': 'uses'})

    for i, ip in enumerate(result['indicators']['public_ips'][:20]):
        node_id = f'ip-{i}'
        add_node(node_id, ip, 'ip')
        edges.append({'source': node_id, 'target': 'sender', 'label': 'observed'})

    for i, url in enumerate(result['indicators']['urls'][:20]):
        node_id = f'url-{i}'
        add_node(node_id, url[:45], 'url')
        edges.append({'source': 'sender', 'target': node_id, 'label': 'contains'})

    return {'nodes': nodes, 'edges': edges}


@app.post('/api/graph')
async def graph(file: UploadFile = File(...)):
    data, filename = await read_eml(file)
    try:
        return build_graph(analyze_eml(data, filename))
    except Exception as exc:
        raise HTTPException(400, f'Unable to build graph: {exc}')


@app.post('/api/report')
async def report(file: UploadFile = File(...)):
    data, filename = await read_eml(file)

    try:
        result = analyze_eml(data, filename)
        buf = io.BytesIO()

        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        styles = getSampleStyleSheet()

        story = [
            Paragraph('MailForensic AI — Forensic Report', styles['Title']),
            Spacer(1, 12),
            Paragraph(
                f"Risk: <b>{result['risk']['score']}/100 ({html_escape(result['risk']['level'])})</b>",
                styles['Heading2']
            ),
            Paragraph(
                f"Evidence SHA-256: {html_escape(result['file']['sha256'])}",
                styles['BodyText']
            ),
            Spacer(1, 10)
        ]

        rows = [
            ['Field', 'Value'],
            ['From', result['email']['from']],
            ['To', result['email']['to']],
            ['Subject', result['email']['subject']],
            ['Reply-To', result['email']['reply_to']],
            ['SPF', result['authentication']['spf']],
            ['DKIM', result['authentication']['dkim']],
            ['DMARC', result['authentication']['dmarc']]
        ]

        safe_rows = [
            [html_escape(str(cell)) for cell in row]
            for row in rows
        ]

        table = Table(safe_rows, colWidths=[100, 400])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0b2a45')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('VALIGN', (0,0), (-1,-1), 'TOP')
        ]))

        story += [
            table,
            Spacer(1, 14),
            Paragraph('Threat indicators', styles['Heading2'])
        ]

        for reason in result['risk']['reasons'][:20]:
            story.append(Paragraph('• ' + html_escape(reason), styles['BodyText']))

        story += [
            Spacer(1, 10),
            Paragraph(
                'URLs: ' + html_escape(', '.join(result['indicators']['urls']) or 'None'),
                styles['BodyText']
            ),
            Paragraph(
                'IPs: ' + html_escape(', '.join(result['indicators']['ips']) or 'None'),
                styles['BodyText']
            ),
            Paragraph(
                'Domains: ' + html_escape(', '.join(result['indicators']['domains']) or 'None'),
                styles['BodyText']
            )
        ]

        doc.build(story)
        buf.seek(0)

        safe_name = filename.rsplit('.', 1)[0].replace('"', '_')
        return StreamingResponse(
            buf,
            media_type='application/pdf',
            headers={
                'Content-Disposition':
                    f'attachment; filename="{safe_name}_forensic_report.pdf"'
            }
        )

    except Exception as exc:
        raise HTTPException(400, f'Unable to generate report: {exc}')
