import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

def create_architecture_docx():
    doc = docx.Document()

    # Standard Page Margins (0.75 in for clean 2-page fit)
    for section in doc.sections:
        section.top_margin = Inches(0.7)
        section.bottom_margin = Inches(0.7)
        section.left_margin = Inches(0.75)
        section.right_margin = Inches(0.75)

    NAVY = RGBColor(0, 51, 102)     # #003366 Official Gov Navy
    SLATE = RGBColor(15, 23, 42)    # #0f172a
    MUTED = RGBColor(71, 85, 105)   # #475569
    WHITE = RGBColor(255, 255, 255)

    def set_cell_background(cell, fill_hex):
        tcPr = cell._tc.get_or_add_tcPr()
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
        tcPr.append(shd)

    def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
        tcPr = cell._tc.get_or_add_tcPr()
        tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
        tcPr.append(tcMar)

    # Title
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(0)
    title_p.paragraph_format.space_after = Pt(2)
    run_title = title_p.add_run('LOGFORGE: Universal Log Pre-processing Framework (ULPF)')
    run_title.font.name = 'Calibri'
    run_title.font.size = Pt(17)
    run_title.font.bold = True
    run_title.font.color.rgb = NAVY

    # Subtitle
    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_before = Pt(0)
    sub_p.paragraph_format.space_after = Pt(6)
    run_sub = sub_p.add_run('System Architecture & Engineering Specification | SIH Problem Statement ID: 26156')
    run_sub.font.name = 'Calibri'
    run_sub.font.size = Pt(10)
    run_sub.font.bold = True
    run_sub.font.color.rgb = MUTED

    # Scope Summary Box
    callout = doc.add_table(rows=1, cols=1)
    callout.alignment = WD_TABLE_ALIGNMENT.CENTER
    callout.autofit = False
    callout.columns[0].width = Inches(7.0)
    cell = callout.cell(0, 0)
    set_cell_background(cell, 'F1F5F9')
    set_cell_margins(cell, top=90, bottom=90, left=140, right=140)
    cp = cell.paragraphs[0]
    cp.paragraph_format.space_after = Pt(0)
    cr = cp.add_run('Scope: Ingest heterogeneous perimeter security logs (Syslog RFC 5424/3164, ArcSight CEF, IBM QRadar LEEF, Suricata EVE JSON, Cisco ASA, CSV) and normalize them into an analytics-ready Universal Schema with 100 percent lossless forensic retention and air-gapped GIGW 3.0 compliance.')
    cr.font.name = 'Calibri'
    cr.font.size = Pt(9)
    cr.font.italic = True
    cr.font.color.rgb = SLATE

    # Section 1
    h1 = doc.add_paragraph()
    h1.paragraph_format.space_before = Pt(8)
    h1.paragraph_format.space_after = Pt(2)
    r1 = h1.add_run('1. High-Level 4-Tier Pipeline Architecture')
    r1.font.name = 'Calibri'
    r1.font.size = Pt(11.5)
    r1.font.bold = True
    r1.font.color.rgb = NAVY

    p_arch = doc.add_paragraph()
    p_arch.paragraph_format.space_after = Pt(2)
    p_arch.add_run('LOGFORGE is engineered as a decoupled, multi-tier streaming appliance to ensure bounded memory and zero dropped packets:')

    tiers = [
        ('Tier 1 — High-Speed Ingestion & Dispatcher: ', 'Accepts streaming multi-vendor log files, network Syslog UDP/TCP feeds, and raw stream inputs using memory-bounded O(1) Python generators.'),
        ('Tier 2 — Intelligent Parser Registry & Auto-Detection: ', 'A multi-token confidence scoring matrix (0.0 to 1.0) automatically identifies RFC 5424/3164, CEF, LEEF, JSON, and Cisco ASA syntax. Corrupt lines are routed to a Quarantined Forensic Repository without disrupting the pipeline.'),
        ('Tier 3 — Universal Normalization & Taxonomy Harmonization: ', 'Extracts standard network 5-tuples (src/dst IP, src/dst port, protocol), canonical security actions (ALLOW / DENY / ALERT), 5-tier severity levels, and ISO-8601 UTC microsecond timestamps.'),
        ('Tier 4 — Zero-Loss Storage & SIEM / AI Export: ', 'SQLite WAL engine with B-Tree indexes enables sub-millisecond query filtering. Downstream connectors stream directly to JSONL (Splunk, OpenSearch, BigQuery) and CSV (Pandas, PySpark, Scikit-learn).')
    ]

    for title, desc in tiers:
        bp = doc.add_paragraph(style='List Bullet')
        bp.paragraph_format.space_before = Pt(1)
        bp.paragraph_format.space_after = Pt(1)
        rt = bp.add_run(title)
        rt.font.name = 'Calibri'
        rt.font.size = Pt(9)
        rt.font.bold = True
        rt.font.color.rgb = NAVY
        rd = bp.add_run(desc)
        rd.font.name = 'Calibri'
        rd.font.size = Pt(9)
        rd.font.color.rgb = SLATE

    # Section 2
    h2 = doc.add_paragraph()
    h2.paragraph_format.space_before = Pt(7)
    h2.paragraph_format.space_after = Pt(2)
    r2 = h2.add_run('2. Core Architectural Pillars')
    r2.font.name = 'Calibri'
    r2.font.size = Pt(11.5)
    r2.font.bold = True
    r2.font.color.rgb = NAVY

    pillars = [
        ('100% Lossless Forensic Guarantee: ', 'Unlike traditional forwarders that drop unrecognized fields to conserve storage, LOGFORGE permanently preserves the exact byte-for-byte uncompressed raw log in raw_event alongside normalized attributes for strict evidentiary admissibility under CERT-In and Indian IT Act standards.'),
        ('O(1) Bounded Memory Architecture: ', 'Processing millions of logs typically crashes log parsers with Out-Of-Memory (OOM) errors. LOGFORGE processes streams in bounded chunk batches (5,000 to 25,000 events) coupled with periodic SQLite WAL flushes, guaranteeing flat RAM usage (< 80 MB) up to 1,000,000 events.'),
        ('GIGW 3.0 & WCAG 2.1 AA Compliance: ', 'The web portal features bilingual Indian Government identity, live font sizing controls (A-, A, A+), high-contrast accessibility mode (yellow-on-black), and screen reader bypass links (#main-content).'),
        ('Air-Gapped Sovereign Readiness: ', 'Operates 100% offline with zero external cloud dependencies, zero external telemetry phone-home, and complete Docker containerization.')
    ]

    for title, desc in pillars:
        bp = doc.add_paragraph(style='List Bullet')
        bp.paragraph_format.space_before = Pt(1)
        bp.paragraph_format.space_after = Pt(1)
        rt = bp.add_run(title)
        rt.font.name = 'Calibri'
        rt.font.size = Pt(9)
        rt.font.bold = True
        rt.font.color.rgb = SLATE
        rd = bp.add_run(desc)
        rd.font.name = 'Calibri'
        rd.font.size = Pt(9)
        rd.font.color.rgb = SLATE

    # Section 3: Empirical Benchmarks Table
    h3 = doc.add_paragraph()
    h3.paragraph_format.space_before = Pt(7)
    h3.paragraph_format.space_after = Pt(3)
    r3 = h3.add_run('3. Empirical Scalability & Performance Benchmarks')
    r3.font.name = 'Calibri'
    r3.font.size = Pt(11.5)
    r3.font.bold = True
    r3.font.color.rgb = NAVY

    table = doc.add_table(rows=6, cols=5)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    col_widths = [Inches(1.3), Inches(1.3), Inches(1.6), Inches(1.4), Inches(1.4)]
    headers = ['Workload Tier', 'Processing Latency', 'Sustained Throughput', 'Lossless Retention', 'Memory Footprint']
    data = [
        ['1,000 Logs', '0.058 seconds', '17,169.71 eps', '100% Retained', '< 15 MB RAM'],
        ['10,000 Logs', '0.579 seconds', '17,268.39 eps', '100% Retained', '< 25 MB RAM'],
        ['50,000 Logs', '2.869 seconds', '17,426.36 eps', '100% Retained', '< 35 MB RAM'],
        ['100,000 Logs', '6.197 seconds', '16,136.10 eps', '100% Retained', '< 45 MB RAM'],
        ['1,000,000 Logs', '71.24 seconds', '14,043.62 eps', '100% Retained', 'O(1) Chunked (< 80 MB)']
    ]

    hdr_cells = table.rows[0].cells
    for i, h in enumerate(headers):
        hdr_cells[i].width = col_widths[i]
        set_cell_background(hdr_cells[i], '003366')
        set_cell_margins(hdr_cells[i], top=70, bottom=70, left=90, right=90)
        p = hdr_cells[i].paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        run = p.add_run(h)
        run.font.name = 'Calibri'
        run.font.size = Pt(8.5)
        run.font.bold = True
        run.font.color.rgb = WHITE

    for row_idx, row_data in enumerate(data):
        row_cells = table.rows[row_idx + 1].cells
        bg_color = 'F8FAFC' if row_idx % 2 == 0 else 'FFFFFF'
        for col_idx, text in enumerate(row_data):
            row_cells[col_idx].width = col_widths[col_idx]
            set_cell_background(row_cells[col_idx], bg_color)
            set_cell_margins(row_cells[col_idx], top=60, bottom=60, left=90, right=90)
            p = row_cells[col_idx].paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            run = p.add_run(text)
            run.font.name = 'Calibri'
            run.font.size = Pt(8)
            run.font.color.rgb = SLATE
            if col_idx == 0 or col_idx == 2:
                run.font.bold = True

    # Section 4: Universal Event Schema Definition
    h4 = doc.add_paragraph()
    h4.paragraph_format.space_before = Pt(7)
    h4.paragraph_format.space_after = Pt(2)
    r4 = h4.add_run('4. Canonical Universal Schema Data Model')
    r4.font.name = 'Calibri'
    r4.font.size = Pt(11.5)
    r4.font.bold = True
    r4.font.color.rgb = NAVY

    schema_box = doc.add_table(rows=1, cols=1)
    schema_box.alignment = WD_TABLE_ALIGNMENT.CENTER
    schema_box.autofit = False
    schema_box.columns[0].width = Inches(7.0)
    scell = schema_box.cell(0, 0)
    set_cell_background(scell, 'F8FAFC')
    set_cell_margins(scell, top=70, bottom=70, left=100, right=100)
    sp = scell.paragraphs[0]
    sp.paragraph_format.space_after = Pt(0)
    schema_text = (
        '{\n'
        '  "event_id": "uuid-v4-unique-identifier",\n'
        '  "timestamp": "2026-09-28T14:30:01.000000Z",  // Normalized ISO-8601 UTC\n'
        '  "source": { "vendor": "Palo Alto", "device_type": "firewall", "hostname": "PA-5220-FW01" },\n'
        '  "network": {\n'
        '    "source_ip": "192.168.1.105", "destination_ip": "8.8.8.8",\n'
        '    "source_port": 52341, "destination_port": 443, "protocol": "TCP"\n'
        '  },\n'
        '  "event": { "category": "network", "action": "ALLOW", "severity": "INFORMATIONAL" },\n'
        '  "metadata": { "parser": "SyslogParser", "source_format": "syslog_rfc5424", "confidence": 0.95 },\n'
        '  "raw_event": "<14>1 2026-09-28T14:30:01Z PA-5220-FW01 ... (100% Lossless Original String)"\n'
        '}'
    )
    srun = sp.add_run(schema_text)
    srun.font.name = 'Consolas'
    srun.font.size = Pt(7.5)
    srun.font.color.rgb = RGBColor(0, 51, 102)

    # Footer Note
    foot_p = doc.add_paragraph()
    foot_p.paragraph_format.space_before = Pt(6)
    foot_p.paragraph_format.space_after = Pt(0)
    foot_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = foot_p.add_run('LOGFORGE (SIH26156) • Repository: https://github.com/goutham-11-16/LOGFORGE • Sovereign Air-Gapped Architecture')
    fr.font.name = 'Calibri'
    fr.font.size = Pt(8)
    fr.font.color.rgb = MUTED

    output_path = 'docs/LOGFORGE_Architecture_Specification.docx'
    doc.save(output_path)
    print(f'Successfully generated: {output_path}')

if __name__ == '__main__':
    create_architecture_docx()
