import React, { useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { FileText, Download, FileDown, Loader2 } from 'lucide-react';

export default function ReportView({ report }) {
  const reportRef = useRef(null);
  const [exporting, setExporting] = useState(null);

  if (!report) {
    return (
      <div className="glass-card p-12 text-center">
        <FileText className="w-14 h-14 mx-auto text-[#7a8ba7] mb-4" />
        <p className="text-[#7a8ba7] text-sm">Report will appear after investigation completes</p>
      </div>
    );
  }

  /* ── Markdown export ── */
  const handleExportMd = () => {
    setExporting('md');
    try {
      const blob = new Blob([report], { type: 'text/markdown;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `RAPTOR-Report-${new Date().toISOString().slice(0, 10)}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } finally {
      setTimeout(() => setExporting(null), 500);
    }
  };

  /* ── PDF export ── */
  const handleExportPdf = async () => {
    setExporting('pdf');
    try {
      const element = reportRef.current;
      if (!element) return;

      const clone = element.cloneNode(true);
      clone.style.cssText = `
        background: #0b1120; color: #e8ecf1; padding: 32px;
        width: 210mm; font-family: Inter, system-ui, sans-serif;
        line-height: 1.8; font-size: 13px;
      `;

      // Apply print styles to cloned elements
      const applyStyle = (sel, styles) => {
        clone.querySelectorAll(sel).forEach(el => Object.assign(el.style, styles));
      };

      applyStyle('table', { width: '100%', borderCollapse: 'collapse', fontSize: '11px', margin: '12px 0', border: '1px solid #263354' });
      applyStyle('th', { background: 'rgba(226,168,50,0.08)', color: '#e2a832', padding: '8px 12px', borderBottom: '2px solid rgba(226,168,50,0.2)', textAlign: 'left', fontWeight: '600' });
      applyStyle('td', { padding: '8px 12px', borderBottom: '1px solid #1a2540', color: '#9aa8bd' });
      applyStyle('h1', { color: '#e8ecf1', fontSize: '18px', borderBottom: '1px solid #263354', paddingBottom: '8px' });
      applyStyle('h2', { color: '#e2a832', fontSize: '15px' });
      applyStyle('h3', { color: '#f0c860', fontSize: '14px' });
      applyStyle('code', { background: '#1a2540', color: '#e2a832', padding: '2px 5px', borderRadius: '3px', fontSize: '11px' });
      applyStyle('strong', { color: '#e8ecf1' });
      applyStyle('blockquote', { borderLeft: '3px solid #e2a832', paddingLeft: '12px', color: '#7a8ba7' });
      applyStyle('li', { color: '#9aa8bd' });
      applyStyle('p', { color: '#9aa8bd' });

      const opt = {
        margin: [10, 12, 10, 12],
        filename: `RAPTOR-Report-${new Date().toISOString().slice(0, 10)}.pdf`,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true, backgroundColor: '#0b1120', logging: false },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
        pagebreak: { mode: ['avoid-all', 'css', 'legacy'] },
      };

      clone.style.position = 'fixed';
      clone.style.left = '-9999px';
      document.body.appendChild(clone);
      const { default: html2pdf } = await import('html2pdf.js');
      await html2pdf().set(opt).from(clone).save();
      document.body.removeChild(clone);
    } catch (err) {
      console.error('PDF export failed:', err);
    } finally {
      setTimeout(() => setExporting(null), 500);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-raptor-text flex items-center gap-2">
          <FileText className="w-5 h-5 text-raptor-accent" />
          Investigation Report
        </h3>
        <div className="flex gap-2">
          <button onClick={handleExportPdf} disabled={exporting === 'pdf'}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium
                       transition-all duration-200 disabled:opacity-50
                       bg-[#2a1520]/60 text-[#e76f6f] border-[#4a2030] hover:bg-[#3a1f2c] hover:border-[#6a3040]">
            {exporting === 'pdf' ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileDown className="w-4 h-4" />}
            Export PDF
          </button>
          <button onClick={handleExportMd} disabled={exporting === 'md'}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium
                       transition-all duration-200 disabled:opacity-50
                       bg-[#1a2030]/60 text-raptor-accent border-[#2a3050] hover:bg-[#1f2840] hover:border-[#e2a832]/30">
            {exporting === 'md' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            Export Markdown
          </button>
        </div>
      </div>

      <div ref={reportRef} className="glass-card p-8 report-content">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{report}</ReactMarkdown>
      </div>
    </div>
  );
}
