# BridgeIDS LaTeX Report Files

This directory contains the LaTeX source files for the BridgeIDS research report.

## Files

- **`BridgeIDS_Report.tex`** - Main LaTeX document (IEEE conference format)
- **`references.bib`** - BibTeX bibliography with 12 academic references
- **`BridgeIDS_Report.pdf`** - Compiled PDF output

## Compiling the Document

To compile the PDF from source, run the following commands in sequence:

```bash
pdflatex BridgeIDS_Report.tex
bibtex BridgeIDS_Report
pdflatex BridgeIDS_Report.tex
pdflatex BridgeIDS_Report.tex
```

The three-pass compilation is necessary to:
1. First pass: Generate initial document and aux files
2. BibTeX: Process references
3. Second pass: Include references and update citations
4. Third pass: Resolve all cross-references

## Output

The compilation produces:
- `BridgeIDS_Report.pdf` - Final paper (5 pages)
- `BridgeIDS_Report.aux` - Auxiliary file
- `BridgeIDS_Report.bbl` - Bibliography file
- `BridgeIDS_Report.log` - Compilation log

## Requirements

Standard LaTeX packages (included in most TeX distributions):
- IEEEtran document class
- cite, amsmath, amssymb, amsfonts
- graphicx, textcomp, xcolor
- booktabs, multirow, url, hyperref

## Customization

**Author Information**: Edit lines 19-24 in `BridgeIDS_Report.tex`:
```latex
\author{\IEEEauthorblockN{Your Name Here}
\IEEEauthorblockA{\textit{Department of Computer Science} \\
...
```

**Adding Figures**: The Mermaid diagram from the markdown version has been omitted. To add it:
1. Export the diagram as PNG/PDF
2. Place in the `docs/` directory
3. Include using: `\includegraphics[width=\columnwidth]{filename.png}`

## Notes

- The document uses IEEE conference paper format (two-column)
- All mathematical equations have been properly formatted
- Tables use `booktabs` for professional appearance
- Citations are numbered in IEEE style [1], [2], etc.
