const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

function generateCertificate(outputPath, studentName, CompanyName, associateName, position,evaluation) {
    const doc = new PDFDocument({
        layout: 'landscape',
        size: 'A4',
    });

    // Helper to move to next line
    function jumpLine(doc, lines) {
        for (let index = 0; index < lines; index++) {
            doc.moveDown();
        }
    }

    doc.pipe(fs.createWriteStream(outputPath));

    doc.rect(0, 0, doc.page.width, doc.page.height).fill('#fff');

    doc.fontSize(10);

    // Margin
    const distanceMargin = 18;

    doc
        .fillAndStroke('#0e8cc3')
        .lineWidth(20)
        .lineJoin('round')
        .rect(
            distanceMargin,
            distanceMargin,
            doc.page.width - distanceMargin * 2,
            doc.page.height - distanceMargin * 2,
        )
        .stroke();

    // Header
    const maxWidth = 150;
    const maxHeight = 70;

    doc.image(path.resolve(__dirname, 'public/assets/img/winners.png'), doc.page.width / 2 - maxWidth / 2, 60, {
        fit: [maxWidth, maxHeight],
        align: 'center',
    });

    jumpLine(doc, 6);

    doc
        .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Light.otf'))
        .fontSize(10)
        .fill('#021c27')
        .text('DEMOCRATIC AND POPULAR REPUBLIC OF ALGERIA', {
            align: 'center',
        });
    doc
    .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Light.otf'))
    .fontSize(10)
    .fill('#021c27')
    .text('MINISTRY OF HIGHER EDUCATION AND SCIENTIFIC RESEARCH ', {
        align: 'center',
    });
    doc
    .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Light.otf'))
    .fontSize(10)
    .fill('#021c27')
    .text('UNIVERSITY  Echahid Cheikh Larbi Tebessi -TEBESSA- ', {
        align: 'center',
    });
    jumpLine(doc, 1);
    // Content
    doc
        .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Regular.otf'))
        .fontSize(16)
        .fill('#021c27')
        .text('CERTIFICATE OF COMPLETION', {
            align: 'center',
        });

    jumpLine(doc, 1);

    doc
        .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Light.otf'))
        .fontSize(10)
        .fill('#021c27')
        .text('Presented to', {
            align: 'center',
        });

    jumpLine(doc, 1);
    doc
        .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Bold.otf'))
        .fontSize(24)
        .fill('#021c27')
        .text(studentName, {
            align: 'center',
        });

    doc
        .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Light.otf'))
        .fontSize(10)
        .fill('#021c27')
        .text(`Successfully completed the internship as a ${position} with the following evaluation`, {
            align: 'center',
        });

    jumpLine(doc, 1);

    // Add 2x5 table of evaluation
        const headers = ['Technical Skills', 'Teamwork', 'Problem Solving', 'Presence', 'Overall Evaluation'];
        const cellWidth = 100;
        const cellHeight = 33;
        const tableLeft = (doc.page.width - (cellWidth * headers.length)) / 2;
        const tableTop = doc.y;
        const rows = [evaluation];

    
    doc.font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Bold.otf')).fontSize(9);

    // Draw table headers
    doc.lineWidth(1);  // Thin line width for the table borders
    headers.forEach((header, i) => {
        doc.rect(tableLeft + i * cellWidth, tableTop, cellWidth, cellHeight).stroke();
        doc.text(header, tableLeft + i * cellWidth + 5, tableTop + 8, { width: cellWidth - 10, align: 'center' });
    });

    // Draw table rows
    rows.forEach((row, j) => {
        row.forEach((cell, i) => {
            doc.rect(tableLeft + i * cellWidth, tableTop + (j + 1) * cellHeight, cellWidth, cellHeight).stroke();
            doc.text(cell, tableLeft + i * cellWidth + 5, tableTop + (j + 1) * cellHeight + 8, { width: cellWidth - 10, align: 'center' });
        });
    });

    jumpLine(doc, 1);

    doc.lineWidth(1);

    // Signatures
    const lineSize = 174;
    const signatureHeight = doc.y + 40;

    doc.fillAndStroke('#021c27');
    doc.strokeOpacity(0.2);

    const startLine1 = 128;
    const endLine1 = 128 + lineSize;
    doc
        .moveTo(startLine1, signatureHeight)
        .lineTo(endLine1, signatureHeight)
        .stroke();

    const startLine2 = endLine1 + 32;
    const endLine2 = startLine2 + lineSize;
    doc
        .moveTo(startLine2, signatureHeight)
        .lineTo(endLine2, signatureHeight)
        .stroke();

    const startLine3 = endLine2 + 32;
    const endLine3 = startLine3 + lineSize;
    doc
        .moveTo(startLine3, signatureHeight)
        .lineTo(endLine3, signatureHeight)
        .stroke();

    doc
        .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Bold.otf'))
        .fontSize(10)
        .fill('#021c27')
        .text(associateName, startLine1, signatureHeight + 10, {
            columns: 1,
            columnGap: 0,
            height: 40,
            width: lineSize,
            align: 'center',
        });

    doc
        .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Light.otf'))
        .fontSize(10)
        .fill('#021c27')
        .text('Internship Supervisor', startLine1, signatureHeight + 25, {
            columns: 1,
            columnGap: 0,
            height: 40,
            width: lineSize,
            align: 'center',
        });

    doc
        .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Bold.otf'))
        .fontSize(10)
        .fill('#021c27')
        .text(studentName, startLine2, signatureHeight + 10, {
            columns: 1,
            columnGap: 0,
            height: 40,
            width: lineSize,
            align: 'center',
        });

    doc
        .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Light.otf'))
        .fontSize(10)
        .fill('#021c27')
        .text('Student', startLine2, signatureHeight + 25, {
            columns: 1,
            columnGap: 0,
            height: 40,
            width: lineSize,
            align: 'center',
        });

    doc
        .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Bold.otf'))
        .fontSize(10)
        .fill('#021c27')
        .text(CompanyName, startLine3, signatureHeight + 10, {
            columns: 1,
            columnGap: 0,
            height: 40,
            width: lineSize,
            align: 'center',
        });

    doc
        .font(path.resolve(__dirname, 'public/assets/fonts/NotoSansJP-Light.otf'))
        .fontSize(10)
        .fill('#021c27')
        .text('Company', startLine3, signatureHeight + 25, {
            columns: 1,
            columnGap: 0,
            height: 40,
            width: lineSize,
            align: 'center',
        });

    jumpLine(doc, 1);
    const bottomHeight = doc.page.height - 100;

    doc.image(path.resolve(__dirname, 'public/assets/img/stamp.png'), doc.page.width / 2 - 30, bottomHeight, {
        fit: [60, 60],
    });

    doc.end();
}

module.exports = generateCertificate;
