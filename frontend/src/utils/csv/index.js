export function arrayToCsv(data) {
    const array = [Object.keys(data[0])].concat(data)

    return array.map(row => {
        return Object.values(row).map(value => {
            const stringValue = String(value);
            
            if (stringValue.includes('"') || stringValue.includes(',') || stringValue.includes('\n')) {
                return `"${stringValue.replace(/"/g, '""')}"`;
            }
            
            return stringValue;
        }).join(',');
    }).join('\n');
}

/* downloadBlob(csv, 'export.csv')*/
export function downloadBlob(content, filename) {
    // Create a blob
    var blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
    var url = URL.createObjectURL(blob);

    // Create a link to download it
    var pom = document.createElement('a');
    pom.href = url;
    pom.setAttribute('download', filename);
    pom.click();
}

export default {arrayToCsv, downloadBlob}
