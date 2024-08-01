export function copyToClipBoard(item, data, message = "data") {
    if ('clipboard' in navigator) {
        console.log(typeof data)
        navigator.clipboard.writeText(data)
        .then(() => {
        console.log('Text copied');
        })
        .catch((err) => console.error(err.name, err.message));
    } else {
        const textArea = document.createElement('textarea');
        textArea.value = out.value;
        textArea.style.opacity = 0;
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
        const success = document.execCommand('copy');
        console.log(`Text copy was ${success ? 'successful' : 'unsuccessful'}.`);
        } catch (err) {
        console.error(err.name, err.message);
        }
        document.body.removeChild(textArea);
    }
    item.$notify({
        title: "DonPAPI",
        type: "success",
        text: "Successfully copied " + message + " to clipboard! 🎉",
    });
}

export default copyToClipBoard