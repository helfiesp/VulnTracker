function toggleDescription(button) {
    var moreText = button.previousElementSibling;
    var ellipsis = moreText.previousElementSibling;
    var buttonText = button.textContent;

    // Toggle the display of the 'ellipsis' and 'more-text'
    if (buttonText === "View More") {
        ellipsis.style.display = "none";
        moreText.style.display = "inline";
        button.textContent = "View Less";
    } else {
        ellipsis.style.display = "inline";
        moreText.style.display = "none";
        button.textContent = "View More";
    }
}

document.addEventListener('DOMContentLoaded', function() {
    var description = document.getElementById('vulnerability-description');
    var originalText = description.innerText;
    var truncated = false;
    var maxLength = 300;

    function truncateText(text, length) {
        if (text.length <= length) return text;

        var truncatedText = text.slice(0, length);
        var lastPunctuationIndex = Math.max(
            truncatedText.lastIndexOf('.'),
            truncatedText.lastIndexOf('!'),
            truncatedText.lastIndexOf('?')
        );

        if (lastPunctuationIndex > -1) {
            return truncatedText.slice(0, lastPunctuationIndex + 1);
        } else {
            return truncatedText + '...';
        }
    }

    function toggleVulnDescription(button) {
        if (truncated) {
            description.innerText = originalText;
            button.textContent = "View Less";
        } else {
            description.innerText = truncateText(originalText, maxLength);
            button.textContent = "View More";
        }
        truncated = !truncated;
    }

    // Initially truncate the text
    description.innerText = truncateText(originalText, maxLength);
    truncated = true;
});
