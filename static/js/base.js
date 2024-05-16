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

