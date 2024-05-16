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
    var searchInput = document.getElementById('search-input');
    var cveArticles = document.querySelectorAll('.cve');

    searchInput.addEventListener('keyup', function(e) {
        var searchTerm = e.target.value.toLowerCase();
        cveArticles.forEach(function(article) {
            var title = article.querySelector('.cve-title').textContent.toLowerCase();
            var description = article.querySelector('.cve-description').textContent.toLowerCase();
            if (title.includes(searchTerm) || description.includes(searchTerm)) {
                article.style.display = '';
            } else {
                article.style.display = 'none';
            }
        });
    });

});