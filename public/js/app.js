document.addEventListener('DOMContentLoaded', () => {

    // Copy-link buttons on the create page
    document.querySelectorAll('.cs-copy-link').forEach(btn => {
        btn.addEventListener('click', () => {
            const text        = btn.dataset.copy;
            const originalHtml = btn.innerHTML;
            navigator.clipboard.writeText(text).then(() => {
                btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1" viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg> Kopiert!';
                btn.classList.replace('btn-outline-secondary', 'btn-success');
                setTimeout(() => {
                    btn.innerHTML = originalHtml;
                    btn.classList.replace('btn-success', 'btn-outline-secondary');
                }, 3000);
            }).catch(() => {
                alert('Kopieren fehlgeschlagen. Bitte manuell kopieren.');
            });
        });
    });

    // Copy-password buttons on the revealed page
    document.querySelectorAll('.cs-copy-password').forEach(btn => {
        btn.addEventListener('click', () => {
            navigator.clipboard.writeText(btn.dataset.copy).then(() => {
                btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1" viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg> Kopiert!';
                btn.classList.replace('btn-outline-secondary', 'btn-success');
            }).catch(() => {
                alert('Kopieren fehlgeschlagen. Bitte manuell kopieren.');
            });
        });
    });

});
