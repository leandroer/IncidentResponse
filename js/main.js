(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', function () {
        const toggle = document.querySelector('.mobile-menu-toggle');
        const menu = document.querySelector('.nav-menu');

        if (!toggle || !menu) return;

        toggle.addEventListener('click', function () {
            const expanded = menu.classList.toggle('active');
            toggle.setAttribute('aria-expanded', String(expanded));
            toggle.setAttribute('aria-label', expanded ? 'Close navigation menu' : 'Open navigation menu');
        });

        menu.addEventListener('click', function (event) {
            if (event.target.closest('a') && menu.classList.contains('active')) {
                menu.classList.remove('active');
                toggle.setAttribute('aria-expanded', 'false');
                toggle.setAttribute('aria-label', 'Open navigation menu');
            }
        });
    });
})();
