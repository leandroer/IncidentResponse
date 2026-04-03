// Improved error handling and accessibility enhancements in main.js

// Function to check if an element exists in the DOM
function elementExists(selector) {
    return document.querySelector(selector) !== null;
}

// Mobile menu toggle with aria-expanded attribute for accessibility
const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
if (elementExists('.mobile-menu-toggle')) {
    mobileMenuToggle.addEventListener('click', function() {
        const menu = document.querySelector('.mobile-menu');
        if (menu) {
            const isExpanded = mobileMenuToggle.getAttribute('aria-expanded') === 'true';
            mobileMenuToggle.setAttribute('aria-expanded', !isExpanded);
            menu.classList.toggle('visible');
        }
    });
}

// Debounce function to limit the rate at which a function can fire
function debounce(func, delay) {
    let timeout;
    return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), delay);
    };
}

// Smooth scroll with URL updates using history.pushState
const anchorLinks = document.querySelectorAll('a[href^="#"]');
anchorLinks.forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        const targetId = this.getAttribute('href');
        const targetElement = document.querySelector(targetId);
        if (targetElement) {
            window.scrollTo({
                top: targetElement.offsetTop,
                behavior: 'smooth'
            });
            history.pushState(null, null, targetId);
        }
    });
});

// Improved documentation comments
/**
 * Smoothly scrolls to an anchor link and updates the URL.
 * @param {Event} e - The click event.
 */

/**
 * Toggles the mobile menu and updates aria-expanded for accessibility.
 */

/**
 * Debounce a function to improve performance.
 * @param {Function} func - The function to debounce.
 * @param {number} delay - The debounce delay in milliseconds.
 * @returns {Function} - Debounced version of the function.
 */
