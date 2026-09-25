/*
    The shell: the theme, and opening the navigation on a narrow screen.
    The only script this application ships.

    Deliberately not Blazor. The layout is rendered statically - pages are
    interactive islands inside it - so an @onclick in the layout is never
    wired up, and the first version of this silently did nothing at all when
    clicked. Even where it would have worked, a menu that needs a round trip
    over SignalR before it opens is a menu that does not open on a bad
    connection. Both of these are client-side concerns and neither needs the
    server to know.

    Light is the default and dark is an explicit choice, so this does NOT
    consult prefers-color-scheme: somebody who picked light meant it, and
    having the app go dark because their laptop did at sunset is not a
    preference being honoured.

    The preference is applied by an inline script in App.razor before first
    paint. This file only reads it back and changes it, because by the time an
    external script has loaded the page has already painted.

    Every localStorage call is wrapped. It throws outright, rather than
    returning null, in some privacy modes, and an unreadable preference should
    cost the toggle, not the page.
*/
window.dmarcTheme = {
    isDark() {
        return document.documentElement.dataset.theme === 'dark';
    },

    set(dark) {
        if (dark) {
            document.documentElement.dataset.theme = 'dark';
        } else {
            delete document.documentElement.dataset.theme;
        }

        try {
            localStorage.setItem('dmarc-theme', dark ? 'dark' : 'light');
        } catch (e) {
            // The page has still switched; it just will not be remembered.
        }

        this.label();
    },

    toggle() {
        this.set(!this.isDark());
    },

    /* The stored preference, applied again if the page has lost it. Only
       ever adds dark: removing it is set()'s job. */
    restore() {
        let stored = null;
        try {
            stored = localStorage.getItem('dmarc-theme');
        } catch (e) {
            return;
        }
        if (stored === 'dark' && !this.isDark()) {
            document.documentElement.dataset.theme = 'dark';
        }
    },

    /* The button says what clicking it will do, not what the page currently
       is. "Dark" on a light page means "make it dark". */
    label() {
        const button = document.querySelector('.theme-toggle');
        if (button) {
            button.textContent = this.isDark() ? '☀ Light' : '☾ Dark';
        }
    },
};

window.dmarcShell = {
    toggleNav() {
        const app = document.querySelector('.app');
        if (app) { app.classList.toggle('nav-open'); }
    },

    closeNav() {
        const app = document.querySelector('.app');
        if (app) { app.classList.remove('nav-open'); }
    },

    /* Switching organization is a round trip on purpose: the choice is
       re-signed into the sign-in cookie by the server, so every page - and
       every later request - sees the same scope. Comes back to the page it
       left from, so the person is not dropped on the home page. */
    switchOrg(slug) {
        const back = location.pathname + location.search;
        location.href = '/org/switch?slug=' + encodeURIComponent(slug || '')
            + '&returnUrl=' + encodeURIComponent(back);
    },
};

/*
    Delegated from the document rather than bound to each control, because
    Blazor's enhanced navigation replaces page content in place: anything
    bound to an element directly is lost on the first navigation, and the menu
    stops working in a way nobody would think to re-test.
*/
document.addEventListener('click', (e) => {
    // On a narrow screen the open menu covers the page, so leaving it open
    // after following a link hides the thing just navigated to.
    if (e.target.closest('.sidebar a')) {
        window.dmarcShell.closeNav();
    }
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { window.dmarcShell.closeNav(); }
});

/* The label has to be corrected after every render, not just the first: the
   markup ships the light-theme wording, and a dark-theme user navigating
   would otherwise be told they are about to switch to the theme they are
   already in. */
document.addEventListener('DOMContentLoaded', () => {
    window.dmarcTheme.label();

    /* Blazor raises enhancedload through its own event API, not on the
       document, so the listener that used to sit here never fired. It is
       registered here because blazor.web.js has run by DOMContentLoaded. */
    if (window.Blazor && typeof window.Blazor.addEventListener === 'function') {
        window.Blazor.addEventListener('enhancedload', () => {
            window.dmarcTheme.restore();
            window.dmarcTheme.label();
        });
    }
});

/* Enhanced navigation merges the next page into this one, <html> element
   included, and the server-rendered <html> never carries data-theme: the
   preference lives in the browser. Every in-app link was dropping dark mode.
   Put it back the moment it goes. */
try {
    new MutationObserver(() => window.dmarcTheme.restore())
        .observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
} catch (e) {
    /* No MutationObserver: the enhancedload hook above still restores it. */
}
