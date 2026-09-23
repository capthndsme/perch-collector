// Live total of an open checkout (Paid Hotspot). The page works without
// it: the panel has a Refresh link and the forms post without script.
(function () {
  'use strict';
  var box = document.querySelector('[data-perch-checkout="open"]');
  if (!box || !window.fetch) return;
  var ref = box.getAttribute('data-ref');
  function set(name, text) {
    var el = box.querySelector('[data-perch-' + name + ']');
    if (el && el.textContent !== text) el.textContent = text;
  }
  function tick() {
    fetch('/portal/checkout', { cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (s) {
        var c = s && s.checkout;
        if (!c || c.checkoutRef !== ref || c.state !== 'open') {
          location.replace('/?m=' + (c && c.checkoutRef === ref && c.state === 'finalized' ? 'paid' : 'checkout_closed'));
          return;
        }
        set('amount', c.amountText);
        set('preview', c.previewText);
        set('idle', String(c.idleSecondsLeft));
        set('terminal-state', c.terminalOnline ? '' : 'The terminal is not responding.');
        setTimeout(tick, 1000);
      })
      .catch(function () { setTimeout(tick, 3000); });
  }
  setTimeout(tick, 1000);
})();
