const deleteForms = document.querySelectorAll('form.js-confirm-delete');

for (const form of deleteForms) {
  form.addEventListener('submit', (event) => {
    const message = form.getAttribute('data-confirm') || 'Delete this user account?';
    if (!window.confirm(message)) {
      event.preventDefault();
    }
  });
}

