const form = document.getElementById('convert-form');
const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
const submitButton = form.querySelector('button[type="submit"]');
const submitButtonDefaultLabel = submitButton.textContent;
const errorBox = document.getElementById('error-box');
const successBox = document.getElementById('success-box');

const garminEmail = document.getElementById('garmin_email');
const garminPassword = document.getElementById('garmin_password');
const saveGarmin = document.getElementById('save_garmin');
const garminFields = document.getElementById('garmin-fields');
const garminSaved = document.getElementById('garmin-saved');
const garminDisconnect = document.getElementById('garmin-disconnect');

const omronEmail = document.getElementById('omron_email');
const omronPassword = document.getElementById('omron_password');
const omronCountry = document.getElementById('omron_country');
const saveOmron = document.getElementById('save_omron');
const omronFields = document.getElementById('omron-fields');
const omronSaved = document.getElementById('omron-saved');
const omronDisconnect = document.getElementById('omron-disconnect');

function showError(message) {
  successBox.style.display = 'none';
  successBox.textContent = '';
  errorBox.textContent = message;
  errorBox.style.display = 'block';
}

function showSuccess(message) {
  errorBox.style.display = 'none';
  errorBox.textContent = '';
  successBox.textContent = message;
  successBox.style.display = 'block';
}

function clearAlerts() {
  errorBox.style.display = 'none';
  errorBox.textContent = '';
  successBox.style.display = 'none';
  successBox.textContent = '';
}

async function parseJsonSafe(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function applyGarminState(state) {
  const isSaved = Boolean(state && state.saved);
  garminEmail.value = state?.email || '';
  garminPassword.value = '';
  saveGarmin.checked = isSaved;

  if (isSaved) {
    garminFields.classList.add('hidden');
    garminSaved.classList.remove('hidden');
  } else {
    garminFields.classList.remove('hidden');
    garminSaved.classList.add('hidden');
  }
}

function applyOmronState(state) {
  const isSaved = Boolean(state && state.saved);
  omronEmail.value = state?.email || '';
  omronCountry.value = state?.country || '';
  omronPassword.value = '';
  saveOmron.checked = isSaved;

  if (isSaved) {
    omronFields.classList.add('hidden');
    omronSaved.classList.remove('hidden');
  } else {
    omronFields.classList.remove('hidden');
    omronSaved.classList.add('hidden');
  }
}

async function loadSavedCredentialStatus(showLoadError = false) {
  try {
    const response = await fetch('/api/credentials', {
      method: 'GET',
      headers: {
        'Accept': 'application/json'
      }
    });

    if (response.status === 401) {
      window.location.href = '/login';
      return;
    }

    if (!response.ok) {
      if (showLoadError) {
        showError('Failed to load saved credential status.');
      }
      return;
    }

    const data = await parseJsonSafe(response);
    if (!data) {
      if (showLoadError) {
        showError('Failed to parse saved credential status response.');
      }
      return;
    }

    applyGarminState(data.garmin || {});
    applyOmronState(data.omron || {});
  } catch {
    if (showLoadError) {
      showError('Failed to load saved credential status.');
    }
  }
}

async function disconnectProvider(provider) {
  try {
    const response = await fetch(`/api/credentials/${provider}`, {
      method: 'DELETE',
      headers: {
        'Accept': 'application/json',
        'X-CSRF-Token': csrfToken
      }
    });

    if (response.status === 401) {
      window.location.href = '/login';
      return;
    }

    const data = await parseJsonSafe(response);
    if (!response.ok) {
      throw new Error(data?.error || `Failed to clear ${provider} credentials.`);
    }

    await loadSavedCredentialStatus(false);
    showSuccess(data?.message || `Cleared ${provider} credentials.`);
  } catch (err) {
    showError(err?.message || `Failed to clear ${provider} credentials.`);
  }
}

garminDisconnect.addEventListener('click', () => {
  disconnectProvider('garmin');
});

omronDisconnect.addEventListener('click', () => {
  disconnectProvider('omron');
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearAlerts();

  const garminEmailValue = garminEmail.value.trim();
  const omronEmailValue = omronEmail.value.trim();
  const omronCountryValue = omronCountry.value.trim().toUpperCase();
  garminEmail.value = garminEmailValue;
  omronEmail.value = omronEmailValue;
  omronCountry.value = omronCountryValue;

  submitButton.disabled = true;
  submitButton.textContent = 'Syncing...';

  try {
    const formData = new FormData(form);
    const response = await fetch('/sync-omron', {
      method: 'POST',
      body: formData,
      headers: {
        'Accept': 'application/json',
        'X-CSRF-Token': csrfToken
      }
    });

    if (response.status === 401) {
      window.location.href = '/login';
      return;
    }

    const data = await parseJsonSafe(response);
    if (!response.ok) {
      showError(data?.error || 'Sync failed.');
      return;
    }

    showSuccess(data?.message || 'Sync complete.');
    await loadSavedCredentialStatus(false);
  } catch (err) {
    showError('Request failed: ' + (err?.message || String(err)));
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = submitButtonDefaultLabel;
  }
});

loadSavedCredentialStatus(true);

